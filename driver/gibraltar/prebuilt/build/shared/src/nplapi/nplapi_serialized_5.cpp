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

template <class Archive> void save(Archive&, const npl_base_l3_lp_attr_union_t&);
template <class Archive> void load(Archive&, npl_base_l3_lp_attr_union_t&);

template <class Archive> void save(Archive&, const npl_counter_offset_t&);
template <class Archive> void load(Archive&, npl_counter_offset_t&);

template <class Archive> void save(Archive&, const npl_counter_ptr_t&);
template <class Archive> void load(Archive&, npl_counter_ptr_t&);

template <class Archive> void save(Archive&, const npl_destination_t&);
template <class Archive> void load(Archive&, npl_destination_t&);

template <class Archive> void save(Archive&, const npl_gre_tunnel_attributes_t&);
template <class Archive> void load(Archive&, npl_gre_tunnel_attributes_t&);

template <class Archive> void save(Archive&, const npl_header_format_t&);
template <class Archive> void load(Archive&, npl_header_format_t&);

template <class Archive> void save(Archive&, const npl_ingress_lpts_og_app_config_t&);
template <class Archive> void load(Archive&, npl_ingress_lpts_og_app_config_t&);

template <class Archive> void save(Archive&, const npl_ingress_qos_acl_result_t&);
template <class Archive> void load(Archive&, npl_ingress_qos_acl_result_t&);

template <class Archive> void save(Archive&, const npl_ipv4_ipv6_init_rtf_stage_t&);
template <class Archive> void load(Archive&, npl_ipv4_ipv6_init_rtf_stage_t&);

template <class Archive> void save(Archive&, const npl_l2_relay_id_t&);
template <class Archive> void load(Archive&, npl_l2_relay_id_t&);

template <class Archive> void save(Archive&, const npl_l3_dlp_attributes_t&);
template <class Archive> void load(Archive&, npl_l3_dlp_attributes_t&);

template <class Archive> void save(Archive&, const npl_l3_relay_id_t&);
template <class Archive> void load(Archive&, npl_l3_relay_id_t&);

template <class Archive> void save(Archive&, const npl_l4_ports_header_t&);
template <class Archive> void load(Archive&, npl_l4_ports_header_t&);

template <class Archive> void save(Archive&, const npl_large_em_label_encap_data_and_counter_ptr_t&);
template <class Archive> void load(Archive&, npl_large_em_label_encap_data_and_counter_ptr_t&);

template <class Archive> void save(Archive&, const npl_learn_manager_cfg_max_learn_type_t&);
template <class Archive> void load(Archive&, npl_learn_manager_cfg_max_learn_type_t&);

template <class Archive> void save(Archive&, const npl_light_fi_stage_cfg_t&);
template <class Archive> void load(Archive&, npl_light_fi_stage_cfg_t&);

template <class Archive> void save(Archive&, const npl_link_up_vector_result_t&);
template <class Archive> void load(Archive&, npl_link_up_vector_result_t&);

template <class Archive> void save(Archive&, const npl_lpts_flow_type_t&);
template <class Archive> void load(Archive&, npl_lpts_flow_type_t&);

template <class Archive> void save(Archive&, const npl_lpts_payload_t&);
template <class Archive> void load(Archive&, npl_lpts_payload_t&);

template <class Archive> void save(Archive&, const npl_lr_fifo_register_t&);
template <class Archive> void load(Archive&, npl_lr_fifo_register_t&);

template <class Archive> void save(Archive&, const npl_lr_filter_fifo_register_t&);
template <class Archive> void load(Archive&, npl_lr_filter_fifo_register_t&);

template <class Archive> void save(Archive&, const npl_lsp_encap_mapping_data_payload_t&);
template <class Archive> void load(Archive&, npl_lsp_encap_mapping_data_payload_t&);

template <class Archive> void save(Archive&, const npl_mac_addr_t&);
template <class Archive> void load(Archive&, npl_mac_addr_t&);

template <class Archive> void save(Archive&, const npl_mac_af_npp_attributes_t&);
template <class Archive> void load(Archive&, npl_mac_af_npp_attributes_t&);

template <class Archive> void save(Archive&, const npl_mac_da_t&);
template <class Archive> void load(Archive&, npl_mac_da_t&);

template <class Archive> void save(Archive&, const npl_mac_forwarding_key_t&);
template <class Archive> void load(Archive&, npl_mac_forwarding_key_t&);

template <class Archive> void save(Archive&, const npl_mac_metadata_t&);
template <class Archive> void load(Archive&, npl_mac_metadata_t&);

template <class Archive> void save(Archive&, const npl_mac_relay_g_destination_t&);
template <class Archive> void load(Archive&, npl_mac_relay_g_destination_t&);

template <class Archive> void save(Archive&, const npl_mact_result_t&);
template <class Archive> void load(Archive&, npl_mact_result_t&);

template <class Archive> void save(Archive&, const npl_my_one_bit_result_t&);
template <class Archive> void load(Archive&, npl_my_one_bit_result_t&);

template <class Archive> void save(Archive&, const npl_output_learn_record_t&);
template <class Archive> void load(Archive&, npl_output_learn_record_t&);

template <class Archive> void save(Archive&, const npl_relay_attr_table_payload_t&);
template <class Archive> void load(Archive&, npl_relay_attr_table_payload_t&);

template <class Archive> void save(Archive&, const npl_relay_id_t&);
template <class Archive> void load(Archive&, npl_relay_id_t&);

template <class Archive> void save(Archive&, const npl_tunnel_type_and_force_pipe_ttl_ingress_ptp_info_t&);
template <class Archive> void load(Archive&, npl_tunnel_type_and_force_pipe_ttl_ingress_ptp_info_t&);

template <class Archive> void save(Archive&, const npl_vxlan_relay_encap_data_t&);
template <class Archive> void load(Archive&, npl_vxlan_relay_encap_data_t&);

template<>
class serializer_class<npl_l3_dlp_p_counter_offset_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_dlp_p_counter_offset_table_key_t& m) {
        uint64_t m_is_mc = m.is_mc;
            archive(::cereal::make_nvp("is_mc", m_is_mc));
            archive(::cereal::make_nvp("ip_acl_macro_control", m.ip_acl_macro_control));
            archive(::cereal::make_nvp("l3_encap_type", m.l3_encap_type));
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_dlp_p_counter_offset_table_key_t& m) {
        uint64_t m_is_mc;
            archive(::cereal::make_nvp("is_mc", m_is_mc));
            archive(::cereal::make_nvp("ip_acl_macro_control", m.ip_acl_macro_control));
            archive(::cereal::make_nvp("l3_encap_type", m.l3_encap_type));
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
        m.is_mc = m_is_mc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_dlp_p_counter_offset_table_key_t& m)
{
    serializer_class<npl_l3_dlp_p_counter_offset_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_dlp_p_counter_offset_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_dlp_p_counter_offset_table_key_t& m)
{
    serializer_class<npl_l3_dlp_p_counter_offset_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_dlp_p_counter_offset_table_key_t&);



template<>
class serializer_class<npl_l3_dlp_p_counter_offset_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_dlp_p_counter_offset_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_dlp_p_counter_offset_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_dlp_p_counter_offset_table_value_t& m)
{
    serializer_class<npl_l3_dlp_p_counter_offset_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_dlp_p_counter_offset_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_dlp_p_counter_offset_table_value_t& m)
{
    serializer_class<npl_l3_dlp_p_counter_offset_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_dlp_p_counter_offset_table_value_t&);



template<>
class serializer_class<npl_l3_dlp_p_counter_offset_table_value_t::npl_l3_dlp_p_counter_offset_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_dlp_p_counter_offset_table_value_t::npl_l3_dlp_p_counter_offset_table_payloads_t& m) {
            archive(::cereal::make_nvp("local_tx_counter_offset", m.local_tx_counter_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_dlp_p_counter_offset_table_value_t::npl_l3_dlp_p_counter_offset_table_payloads_t& m) {
            archive(::cereal::make_nvp("local_tx_counter_offset", m.local_tx_counter_offset));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_dlp_p_counter_offset_table_value_t::npl_l3_dlp_p_counter_offset_table_payloads_t& m)
{
    serializer_class<npl_l3_dlp_p_counter_offset_table_value_t::npl_l3_dlp_p_counter_offset_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_dlp_p_counter_offset_table_value_t::npl_l3_dlp_p_counter_offset_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_dlp_p_counter_offset_table_value_t::npl_l3_dlp_p_counter_offset_table_payloads_t& m)
{
    serializer_class<npl_l3_dlp_p_counter_offset_table_value_t::npl_l3_dlp_p_counter_offset_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_dlp_p_counter_offset_table_value_t::npl_l3_dlp_p_counter_offset_table_payloads_t&);



template<>
class serializer_class<npl_l3_dlp_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_dlp_table_key_t& m) {
        uint64_t m_l3_dlp_msbs = m.l3_dlp_msbs;
        uint64_t m_l3_dlp_lsbs = m.l3_dlp_lsbs;
            archive(::cereal::make_nvp("l3_dlp_msbs", m_l3_dlp_msbs));
            archive(::cereal::make_nvp("l3_dlp_lsbs", m_l3_dlp_lsbs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_dlp_table_key_t& m) {
        uint64_t m_l3_dlp_msbs;
        uint64_t m_l3_dlp_lsbs;
            archive(::cereal::make_nvp("l3_dlp_msbs", m_l3_dlp_msbs));
            archive(::cereal::make_nvp("l3_dlp_lsbs", m_l3_dlp_lsbs));
        m.l3_dlp_msbs = m_l3_dlp_msbs;
        m.l3_dlp_lsbs = m_l3_dlp_lsbs;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_dlp_table_key_t& m)
{
    serializer_class<npl_l3_dlp_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_dlp_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_dlp_table_key_t& m)
{
    serializer_class<npl_l3_dlp_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_dlp_table_key_t&);



template<>
class serializer_class<npl_l3_dlp_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_dlp_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_dlp_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_dlp_table_value_t& m)
{
    serializer_class<npl_l3_dlp_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_dlp_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_dlp_table_value_t& m)
{
    serializer_class<npl_l3_dlp_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_dlp_table_value_t&);



template<>
class serializer_class<npl_l3_dlp_table_value_t::npl_l3_dlp_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_dlp_table_value_t::npl_l3_dlp_table_payloads_t& m) {
            archive(::cereal::make_nvp("l3_dlp_attributes", m.l3_dlp_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_dlp_table_value_t::npl_l3_dlp_table_payloads_t& m) {
            archive(::cereal::make_nvp("l3_dlp_attributes", m.l3_dlp_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_dlp_table_value_t::npl_l3_dlp_table_payloads_t& m)
{
    serializer_class<npl_l3_dlp_table_value_t::npl_l3_dlp_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_dlp_table_value_t::npl_l3_dlp_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_dlp_table_value_t::npl_l3_dlp_table_payloads_t& m)
{
    serializer_class<npl_l3_dlp_table_value_t::npl_l3_dlp_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_dlp_table_value_t::npl_l3_dlp_table_payloads_t&);



template<>
class serializer_class<npl_l3_lp_profile_filter_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_lp_profile_filter_table_key_t& m) {
        uint64_t m_slp_profile = m.slp_profile;
        uint64_t m_lp_profile = m.lp_profile;
            archive(::cereal::make_nvp("slp_profile", m_slp_profile));
            archive(::cereal::make_nvp("lp_profile", m_lp_profile));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_lp_profile_filter_table_key_t& m) {
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
save(Archive& archive, const npl_l3_lp_profile_filter_table_key_t& m)
{
    serializer_class<npl_l3_lp_profile_filter_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_lp_profile_filter_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_lp_profile_filter_table_key_t& m)
{
    serializer_class<npl_l3_lp_profile_filter_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_lp_profile_filter_table_key_t&);



template<>
class serializer_class<npl_l3_lp_profile_filter_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_lp_profile_filter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_lp_profile_filter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_lp_profile_filter_table_value_t& m)
{
    serializer_class<npl_l3_lp_profile_filter_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_lp_profile_filter_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_lp_profile_filter_table_value_t& m)
{
    serializer_class<npl_l3_lp_profile_filter_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_lp_profile_filter_table_value_t&);



template<>
class serializer_class<npl_l3_lp_profile_filter_table_value_t::npl_l3_lp_profile_filter_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_lp_profile_filter_table_value_t::npl_l3_lp_profile_filter_table_payloads_t& m) {
        uint64_t m_split_horizon = m.split_horizon;
            archive(::cereal::make_nvp("split_horizon", m_split_horizon));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_lp_profile_filter_table_value_t::npl_l3_lp_profile_filter_table_payloads_t& m) {
        uint64_t m_split_horizon;
            archive(::cereal::make_nvp("split_horizon", m_split_horizon));
        m.split_horizon = m_split_horizon;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_lp_profile_filter_table_value_t::npl_l3_lp_profile_filter_table_payloads_t& m)
{
    serializer_class<npl_l3_lp_profile_filter_table_value_t::npl_l3_lp_profile_filter_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_lp_profile_filter_table_value_t::npl_l3_lp_profile_filter_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_lp_profile_filter_table_value_t::npl_l3_lp_profile_filter_table_payloads_t& m)
{
    serializer_class<npl_l3_lp_profile_filter_table_value_t::npl_l3_lp_profile_filter_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_lp_profile_filter_table_value_t::npl_l3_lp_profile_filter_table_payloads_t&);



template<>
class serializer_class<npl_l3_termination_classify_ip_tunnels_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_termination_classify_ip_tunnels_table_key_t& m) {
        uint64_t m_l3_protocol_type = m.l3_protocol_type;
        uint64_t m_udp_dst_port_or_gre_proto = m.udp_dst_port_or_gre_proto;
            archive(::cereal::make_nvp("l3_protocol_type", m_l3_protocol_type));
            archive(::cereal::make_nvp("l4_protocol_type", m.l4_protocol_type));
            archive(::cereal::make_nvp("udp_dst_port_or_gre_proto", m_udp_dst_port_or_gre_proto));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_termination_classify_ip_tunnels_table_key_t& m) {
        uint64_t m_l3_protocol_type;
        uint64_t m_udp_dst_port_or_gre_proto;
            archive(::cereal::make_nvp("l3_protocol_type", m_l3_protocol_type));
            archive(::cereal::make_nvp("l4_protocol_type", m.l4_protocol_type));
            archive(::cereal::make_nvp("udp_dst_port_or_gre_proto", m_udp_dst_port_or_gre_proto));
        m.l3_protocol_type = m_l3_protocol_type;
        m.udp_dst_port_or_gre_proto = m_udp_dst_port_or_gre_proto;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_termination_classify_ip_tunnels_table_key_t& m)
{
    serializer_class<npl_l3_termination_classify_ip_tunnels_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_termination_classify_ip_tunnels_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_termination_classify_ip_tunnels_table_key_t& m)
{
    serializer_class<npl_l3_termination_classify_ip_tunnels_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_termination_classify_ip_tunnels_table_key_t&);



template<>
class serializer_class<npl_l3_termination_classify_ip_tunnels_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_termination_classify_ip_tunnels_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_termination_classify_ip_tunnels_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_termination_classify_ip_tunnels_table_value_t& m)
{
    serializer_class<npl_l3_termination_classify_ip_tunnels_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_termination_classify_ip_tunnels_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_termination_classify_ip_tunnels_table_value_t& m)
{
    serializer_class<npl_l3_termination_classify_ip_tunnels_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_termination_classify_ip_tunnels_table_value_t&);



template<>
class serializer_class<npl_l3_termination_classify_ip_tunnels_table_value_t::npl_l3_termination_classify_ip_tunnels_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_termination_classify_ip_tunnels_table_value_t::npl_l3_termination_classify_ip_tunnels_table_payloads_t& m) {
            archive(::cereal::make_nvp("tunnel_type", m.tunnel_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_termination_classify_ip_tunnels_table_value_t::npl_l3_termination_classify_ip_tunnels_table_payloads_t& m) {
            archive(::cereal::make_nvp("tunnel_type", m.tunnel_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_termination_classify_ip_tunnels_table_value_t::npl_l3_termination_classify_ip_tunnels_table_payloads_t& m)
{
    serializer_class<npl_l3_termination_classify_ip_tunnels_table_value_t::npl_l3_termination_classify_ip_tunnels_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_termination_classify_ip_tunnels_table_value_t::npl_l3_termination_classify_ip_tunnels_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_termination_classify_ip_tunnels_table_value_t::npl_l3_termination_classify_ip_tunnels_table_payloads_t& m)
{
    serializer_class<npl_l3_termination_classify_ip_tunnels_table_value_t::npl_l3_termination_classify_ip_tunnels_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_termination_classify_ip_tunnels_table_value_t::npl_l3_termination_classify_ip_tunnels_table_payloads_t&);



template<>
class serializer_class<npl_l3_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t& m) {
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t& m) {
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
save(Archive& archive, const npl_l3_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t& m)
{
    serializer_class<npl_l3_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t& m)
{
    serializer_class<npl_l3_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t&);



template<>
class serializer_class<npl_l3_termination_next_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_termination_next_macro_static_table_key_t& m) {
        uint64_t m_hdr_type = m.hdr_type;
        uint64_t m_dont_inc_pl = m.dont_inc_pl;
            archive(::cereal::make_nvp("hdr_type", m_hdr_type));
            archive(::cereal::make_nvp("ipv4_ipv6_init_rtf_stage", m.ipv4_ipv6_init_rtf_stage));
            archive(::cereal::make_nvp("dont_inc_pl", m_dont_inc_pl));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_termination_next_macro_static_table_key_t& m) {
        uint64_t m_hdr_type;
        uint64_t m_dont_inc_pl;
            archive(::cereal::make_nvp("hdr_type", m_hdr_type));
            archive(::cereal::make_nvp("ipv4_ipv6_init_rtf_stage", m.ipv4_ipv6_init_rtf_stage));
            archive(::cereal::make_nvp("dont_inc_pl", m_dont_inc_pl));
        m.hdr_type = m_hdr_type;
        m.dont_inc_pl = m_dont_inc_pl;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_termination_next_macro_static_table_key_t& m)
{
    serializer_class<npl_l3_termination_next_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_termination_next_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_termination_next_macro_static_table_key_t& m)
{
    serializer_class<npl_l3_termination_next_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_termination_next_macro_static_table_key_t&);



template<>
class serializer_class<npl_l3_termination_next_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_termination_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_termination_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_termination_next_macro_static_table_value_t& m)
{
    serializer_class<npl_l3_termination_next_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_termination_next_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_termination_next_macro_static_table_value_t& m)
{
    serializer_class<npl_l3_termination_next_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_termination_next_macro_static_table_value_t&);



template<>
class serializer_class<npl_l3_termination_next_macro_static_table_value_t::npl_l3_termination_next_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_termination_next_macro_static_table_value_t::npl_l3_termination_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("ip_termination_next_macro_action", m.ip_termination_next_macro_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_termination_next_macro_static_table_value_t::npl_l3_termination_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("ip_termination_next_macro_action", m.ip_termination_next_macro_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_termination_next_macro_static_table_value_t::npl_l3_termination_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_l3_termination_next_macro_static_table_value_t::npl_l3_termination_next_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_termination_next_macro_static_table_value_t::npl_l3_termination_next_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_termination_next_macro_static_table_value_t::npl_l3_termination_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_l3_termination_next_macro_static_table_value_t::npl_l3_termination_next_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_termination_next_macro_static_table_value_t::npl_l3_termination_next_macro_static_table_payloads_t&);



template<>
class serializer_class<npl_l3_tunnel_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_tunnel_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t& m) {
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_tunnel_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t& m) {
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
save(Archive& archive, const npl_l3_tunnel_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t& m)
{
    serializer_class<npl_l3_tunnel_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_tunnel_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_tunnel_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t& m)
{
    serializer_class<npl_l3_tunnel_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_tunnel_termination_next_macro_static_table_ip_termination_next_macro_action_payload_t&);



template<>
class serializer_class<npl_l3_tunnel_termination_next_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_tunnel_termination_next_macro_static_table_key_t& m) {
        uint64_t m_next_hdr_type = m.next_hdr_type;
        uint64_t m_lp_set = m.lp_set;
            archive(::cereal::make_nvp("next_hdr_type", m_next_hdr_type));
            archive(::cereal::make_nvp("term_attr_ipv4_ipv6_init_rtf_stage", m.term_attr_ipv4_ipv6_init_rtf_stage));
            archive(::cereal::make_nvp("pd_ipv4_init_rtf_stage", m.pd_ipv4_init_rtf_stage));
            archive(::cereal::make_nvp("lp_set", m_lp_set));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_tunnel_termination_next_macro_static_table_key_t& m) {
        uint64_t m_next_hdr_type;
        uint64_t m_lp_set;
            archive(::cereal::make_nvp("next_hdr_type", m_next_hdr_type));
            archive(::cereal::make_nvp("term_attr_ipv4_ipv6_init_rtf_stage", m.term_attr_ipv4_ipv6_init_rtf_stage));
            archive(::cereal::make_nvp("pd_ipv4_init_rtf_stage", m.pd_ipv4_init_rtf_stage));
            archive(::cereal::make_nvp("lp_set", m_lp_set));
        m.next_hdr_type = m_next_hdr_type;
        m.lp_set = m_lp_set;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_tunnel_termination_next_macro_static_table_key_t& m)
{
    serializer_class<npl_l3_tunnel_termination_next_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_tunnel_termination_next_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_tunnel_termination_next_macro_static_table_key_t& m)
{
    serializer_class<npl_l3_tunnel_termination_next_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_tunnel_termination_next_macro_static_table_key_t&);



template<>
class serializer_class<npl_l3_tunnel_termination_next_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_tunnel_termination_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_tunnel_termination_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_tunnel_termination_next_macro_static_table_value_t& m)
{
    serializer_class<npl_l3_tunnel_termination_next_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_tunnel_termination_next_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_tunnel_termination_next_macro_static_table_value_t& m)
{
    serializer_class<npl_l3_tunnel_termination_next_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_tunnel_termination_next_macro_static_table_value_t&);



template<>
class serializer_class<npl_l3_tunnel_termination_next_macro_static_table_value_t::npl_l3_tunnel_termination_next_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_tunnel_termination_next_macro_static_table_value_t::npl_l3_tunnel_termination_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("ip_termination_next_macro_action", m.ip_termination_next_macro_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_tunnel_termination_next_macro_static_table_value_t::npl_l3_tunnel_termination_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("ip_termination_next_macro_action", m.ip_termination_next_macro_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_tunnel_termination_next_macro_static_table_value_t::npl_l3_tunnel_termination_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_l3_tunnel_termination_next_macro_static_table_value_t::npl_l3_tunnel_termination_next_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_tunnel_termination_next_macro_static_table_value_t::npl_l3_tunnel_termination_next_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_tunnel_termination_next_macro_static_table_value_t::npl_l3_tunnel_termination_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_l3_tunnel_termination_next_macro_static_table_value_t::npl_l3_tunnel_termination_next_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_tunnel_termination_next_macro_static_table_value_t::npl_l3_tunnel_termination_next_macro_static_table_payloads_t&);



template<>
class serializer_class<npl_l3_vxlan_overlay_sa_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_vxlan_overlay_sa_table_key_t& m) {
        uint64_t m_sa_prefix_index = m.sa_prefix_index;
            archive(::cereal::make_nvp("sa_prefix_index", m_sa_prefix_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_vxlan_overlay_sa_table_key_t& m) {
        uint64_t m_sa_prefix_index;
            archive(::cereal::make_nvp("sa_prefix_index", m_sa_prefix_index));
        m.sa_prefix_index = m_sa_prefix_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_vxlan_overlay_sa_table_key_t& m)
{
    serializer_class<npl_l3_vxlan_overlay_sa_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_vxlan_overlay_sa_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_vxlan_overlay_sa_table_key_t& m)
{
    serializer_class<npl_l3_vxlan_overlay_sa_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_vxlan_overlay_sa_table_key_t&);



template<>
class serializer_class<npl_l3_vxlan_overlay_sa_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_vxlan_overlay_sa_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_vxlan_overlay_sa_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_vxlan_overlay_sa_table_value_t& m)
{
    serializer_class<npl_l3_vxlan_overlay_sa_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_vxlan_overlay_sa_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_vxlan_overlay_sa_table_value_t& m)
{
    serializer_class<npl_l3_vxlan_overlay_sa_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_vxlan_overlay_sa_table_value_t&);



template<>
class serializer_class<npl_l3_vxlan_overlay_sa_table_value_t::npl_l3_vxlan_overlay_sa_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_vxlan_overlay_sa_table_value_t::npl_l3_vxlan_overlay_sa_table_payloads_t& m) {
        uint64_t m_overlay_sa_msb = m.overlay_sa_msb;
            archive(::cereal::make_nvp("overlay_sa_msb", m_overlay_sa_msb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_vxlan_overlay_sa_table_value_t::npl_l3_vxlan_overlay_sa_table_payloads_t& m) {
        uint64_t m_overlay_sa_msb;
            archive(::cereal::make_nvp("overlay_sa_msb", m_overlay_sa_msb));
        m.overlay_sa_msb = m_overlay_sa_msb;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_vxlan_overlay_sa_table_value_t::npl_l3_vxlan_overlay_sa_table_payloads_t& m)
{
    serializer_class<npl_l3_vxlan_overlay_sa_table_value_t::npl_l3_vxlan_overlay_sa_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_vxlan_overlay_sa_table_value_t::npl_l3_vxlan_overlay_sa_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_vxlan_overlay_sa_table_value_t::npl_l3_vxlan_overlay_sa_table_payloads_t& m)
{
    serializer_class<npl_l3_vxlan_overlay_sa_table_value_t::npl_l3_vxlan_overlay_sa_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_vxlan_overlay_sa_table_value_t::npl_l3_vxlan_overlay_sa_table_payloads_t&);



template<>
class serializer_class<npl_large_em_key_lsb_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_large_em_key_lsb_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("lu_c_dest", m.lu_c_dest));
            archive(::cereal::make_nvp("lu_d_dest", m.lu_d_dest));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_large_em_key_lsb_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("lu_c_dest", m.lu_c_dest));
            archive(::cereal::make_nvp("lu_d_dest", m.lu_d_dest));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_large_em_key_lsb_mapping_table_key_t& m)
{
    serializer_class<npl_large_em_key_lsb_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_large_em_key_lsb_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_large_em_key_lsb_mapping_table_key_t& m)
{
    serializer_class<npl_large_em_key_lsb_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_large_em_key_lsb_mapping_table_key_t&);



template<>
class serializer_class<npl_large_em_key_lsb_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_large_em_key_lsb_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_large_em_key_lsb_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_large_em_key_lsb_mapping_table_value_t& m)
{
    serializer_class<npl_large_em_key_lsb_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_large_em_key_lsb_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_large_em_key_lsb_mapping_table_value_t& m)
{
    serializer_class<npl_large_em_key_lsb_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_large_em_key_lsb_mapping_table_value_t&);



template<>
class serializer_class<npl_large_em_key_lsb_mapping_table_value_t::npl_large_em_key_lsb_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_large_em_key_lsb_mapping_table_value_t::npl_large_em_key_lsb_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("large_em_key_lsb", m.large_em_key_lsb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_large_em_key_lsb_mapping_table_value_t::npl_large_em_key_lsb_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("large_em_key_lsb", m.large_em_key_lsb));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_large_em_key_lsb_mapping_table_value_t::npl_large_em_key_lsb_mapping_table_payloads_t& m)
{
    serializer_class<npl_large_em_key_lsb_mapping_table_value_t::npl_large_em_key_lsb_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_large_em_key_lsb_mapping_table_value_t::npl_large_em_key_lsb_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_large_em_key_lsb_mapping_table_value_t::npl_large_em_key_lsb_mapping_table_payloads_t& m)
{
    serializer_class<npl_large_em_key_lsb_mapping_table_value_t::npl_large_em_key_lsb_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_large_em_key_lsb_mapping_table_value_t::npl_large_em_key_lsb_mapping_table_payloads_t&);



template<>
class serializer_class<npl_large_encap_global_lsp_prefix_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_large_encap_global_lsp_prefix_table_key_t& m) {
        uint64_t m_lsp_dest_prefix = m.lsp_dest_prefix;
            archive(::cereal::make_nvp("lsp_dest_prefix", m_lsp_dest_prefix));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_large_encap_global_lsp_prefix_table_key_t& m) {
        uint64_t m_lsp_dest_prefix;
            archive(::cereal::make_nvp("lsp_dest_prefix", m_lsp_dest_prefix));
        m.lsp_dest_prefix = m_lsp_dest_prefix;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_large_encap_global_lsp_prefix_table_key_t& m)
{
    serializer_class<npl_large_encap_global_lsp_prefix_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_large_encap_global_lsp_prefix_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_large_encap_global_lsp_prefix_table_key_t& m)
{
    serializer_class<npl_large_encap_global_lsp_prefix_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_large_encap_global_lsp_prefix_table_key_t&);



template<>
class serializer_class<npl_large_encap_global_lsp_prefix_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_large_encap_global_lsp_prefix_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_large_encap_global_lsp_prefix_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_large_encap_global_lsp_prefix_table_value_t& m)
{
    serializer_class<npl_large_encap_global_lsp_prefix_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_large_encap_global_lsp_prefix_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_large_encap_global_lsp_prefix_table_value_t& m)
{
    serializer_class<npl_large_encap_global_lsp_prefix_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_large_encap_global_lsp_prefix_table_value_t&);



template<>
class serializer_class<npl_large_encap_global_lsp_prefix_table_value_t::npl_large_encap_global_lsp_prefix_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_large_encap_global_lsp_prefix_table_value_t::npl_large_encap_global_lsp_prefix_table_payloads_t& m) {
            archive(::cereal::make_nvp("lsp_encap_mapping_data_payload", m.lsp_encap_mapping_data_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_large_encap_global_lsp_prefix_table_value_t::npl_large_encap_global_lsp_prefix_table_payloads_t& m) {
            archive(::cereal::make_nvp("lsp_encap_mapping_data_payload", m.lsp_encap_mapping_data_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_large_encap_global_lsp_prefix_table_value_t::npl_large_encap_global_lsp_prefix_table_payloads_t& m)
{
    serializer_class<npl_large_encap_global_lsp_prefix_table_value_t::npl_large_encap_global_lsp_prefix_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_large_encap_global_lsp_prefix_table_value_t::npl_large_encap_global_lsp_prefix_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_large_encap_global_lsp_prefix_table_value_t::npl_large_encap_global_lsp_prefix_table_payloads_t& m)
{
    serializer_class<npl_large_encap_global_lsp_prefix_table_value_t::npl_large_encap_global_lsp_prefix_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_large_encap_global_lsp_prefix_table_value_t::npl_large_encap_global_lsp_prefix_table_payloads_t&);



template<>
class serializer_class<npl_large_encap_ip_tunnel_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_large_encap_ip_tunnel_table_key_t& m) {
        uint64_t m_gre_tunnel_dlp = m.gre_tunnel_dlp;
            archive(::cereal::make_nvp("gre_tunnel_dlp", m_gre_tunnel_dlp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_large_encap_ip_tunnel_table_key_t& m) {
        uint64_t m_gre_tunnel_dlp;
            archive(::cereal::make_nvp("gre_tunnel_dlp", m_gre_tunnel_dlp));
        m.gre_tunnel_dlp = m_gre_tunnel_dlp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_large_encap_ip_tunnel_table_key_t& m)
{
    serializer_class<npl_large_encap_ip_tunnel_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_large_encap_ip_tunnel_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_large_encap_ip_tunnel_table_key_t& m)
{
    serializer_class<npl_large_encap_ip_tunnel_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_large_encap_ip_tunnel_table_key_t&);



template<>
class serializer_class<npl_large_encap_ip_tunnel_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_large_encap_ip_tunnel_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_large_encap_ip_tunnel_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_large_encap_ip_tunnel_table_value_t& m)
{
    serializer_class<npl_large_encap_ip_tunnel_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_large_encap_ip_tunnel_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_large_encap_ip_tunnel_table_value_t& m)
{
    serializer_class<npl_large_encap_ip_tunnel_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_large_encap_ip_tunnel_table_value_t&);



template<>
class serializer_class<npl_large_encap_ip_tunnel_table_value_t::npl_large_encap_ip_tunnel_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_large_encap_ip_tunnel_table_value_t::npl_large_encap_ip_tunnel_table_payloads_t& m) {
            archive(::cereal::make_nvp("gre_tunnel_attributes", m.gre_tunnel_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_large_encap_ip_tunnel_table_value_t::npl_large_encap_ip_tunnel_table_payloads_t& m) {
            archive(::cereal::make_nvp("gre_tunnel_attributes", m.gre_tunnel_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_large_encap_ip_tunnel_table_value_t::npl_large_encap_ip_tunnel_table_payloads_t& m)
{
    serializer_class<npl_large_encap_ip_tunnel_table_value_t::npl_large_encap_ip_tunnel_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_large_encap_ip_tunnel_table_value_t::npl_large_encap_ip_tunnel_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_large_encap_ip_tunnel_table_value_t::npl_large_encap_ip_tunnel_table_payloads_t& m)
{
    serializer_class<npl_large_encap_ip_tunnel_table_value_t::npl_large_encap_ip_tunnel_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_large_encap_ip_tunnel_table_value_t::npl_large_encap_ip_tunnel_table_payloads_t&);



template<>
class serializer_class<npl_large_encap_mpls_he_no_ldp_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_large_encap_mpls_he_no_ldp_table_key_t& m) {
        uint64_t m_lsp_dest_prefix = m.lsp_dest_prefix;
        uint64_t m_nh_ptr = m.nh_ptr;
            archive(::cereal::make_nvp("lsp_dest_prefix", m_lsp_dest_prefix));
            archive(::cereal::make_nvp("nh_ptr", m_nh_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_large_encap_mpls_he_no_ldp_table_key_t& m) {
        uint64_t m_lsp_dest_prefix;
        uint64_t m_nh_ptr;
            archive(::cereal::make_nvp("lsp_dest_prefix", m_lsp_dest_prefix));
            archive(::cereal::make_nvp("nh_ptr", m_nh_ptr));
        m.lsp_dest_prefix = m_lsp_dest_prefix;
        m.nh_ptr = m_nh_ptr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_large_encap_mpls_he_no_ldp_table_key_t& m)
{
    serializer_class<npl_large_encap_mpls_he_no_ldp_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_large_encap_mpls_he_no_ldp_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_large_encap_mpls_he_no_ldp_table_key_t& m)
{
    serializer_class<npl_large_encap_mpls_he_no_ldp_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_large_encap_mpls_he_no_ldp_table_key_t&);



template<>
class serializer_class<npl_large_encap_mpls_he_no_ldp_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_large_encap_mpls_he_no_ldp_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_large_encap_mpls_he_no_ldp_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_large_encap_mpls_he_no_ldp_table_value_t& m)
{
    serializer_class<npl_large_encap_mpls_he_no_ldp_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_large_encap_mpls_he_no_ldp_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_large_encap_mpls_he_no_ldp_table_value_t& m)
{
    serializer_class<npl_large_encap_mpls_he_no_ldp_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_large_encap_mpls_he_no_ldp_table_value_t&);



template<>
class serializer_class<npl_large_encap_mpls_he_no_ldp_table_value_t::npl_large_encap_mpls_he_no_ldp_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_large_encap_mpls_he_no_ldp_table_value_t::npl_large_encap_mpls_he_no_ldp_table_payloads_t& m) {
            archive(::cereal::make_nvp("lsp_encap_mapping_data_payload", m.lsp_encap_mapping_data_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_large_encap_mpls_he_no_ldp_table_value_t::npl_large_encap_mpls_he_no_ldp_table_payloads_t& m) {
            archive(::cereal::make_nvp("lsp_encap_mapping_data_payload", m.lsp_encap_mapping_data_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_large_encap_mpls_he_no_ldp_table_value_t::npl_large_encap_mpls_he_no_ldp_table_payloads_t& m)
{
    serializer_class<npl_large_encap_mpls_he_no_ldp_table_value_t::npl_large_encap_mpls_he_no_ldp_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_large_encap_mpls_he_no_ldp_table_value_t::npl_large_encap_mpls_he_no_ldp_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_large_encap_mpls_he_no_ldp_table_value_t::npl_large_encap_mpls_he_no_ldp_table_payloads_t& m)
{
    serializer_class<npl_large_encap_mpls_he_no_ldp_table_value_t::npl_large_encap_mpls_he_no_ldp_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_large_encap_mpls_he_no_ldp_table_value_t::npl_large_encap_mpls_he_no_ldp_table_payloads_t&);



template<>
class serializer_class<npl_large_encap_mpls_ldp_over_te_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_large_encap_mpls_ldp_over_te_table_key_t& m) {
        uint64_t m_lsp_dest_prefix = m.lsp_dest_prefix;
        uint64_t m_te_tunnel = m.te_tunnel;
            archive(::cereal::make_nvp("lsp_dest_prefix", m_lsp_dest_prefix));
            archive(::cereal::make_nvp("te_tunnel", m_te_tunnel));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_large_encap_mpls_ldp_over_te_table_key_t& m) {
        uint64_t m_lsp_dest_prefix;
        uint64_t m_te_tunnel;
            archive(::cereal::make_nvp("lsp_dest_prefix", m_lsp_dest_prefix));
            archive(::cereal::make_nvp("te_tunnel", m_te_tunnel));
        m.lsp_dest_prefix = m_lsp_dest_prefix;
        m.te_tunnel = m_te_tunnel;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_large_encap_mpls_ldp_over_te_table_key_t& m)
{
    serializer_class<npl_large_encap_mpls_ldp_over_te_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_large_encap_mpls_ldp_over_te_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_large_encap_mpls_ldp_over_te_table_key_t& m)
{
    serializer_class<npl_large_encap_mpls_ldp_over_te_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_large_encap_mpls_ldp_over_te_table_key_t&);



template<>
class serializer_class<npl_large_encap_mpls_ldp_over_te_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_large_encap_mpls_ldp_over_te_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_large_encap_mpls_ldp_over_te_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_large_encap_mpls_ldp_over_te_table_value_t& m)
{
    serializer_class<npl_large_encap_mpls_ldp_over_te_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_large_encap_mpls_ldp_over_te_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_large_encap_mpls_ldp_over_te_table_value_t& m)
{
    serializer_class<npl_large_encap_mpls_ldp_over_te_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_large_encap_mpls_ldp_over_te_table_value_t&);



template<>
class serializer_class<npl_large_encap_mpls_ldp_over_te_table_value_t::npl_large_encap_mpls_ldp_over_te_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_large_encap_mpls_ldp_over_te_table_value_t::npl_large_encap_mpls_ldp_over_te_table_payloads_t& m) {
            archive(::cereal::make_nvp("large_em_label_encap_data_and_counter_ptr", m.large_em_label_encap_data_and_counter_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_large_encap_mpls_ldp_over_te_table_value_t::npl_large_encap_mpls_ldp_over_te_table_payloads_t& m) {
            archive(::cereal::make_nvp("large_em_label_encap_data_and_counter_ptr", m.large_em_label_encap_data_and_counter_ptr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_large_encap_mpls_ldp_over_te_table_value_t::npl_large_encap_mpls_ldp_over_te_table_payloads_t& m)
{
    serializer_class<npl_large_encap_mpls_ldp_over_te_table_value_t::npl_large_encap_mpls_ldp_over_te_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_large_encap_mpls_ldp_over_te_table_value_t::npl_large_encap_mpls_ldp_over_te_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_large_encap_mpls_ldp_over_te_table_value_t::npl_large_encap_mpls_ldp_over_te_table_payloads_t& m)
{
    serializer_class<npl_large_encap_mpls_ldp_over_te_table_value_t::npl_large_encap_mpls_ldp_over_te_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_large_encap_mpls_ldp_over_te_table_value_t::npl_large_encap_mpls_ldp_over_te_table_payloads_t&);



template<>
class serializer_class<npl_large_encap_te_he_tunnel_id_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_large_encap_te_he_tunnel_id_table_key_t& m) {
        uint64_t m_te_tunnel = m.te_tunnel;
        uint64_t m_nh_ptr = m.nh_ptr;
            archive(::cereal::make_nvp("te_tunnel", m_te_tunnel));
            archive(::cereal::make_nvp("nh_ptr", m_nh_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_large_encap_te_he_tunnel_id_table_key_t& m) {
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
save(Archive& archive, const npl_large_encap_te_he_tunnel_id_table_key_t& m)
{
    serializer_class<npl_large_encap_te_he_tunnel_id_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_large_encap_te_he_tunnel_id_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_large_encap_te_he_tunnel_id_table_key_t& m)
{
    serializer_class<npl_large_encap_te_he_tunnel_id_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_large_encap_te_he_tunnel_id_table_key_t&);



template<>
class serializer_class<npl_large_encap_te_he_tunnel_id_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_large_encap_te_he_tunnel_id_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_large_encap_te_he_tunnel_id_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_large_encap_te_he_tunnel_id_table_value_t& m)
{
    serializer_class<npl_large_encap_te_he_tunnel_id_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_large_encap_te_he_tunnel_id_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_large_encap_te_he_tunnel_id_table_value_t& m)
{
    serializer_class<npl_large_encap_te_he_tunnel_id_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_large_encap_te_he_tunnel_id_table_value_t&);



template<>
class serializer_class<npl_large_encap_te_he_tunnel_id_table_value_t::npl_large_encap_te_he_tunnel_id_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_large_encap_te_he_tunnel_id_table_value_t::npl_large_encap_te_he_tunnel_id_table_payloads_t& m) {
            archive(::cereal::make_nvp("lsp_encap_mapping_data_payload", m.lsp_encap_mapping_data_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_large_encap_te_he_tunnel_id_table_value_t::npl_large_encap_te_he_tunnel_id_table_payloads_t& m) {
            archive(::cereal::make_nvp("lsp_encap_mapping_data_payload", m.lsp_encap_mapping_data_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_large_encap_te_he_tunnel_id_table_value_t::npl_large_encap_te_he_tunnel_id_table_payloads_t& m)
{
    serializer_class<npl_large_encap_te_he_tunnel_id_table_value_t::npl_large_encap_te_he_tunnel_id_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_large_encap_te_he_tunnel_id_table_value_t::npl_large_encap_te_he_tunnel_id_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_large_encap_te_he_tunnel_id_table_value_t::npl_large_encap_te_he_tunnel_id_table_payloads_t& m)
{
    serializer_class<npl_large_encap_te_he_tunnel_id_table_value_t::npl_large_encap_te_he_tunnel_id_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_large_encap_te_he_tunnel_id_table_value_t::npl_large_encap_te_he_tunnel_id_table_payloads_t&);



template<>
class serializer_class<npl_latest_learn_records_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_latest_learn_records_table_key_t& m) {
            archive(::cereal::make_nvp("learn_record_filter_vars_read_ptr", m.learn_record_filter_vars_read_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_latest_learn_records_table_key_t& m) {
            archive(::cereal::make_nvp("learn_record_filter_vars_read_ptr", m.learn_record_filter_vars_read_ptr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_latest_learn_records_table_key_t& m)
{
    serializer_class<npl_latest_learn_records_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_latest_learn_records_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_latest_learn_records_table_key_t& m)
{
    serializer_class<npl_latest_learn_records_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_latest_learn_records_table_key_t&);



template<>
class serializer_class<npl_latest_learn_records_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_latest_learn_records_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_latest_learn_records_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_latest_learn_records_table_value_t& m)
{
    serializer_class<npl_latest_learn_records_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_latest_learn_records_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_latest_learn_records_table_value_t& m)
{
    serializer_class<npl_latest_learn_records_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_latest_learn_records_table_value_t&);



template<>
class serializer_class<npl_latest_learn_records_table_value_t::npl_latest_learn_records_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_latest_learn_records_table_value_t::npl_latest_learn_records_table_payloads_t& m) {
            archive(::cereal::make_nvp("learn_record_filter_vars_filter_result", m.learn_record_filter_vars_filter_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_latest_learn_records_table_value_t::npl_latest_learn_records_table_payloads_t& m) {
            archive(::cereal::make_nvp("learn_record_filter_vars_filter_result", m.learn_record_filter_vars_filter_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_latest_learn_records_table_value_t::npl_latest_learn_records_table_payloads_t& m)
{
    serializer_class<npl_latest_learn_records_table_value_t::npl_latest_learn_records_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_latest_learn_records_table_value_t::npl_latest_learn_records_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_latest_learn_records_table_value_t::npl_latest_learn_records_table_payloads_t& m)
{
    serializer_class<npl_latest_learn_records_table_value_t::npl_latest_learn_records_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_latest_learn_records_table_value_t::npl_latest_learn_records_table_payloads_t&);



template<>
class serializer_class<npl_learn_manager_cfg_max_learn_type_reg_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_learn_manager_cfg_max_learn_type_reg_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_learn_manager_cfg_max_learn_type_reg_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_learn_manager_cfg_max_learn_type_reg_key_t& m)
{
    serializer_class<npl_learn_manager_cfg_max_learn_type_reg_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_learn_manager_cfg_max_learn_type_reg_key_t&);

template <class Archive>
void
load(Archive& archive, npl_learn_manager_cfg_max_learn_type_reg_key_t& m)
{
    serializer_class<npl_learn_manager_cfg_max_learn_type_reg_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_learn_manager_cfg_max_learn_type_reg_key_t&);



template<>
class serializer_class<npl_learn_manager_cfg_max_learn_type_reg_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_learn_manager_cfg_max_learn_type_reg_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_learn_manager_cfg_max_learn_type_reg_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_learn_manager_cfg_max_learn_type_reg_value_t& m)
{
    serializer_class<npl_learn_manager_cfg_max_learn_type_reg_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_learn_manager_cfg_max_learn_type_reg_value_t&);

template <class Archive>
void
load(Archive& archive, npl_learn_manager_cfg_max_learn_type_reg_value_t& m)
{
    serializer_class<npl_learn_manager_cfg_max_learn_type_reg_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_learn_manager_cfg_max_learn_type_reg_value_t&);



template<>
class serializer_class<npl_learn_manager_cfg_max_learn_type_reg_value_t::npl_learn_manager_cfg_max_learn_type_reg_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_learn_manager_cfg_max_learn_type_reg_value_t::npl_learn_manager_cfg_max_learn_type_reg_payloads_t& m) {
            archive(::cereal::make_nvp("learn_manager_cfg_max_learn_type", m.learn_manager_cfg_max_learn_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_learn_manager_cfg_max_learn_type_reg_value_t::npl_learn_manager_cfg_max_learn_type_reg_payloads_t& m) {
            archive(::cereal::make_nvp("learn_manager_cfg_max_learn_type", m.learn_manager_cfg_max_learn_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_learn_manager_cfg_max_learn_type_reg_value_t::npl_learn_manager_cfg_max_learn_type_reg_payloads_t& m)
{
    serializer_class<npl_learn_manager_cfg_max_learn_type_reg_value_t::npl_learn_manager_cfg_max_learn_type_reg_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_learn_manager_cfg_max_learn_type_reg_value_t::npl_learn_manager_cfg_max_learn_type_reg_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_learn_manager_cfg_max_learn_type_reg_value_t::npl_learn_manager_cfg_max_learn_type_reg_payloads_t& m)
{
    serializer_class<npl_learn_manager_cfg_max_learn_type_reg_value_t::npl_learn_manager_cfg_max_learn_type_reg_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_learn_manager_cfg_max_learn_type_reg_value_t::npl_learn_manager_cfg_max_learn_type_reg_payloads_t&);



template<>
class serializer_class<npl_learn_record_fifo_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_learn_record_fifo_table_key_t& m) {
            archive(::cereal::make_nvp("learn_record_fifo_address", m.learn_record_fifo_address));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_learn_record_fifo_table_key_t& m) {
            archive(::cereal::make_nvp("learn_record_fifo_address", m.learn_record_fifo_address));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_learn_record_fifo_table_key_t& m)
{
    serializer_class<npl_learn_record_fifo_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_learn_record_fifo_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_learn_record_fifo_table_key_t& m)
{
    serializer_class<npl_learn_record_fifo_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_learn_record_fifo_table_key_t&);



template<>
class serializer_class<npl_learn_record_fifo_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_learn_record_fifo_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_learn_record_fifo_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_learn_record_fifo_table_value_t& m)
{
    serializer_class<npl_learn_record_fifo_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_learn_record_fifo_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_learn_record_fifo_table_value_t& m)
{
    serializer_class<npl_learn_record_fifo_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_learn_record_fifo_table_value_t&);



template<>
class serializer_class<npl_learn_record_fifo_table_value_t::npl_learn_record_fifo_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_learn_record_fifo_table_value_t::npl_learn_record_fifo_table_payloads_t& m) {
            archive(::cereal::make_nvp("learn_record_result", m.learn_record_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_learn_record_fifo_table_value_t::npl_learn_record_fifo_table_payloads_t& m) {
            archive(::cereal::make_nvp("learn_record_result", m.learn_record_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_learn_record_fifo_table_value_t::npl_learn_record_fifo_table_payloads_t& m)
{
    serializer_class<npl_learn_record_fifo_table_value_t::npl_learn_record_fifo_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_learn_record_fifo_table_value_t::npl_learn_record_fifo_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_learn_record_fifo_table_value_t::npl_learn_record_fifo_table_payloads_t& m)
{
    serializer_class<npl_learn_record_fifo_table_value_t::npl_learn_record_fifo_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_learn_record_fifo_table_value_t::npl_learn_record_fifo_table_payloads_t&);



template<>
class serializer_class<npl_light_fi_fabric_table_light_fi_leaba_table_hit_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_fabric_table_light_fi_leaba_table_hit_payload_t& m) {
        uint64_t m_use_additional_size = m.use_additional_size;
        uint64_t m_base_size = m.base_size;
        uint64_t m_is_next_protocol_layer = m.is_next_protocol_layer;
        uint64_t m_is_protocol_layer = m.is_protocol_layer;
        uint64_t m_npe_macro_id = m.npe_macro_id;
        uint64_t m_npe_macro_id_valid = m.npe_macro_id_valid;
            archive(::cereal::make_nvp("use_additional_size", m_use_additional_size));
            archive(::cereal::make_nvp("base_size", m_base_size));
            archive(::cereal::make_nvp("is_next_protocol_layer", m_is_next_protocol_layer));
            archive(::cereal::make_nvp("is_protocol_layer", m_is_protocol_layer));
            archive(::cereal::make_nvp("next_fi_macro_id", m.next_fi_macro_id));
            archive(::cereal::make_nvp("npe_macro_id", m_npe_macro_id));
            archive(::cereal::make_nvp("npe_macro_id_valid", m_npe_macro_id_valid));
            archive(::cereal::make_nvp("next_header_format", m.next_header_format));
            archive(::cereal::make_nvp("header_format", m.header_format));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_fabric_table_light_fi_leaba_table_hit_payload_t& m) {
        uint64_t m_use_additional_size;
        uint64_t m_base_size;
        uint64_t m_is_next_protocol_layer;
        uint64_t m_is_protocol_layer;
        uint64_t m_npe_macro_id;
        uint64_t m_npe_macro_id_valid;
            archive(::cereal::make_nvp("use_additional_size", m_use_additional_size));
            archive(::cereal::make_nvp("base_size", m_base_size));
            archive(::cereal::make_nvp("is_next_protocol_layer", m_is_next_protocol_layer));
            archive(::cereal::make_nvp("is_protocol_layer", m_is_protocol_layer));
            archive(::cereal::make_nvp("next_fi_macro_id", m.next_fi_macro_id));
            archive(::cereal::make_nvp("npe_macro_id", m_npe_macro_id));
            archive(::cereal::make_nvp("npe_macro_id_valid", m_npe_macro_id_valid));
            archive(::cereal::make_nvp("next_header_format", m.next_header_format));
            archive(::cereal::make_nvp("header_format", m.header_format));
        m.use_additional_size = m_use_additional_size;
        m.base_size = m_base_size;
        m.is_next_protocol_layer = m_is_next_protocol_layer;
        m.is_protocol_layer = m_is_protocol_layer;
        m.npe_macro_id = m_npe_macro_id;
        m.npe_macro_id_valid = m_npe_macro_id_valid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_fabric_table_light_fi_leaba_table_hit_payload_t& m)
{
    serializer_class<npl_light_fi_fabric_table_light_fi_leaba_table_hit_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_fabric_table_light_fi_leaba_table_hit_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_fabric_table_light_fi_leaba_table_hit_payload_t& m)
{
    serializer_class<npl_light_fi_fabric_table_light_fi_leaba_table_hit_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_fabric_table_light_fi_leaba_table_hit_payload_t&);



template<>
class serializer_class<npl_light_fi_fabric_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_fabric_table_key_t& m) {
        uint64_t m_fabric_header_type = m.fabric_header_type;
            archive(::cereal::make_nvp("fabric_header_type", m_fabric_header_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_fabric_table_key_t& m) {
        uint64_t m_fabric_header_type;
            archive(::cereal::make_nvp("fabric_header_type", m_fabric_header_type));
        m.fabric_header_type = m_fabric_header_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_fabric_table_key_t& m)
{
    serializer_class<npl_light_fi_fabric_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_fabric_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_fabric_table_key_t& m)
{
    serializer_class<npl_light_fi_fabric_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_fabric_table_key_t&);



template<>
class serializer_class<npl_light_fi_fabric_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_fabric_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_fabric_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_fabric_table_value_t& m)
{
    serializer_class<npl_light_fi_fabric_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_fabric_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_fabric_table_value_t& m)
{
    serializer_class<npl_light_fi_fabric_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_fabric_table_value_t&);



template<>
class serializer_class<npl_light_fi_fabric_table_value_t::npl_light_fi_fabric_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_fabric_table_value_t::npl_light_fi_fabric_table_payloads_t& m) {
            archive(::cereal::make_nvp("light_fi_leaba_table_hit", m.light_fi_leaba_table_hit));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_fabric_table_value_t::npl_light_fi_fabric_table_payloads_t& m) {
            archive(::cereal::make_nvp("light_fi_leaba_table_hit", m.light_fi_leaba_table_hit));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_fabric_table_value_t::npl_light_fi_fabric_table_payloads_t& m)
{
    serializer_class<npl_light_fi_fabric_table_value_t::npl_light_fi_fabric_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_fabric_table_value_t::npl_light_fi_fabric_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_fabric_table_value_t::npl_light_fi_fabric_table_payloads_t& m)
{
    serializer_class<npl_light_fi_fabric_table_value_t::npl_light_fi_fabric_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_fabric_table_value_t::npl_light_fi_fabric_table_payloads_t&);



template<>
class serializer_class<npl_light_fi_npu_base_table_light_fi_leaba_table_hit_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_npu_base_table_light_fi_leaba_table_hit_payload_t& m) {
        uint64_t m_use_additional_size = m.use_additional_size;
        uint64_t m_base_size = m.base_size;
        uint64_t m_is_next_protocol_layer = m.is_next_protocol_layer;
        uint64_t m_is_protocol_layer = m.is_protocol_layer;
        uint64_t m_npe_macro_id = m.npe_macro_id;
        uint64_t m_npe_macro_id_valid = m.npe_macro_id_valid;
            archive(::cereal::make_nvp("use_additional_size", m_use_additional_size));
            archive(::cereal::make_nvp("base_size", m_base_size));
            archive(::cereal::make_nvp("is_next_protocol_layer", m_is_next_protocol_layer));
            archive(::cereal::make_nvp("is_protocol_layer", m_is_protocol_layer));
            archive(::cereal::make_nvp("next_fi_macro_id", m.next_fi_macro_id));
            archive(::cereal::make_nvp("npe_macro_id", m_npe_macro_id));
            archive(::cereal::make_nvp("npe_macro_id_valid", m_npe_macro_id_valid));
            archive(::cereal::make_nvp("next_header_format", m.next_header_format));
            archive(::cereal::make_nvp("header_format", m.header_format));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_npu_base_table_light_fi_leaba_table_hit_payload_t& m) {
        uint64_t m_use_additional_size;
        uint64_t m_base_size;
        uint64_t m_is_next_protocol_layer;
        uint64_t m_is_protocol_layer;
        uint64_t m_npe_macro_id;
        uint64_t m_npe_macro_id_valid;
            archive(::cereal::make_nvp("use_additional_size", m_use_additional_size));
            archive(::cereal::make_nvp("base_size", m_base_size));
            archive(::cereal::make_nvp("is_next_protocol_layer", m_is_next_protocol_layer));
            archive(::cereal::make_nvp("is_protocol_layer", m_is_protocol_layer));
            archive(::cereal::make_nvp("next_fi_macro_id", m.next_fi_macro_id));
            archive(::cereal::make_nvp("npe_macro_id", m_npe_macro_id));
            archive(::cereal::make_nvp("npe_macro_id_valid", m_npe_macro_id_valid));
            archive(::cereal::make_nvp("next_header_format", m.next_header_format));
            archive(::cereal::make_nvp("header_format", m.header_format));
        m.use_additional_size = m_use_additional_size;
        m.base_size = m_base_size;
        m.is_next_protocol_layer = m_is_next_protocol_layer;
        m.is_protocol_layer = m_is_protocol_layer;
        m.npe_macro_id = m_npe_macro_id;
        m.npe_macro_id_valid = m_npe_macro_id_valid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_npu_base_table_light_fi_leaba_table_hit_payload_t& m)
{
    serializer_class<npl_light_fi_npu_base_table_light_fi_leaba_table_hit_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_npu_base_table_light_fi_leaba_table_hit_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_npu_base_table_light_fi_leaba_table_hit_payload_t& m)
{
    serializer_class<npl_light_fi_npu_base_table_light_fi_leaba_table_hit_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_npu_base_table_light_fi_leaba_table_hit_payload_t&);



template<>
class serializer_class<npl_light_fi_npu_base_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_npu_base_table_key_t& m) {
        uint64_t m_npu_header_type = m.npu_header_type;
            archive(::cereal::make_nvp("npu_header_type", m_npu_header_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_npu_base_table_key_t& m) {
        uint64_t m_npu_header_type;
            archive(::cereal::make_nvp("npu_header_type", m_npu_header_type));
        m.npu_header_type = m_npu_header_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_npu_base_table_key_t& m)
{
    serializer_class<npl_light_fi_npu_base_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_npu_base_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_npu_base_table_key_t& m)
{
    serializer_class<npl_light_fi_npu_base_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_npu_base_table_key_t&);



template<>
class serializer_class<npl_light_fi_npu_base_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_npu_base_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_npu_base_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_npu_base_table_value_t& m)
{
    serializer_class<npl_light_fi_npu_base_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_npu_base_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_npu_base_table_value_t& m)
{
    serializer_class<npl_light_fi_npu_base_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_npu_base_table_value_t&);



template<>
class serializer_class<npl_light_fi_npu_base_table_value_t::npl_light_fi_npu_base_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_npu_base_table_value_t::npl_light_fi_npu_base_table_payloads_t& m) {
            archive(::cereal::make_nvp("light_fi_leaba_table_hit", m.light_fi_leaba_table_hit));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_npu_base_table_value_t::npl_light_fi_npu_base_table_payloads_t& m) {
            archive(::cereal::make_nvp("light_fi_leaba_table_hit", m.light_fi_leaba_table_hit));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_npu_base_table_value_t::npl_light_fi_npu_base_table_payloads_t& m)
{
    serializer_class<npl_light_fi_npu_base_table_value_t::npl_light_fi_npu_base_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_npu_base_table_value_t::npl_light_fi_npu_base_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_npu_base_table_value_t::npl_light_fi_npu_base_table_payloads_t& m)
{
    serializer_class<npl_light_fi_npu_base_table_value_t::npl_light_fi_npu_base_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_npu_base_table_value_t::npl_light_fi_npu_base_table_payloads_t&);



template<>
class serializer_class<npl_light_fi_npu_encap_table_light_fi_npu_encap_table_hit_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_npu_encap_table_light_fi_npu_encap_table_hit_payload_t& m) {
        uint64_t m_spare = m.spare;
        uint64_t m_next_stage_size_width = m.next_stage_size_width;
        uint64_t m_next_stage_size_offset = m.next_stage_size_offset;
        uint64_t m_next_stage_protocol_or_type_offset = m.next_stage_protocol_or_type_offset;
            archive(::cereal::make_nvp("spare", m_spare));
            archive(::cereal::make_nvp("next_stage_size_width", m_next_stage_size_width));
            archive(::cereal::make_nvp("next_stage_size_offset", m_next_stage_size_offset));
            archive(::cereal::make_nvp("next_stage_protocol_or_type_offset", m_next_stage_protocol_or_type_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_npu_encap_table_light_fi_npu_encap_table_hit_payload_t& m) {
        uint64_t m_spare;
        uint64_t m_next_stage_size_width;
        uint64_t m_next_stage_size_offset;
        uint64_t m_next_stage_protocol_or_type_offset;
            archive(::cereal::make_nvp("spare", m_spare));
            archive(::cereal::make_nvp("next_stage_size_width", m_next_stage_size_width));
            archive(::cereal::make_nvp("next_stage_size_offset", m_next_stage_size_offset));
            archive(::cereal::make_nvp("next_stage_protocol_or_type_offset", m_next_stage_protocol_or_type_offset));
        m.spare = m_spare;
        m.next_stage_size_width = m_next_stage_size_width;
        m.next_stage_size_offset = m_next_stage_size_offset;
        m.next_stage_protocol_or_type_offset = m_next_stage_protocol_or_type_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_npu_encap_table_light_fi_npu_encap_table_hit_payload_t& m)
{
    serializer_class<npl_light_fi_npu_encap_table_light_fi_npu_encap_table_hit_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_npu_encap_table_light_fi_npu_encap_table_hit_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_npu_encap_table_light_fi_npu_encap_table_hit_payload_t& m)
{
    serializer_class<npl_light_fi_npu_encap_table_light_fi_npu_encap_table_hit_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_npu_encap_table_light_fi_npu_encap_table_hit_payload_t&);



template<>
class serializer_class<npl_light_fi_npu_encap_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_npu_encap_table_key_t& m) {
        uint64_t m_next_header_type = m.next_header_type;
            archive(::cereal::make_nvp("next_header_type", m_next_header_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_npu_encap_table_key_t& m) {
        uint64_t m_next_header_type;
            archive(::cereal::make_nvp("next_header_type", m_next_header_type));
        m.next_header_type = m_next_header_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_npu_encap_table_key_t& m)
{
    serializer_class<npl_light_fi_npu_encap_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_npu_encap_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_npu_encap_table_key_t& m)
{
    serializer_class<npl_light_fi_npu_encap_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_npu_encap_table_key_t&);



template<>
class serializer_class<npl_light_fi_npu_encap_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_npu_encap_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_npu_encap_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_npu_encap_table_value_t& m)
{
    serializer_class<npl_light_fi_npu_encap_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_npu_encap_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_npu_encap_table_value_t& m)
{
    serializer_class<npl_light_fi_npu_encap_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_npu_encap_table_value_t&);



template<>
class serializer_class<npl_light_fi_npu_encap_table_value_t::npl_light_fi_npu_encap_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_npu_encap_table_value_t::npl_light_fi_npu_encap_table_payloads_t& m) {
            archive(::cereal::make_nvp("light_fi_npu_encap_table_hit", m.light_fi_npu_encap_table_hit));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_npu_encap_table_value_t::npl_light_fi_npu_encap_table_payloads_t& m) {
            archive(::cereal::make_nvp("light_fi_npu_encap_table_hit", m.light_fi_npu_encap_table_hit));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_npu_encap_table_value_t::npl_light_fi_npu_encap_table_payloads_t& m)
{
    serializer_class<npl_light_fi_npu_encap_table_value_t::npl_light_fi_npu_encap_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_npu_encap_table_value_t::npl_light_fi_npu_encap_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_npu_encap_table_value_t::npl_light_fi_npu_encap_table_payloads_t& m)
{
    serializer_class<npl_light_fi_npu_encap_table_value_t::npl_light_fi_npu_encap_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_npu_encap_table_value_t::npl_light_fi_npu_encap_table_payloads_t&);



template<>
class serializer_class<npl_light_fi_nw_0_table_light_fi_nw_table_hit_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_nw_0_table_light_fi_nw_table_hit_payload_t& m) {
        uint64_t m_next_stage_size_width = m.next_stage_size_width;
        uint64_t m_next_stage_size_offset = m.next_stage_size_offset;
        uint64_t m_next_stage_protocol_or_type_offset = m.next_stage_protocol_or_type_offset;
        uint64_t m_use_additional_size = m.use_additional_size;
        uint64_t m_base_size = m.base_size;
        uint64_t m_is_next_protocol_layer = m.is_next_protocol_layer;
        uint64_t m_is_protocol_layer = m.is_protocol_layer;
            archive(::cereal::make_nvp("next_stage_size_width", m_next_stage_size_width));
            archive(::cereal::make_nvp("next_stage_size_offset", m_next_stage_size_offset));
            archive(::cereal::make_nvp("next_stage_protocol_or_type_offset", m_next_stage_protocol_or_type_offset));
            archive(::cereal::make_nvp("use_additional_size", m_use_additional_size));
            archive(::cereal::make_nvp("base_size", m_base_size));
            archive(::cereal::make_nvp("is_next_protocol_layer", m_is_next_protocol_layer));
            archive(::cereal::make_nvp("is_protocol_layer", m_is_protocol_layer));
            archive(::cereal::make_nvp("next_fi_macro_id", m.next_fi_macro_id));
            archive(::cereal::make_nvp("next_header_format", m.next_header_format));
            archive(::cereal::make_nvp("header_format", m.header_format));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_nw_0_table_light_fi_nw_table_hit_payload_t& m) {
        uint64_t m_next_stage_size_width;
        uint64_t m_next_stage_size_offset;
        uint64_t m_next_stage_protocol_or_type_offset;
        uint64_t m_use_additional_size;
        uint64_t m_base_size;
        uint64_t m_is_next_protocol_layer;
        uint64_t m_is_protocol_layer;
            archive(::cereal::make_nvp("next_stage_size_width", m_next_stage_size_width));
            archive(::cereal::make_nvp("next_stage_size_offset", m_next_stage_size_offset));
            archive(::cereal::make_nvp("next_stage_protocol_or_type_offset", m_next_stage_protocol_or_type_offset));
            archive(::cereal::make_nvp("use_additional_size", m_use_additional_size));
            archive(::cereal::make_nvp("base_size", m_base_size));
            archive(::cereal::make_nvp("is_next_protocol_layer", m_is_next_protocol_layer));
            archive(::cereal::make_nvp("is_protocol_layer", m_is_protocol_layer));
            archive(::cereal::make_nvp("next_fi_macro_id", m.next_fi_macro_id));
            archive(::cereal::make_nvp("next_header_format", m.next_header_format));
            archive(::cereal::make_nvp("header_format", m.header_format));
        m.next_stage_size_width = m_next_stage_size_width;
        m.next_stage_size_offset = m_next_stage_size_offset;
        m.next_stage_protocol_or_type_offset = m_next_stage_protocol_or_type_offset;
        m.use_additional_size = m_use_additional_size;
        m.base_size = m_base_size;
        m.is_next_protocol_layer = m_is_next_protocol_layer;
        m.is_protocol_layer = m_is_protocol_layer;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_nw_0_table_light_fi_nw_table_hit_payload_t& m)
{
    serializer_class<npl_light_fi_nw_0_table_light_fi_nw_table_hit_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_nw_0_table_light_fi_nw_table_hit_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_nw_0_table_light_fi_nw_table_hit_payload_t& m)
{
    serializer_class<npl_light_fi_nw_0_table_light_fi_nw_table_hit_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_nw_0_table_light_fi_nw_table_hit_payload_t&);



template<>
class serializer_class<npl_light_fi_nw_0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_nw_0_table_key_t& m) {
        uint64_t m_next_protocol_field = m.next_protocol_field;
            archive(::cereal::make_nvp("current_header_type", m.current_header_type));
            archive(::cereal::make_nvp("next_protocol_field", m_next_protocol_field));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_nw_0_table_key_t& m) {
        uint64_t m_next_protocol_field;
            archive(::cereal::make_nvp("current_header_type", m.current_header_type));
            archive(::cereal::make_nvp("next_protocol_field", m_next_protocol_field));
        m.next_protocol_field = m_next_protocol_field;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_nw_0_table_key_t& m)
{
    serializer_class<npl_light_fi_nw_0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_nw_0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_nw_0_table_key_t& m)
{
    serializer_class<npl_light_fi_nw_0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_nw_0_table_key_t&);



template<>
class serializer_class<npl_light_fi_nw_0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_nw_0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_nw_0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_nw_0_table_value_t& m)
{
    serializer_class<npl_light_fi_nw_0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_nw_0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_nw_0_table_value_t& m)
{
    serializer_class<npl_light_fi_nw_0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_nw_0_table_value_t&);



template<>
class serializer_class<npl_light_fi_nw_0_table_value_t::npl_light_fi_nw_0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_nw_0_table_value_t::npl_light_fi_nw_0_table_payloads_t& m) {
            archive(::cereal::make_nvp("light_fi_nw_table_hit", m.light_fi_nw_table_hit));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_nw_0_table_value_t::npl_light_fi_nw_0_table_payloads_t& m) {
            archive(::cereal::make_nvp("light_fi_nw_table_hit", m.light_fi_nw_table_hit));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_nw_0_table_value_t::npl_light_fi_nw_0_table_payloads_t& m)
{
    serializer_class<npl_light_fi_nw_0_table_value_t::npl_light_fi_nw_0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_nw_0_table_value_t::npl_light_fi_nw_0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_nw_0_table_value_t::npl_light_fi_nw_0_table_payloads_t& m)
{
    serializer_class<npl_light_fi_nw_0_table_value_t::npl_light_fi_nw_0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_nw_0_table_value_t::npl_light_fi_nw_0_table_payloads_t&);



template<>
class serializer_class<npl_light_fi_nw_1_table_light_fi_nw_table_hit_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_nw_1_table_light_fi_nw_table_hit_payload_t& m) {
        uint64_t m_next_stage_size_width = m.next_stage_size_width;
        uint64_t m_next_stage_size_offset = m.next_stage_size_offset;
        uint64_t m_next_stage_protocol_or_type_offset = m.next_stage_protocol_or_type_offset;
        uint64_t m_use_additional_size = m.use_additional_size;
        uint64_t m_base_size = m.base_size;
        uint64_t m_is_next_protocol_layer = m.is_next_protocol_layer;
        uint64_t m_is_protocol_layer = m.is_protocol_layer;
            archive(::cereal::make_nvp("next_stage_size_width", m_next_stage_size_width));
            archive(::cereal::make_nvp("next_stage_size_offset", m_next_stage_size_offset));
            archive(::cereal::make_nvp("next_stage_protocol_or_type_offset", m_next_stage_protocol_or_type_offset));
            archive(::cereal::make_nvp("use_additional_size", m_use_additional_size));
            archive(::cereal::make_nvp("base_size", m_base_size));
            archive(::cereal::make_nvp("is_next_protocol_layer", m_is_next_protocol_layer));
            archive(::cereal::make_nvp("is_protocol_layer", m_is_protocol_layer));
            archive(::cereal::make_nvp("next_fi_macro_id", m.next_fi_macro_id));
            archive(::cereal::make_nvp("next_header_format", m.next_header_format));
            archive(::cereal::make_nvp("header_format", m.header_format));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_nw_1_table_light_fi_nw_table_hit_payload_t& m) {
        uint64_t m_next_stage_size_width;
        uint64_t m_next_stage_size_offset;
        uint64_t m_next_stage_protocol_or_type_offset;
        uint64_t m_use_additional_size;
        uint64_t m_base_size;
        uint64_t m_is_next_protocol_layer;
        uint64_t m_is_protocol_layer;
            archive(::cereal::make_nvp("next_stage_size_width", m_next_stage_size_width));
            archive(::cereal::make_nvp("next_stage_size_offset", m_next_stage_size_offset));
            archive(::cereal::make_nvp("next_stage_protocol_or_type_offset", m_next_stage_protocol_or_type_offset));
            archive(::cereal::make_nvp("use_additional_size", m_use_additional_size));
            archive(::cereal::make_nvp("base_size", m_base_size));
            archive(::cereal::make_nvp("is_next_protocol_layer", m_is_next_protocol_layer));
            archive(::cereal::make_nvp("is_protocol_layer", m_is_protocol_layer));
            archive(::cereal::make_nvp("next_fi_macro_id", m.next_fi_macro_id));
            archive(::cereal::make_nvp("next_header_format", m.next_header_format));
            archive(::cereal::make_nvp("header_format", m.header_format));
        m.next_stage_size_width = m_next_stage_size_width;
        m.next_stage_size_offset = m_next_stage_size_offset;
        m.next_stage_protocol_or_type_offset = m_next_stage_protocol_or_type_offset;
        m.use_additional_size = m_use_additional_size;
        m.base_size = m_base_size;
        m.is_next_protocol_layer = m_is_next_protocol_layer;
        m.is_protocol_layer = m_is_protocol_layer;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_nw_1_table_light_fi_nw_table_hit_payload_t& m)
{
    serializer_class<npl_light_fi_nw_1_table_light_fi_nw_table_hit_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_nw_1_table_light_fi_nw_table_hit_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_nw_1_table_light_fi_nw_table_hit_payload_t& m)
{
    serializer_class<npl_light_fi_nw_1_table_light_fi_nw_table_hit_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_nw_1_table_light_fi_nw_table_hit_payload_t&);



template<>
class serializer_class<npl_light_fi_nw_1_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_nw_1_table_key_t& m) {
        uint64_t m_next_protocol_field = m.next_protocol_field;
            archive(::cereal::make_nvp("current_header_type", m.current_header_type));
            archive(::cereal::make_nvp("next_protocol_field", m_next_protocol_field));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_nw_1_table_key_t& m) {
        uint64_t m_next_protocol_field;
            archive(::cereal::make_nvp("current_header_type", m.current_header_type));
            archive(::cereal::make_nvp("next_protocol_field", m_next_protocol_field));
        m.next_protocol_field = m_next_protocol_field;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_nw_1_table_key_t& m)
{
    serializer_class<npl_light_fi_nw_1_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_nw_1_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_nw_1_table_key_t& m)
{
    serializer_class<npl_light_fi_nw_1_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_nw_1_table_key_t&);



template<>
class serializer_class<npl_light_fi_nw_1_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_nw_1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_nw_1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_nw_1_table_value_t& m)
{
    serializer_class<npl_light_fi_nw_1_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_nw_1_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_nw_1_table_value_t& m)
{
    serializer_class<npl_light_fi_nw_1_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_nw_1_table_value_t&);



template<>
class serializer_class<npl_light_fi_nw_1_table_value_t::npl_light_fi_nw_1_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_nw_1_table_value_t::npl_light_fi_nw_1_table_payloads_t& m) {
            archive(::cereal::make_nvp("light_fi_nw_table_hit", m.light_fi_nw_table_hit));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_nw_1_table_value_t::npl_light_fi_nw_1_table_payloads_t& m) {
            archive(::cereal::make_nvp("light_fi_nw_table_hit", m.light_fi_nw_table_hit));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_nw_1_table_value_t::npl_light_fi_nw_1_table_payloads_t& m)
{
    serializer_class<npl_light_fi_nw_1_table_value_t::npl_light_fi_nw_1_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_nw_1_table_value_t::npl_light_fi_nw_1_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_nw_1_table_value_t::npl_light_fi_nw_1_table_payloads_t& m)
{
    serializer_class<npl_light_fi_nw_1_table_value_t::npl_light_fi_nw_1_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_nw_1_table_value_t::npl_light_fi_nw_1_table_payloads_t&);



template<>
class serializer_class<npl_light_fi_nw_2_table_light_fi_nw_table_hit_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_nw_2_table_light_fi_nw_table_hit_payload_t& m) {
        uint64_t m_next_stage_size_width = m.next_stage_size_width;
        uint64_t m_next_stage_size_offset = m.next_stage_size_offset;
        uint64_t m_next_stage_protocol_or_type_offset = m.next_stage_protocol_or_type_offset;
        uint64_t m_use_additional_size = m.use_additional_size;
        uint64_t m_base_size = m.base_size;
        uint64_t m_is_next_protocol_layer = m.is_next_protocol_layer;
        uint64_t m_is_protocol_layer = m.is_protocol_layer;
            archive(::cereal::make_nvp("next_stage_size_width", m_next_stage_size_width));
            archive(::cereal::make_nvp("next_stage_size_offset", m_next_stage_size_offset));
            archive(::cereal::make_nvp("next_stage_protocol_or_type_offset", m_next_stage_protocol_or_type_offset));
            archive(::cereal::make_nvp("use_additional_size", m_use_additional_size));
            archive(::cereal::make_nvp("base_size", m_base_size));
            archive(::cereal::make_nvp("is_next_protocol_layer", m_is_next_protocol_layer));
            archive(::cereal::make_nvp("is_protocol_layer", m_is_protocol_layer));
            archive(::cereal::make_nvp("next_fi_macro_id", m.next_fi_macro_id));
            archive(::cereal::make_nvp("next_header_format", m.next_header_format));
            archive(::cereal::make_nvp("header_format", m.header_format));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_nw_2_table_light_fi_nw_table_hit_payload_t& m) {
        uint64_t m_next_stage_size_width;
        uint64_t m_next_stage_size_offset;
        uint64_t m_next_stage_protocol_or_type_offset;
        uint64_t m_use_additional_size;
        uint64_t m_base_size;
        uint64_t m_is_next_protocol_layer;
        uint64_t m_is_protocol_layer;
            archive(::cereal::make_nvp("next_stage_size_width", m_next_stage_size_width));
            archive(::cereal::make_nvp("next_stage_size_offset", m_next_stage_size_offset));
            archive(::cereal::make_nvp("next_stage_protocol_or_type_offset", m_next_stage_protocol_or_type_offset));
            archive(::cereal::make_nvp("use_additional_size", m_use_additional_size));
            archive(::cereal::make_nvp("base_size", m_base_size));
            archive(::cereal::make_nvp("is_next_protocol_layer", m_is_next_protocol_layer));
            archive(::cereal::make_nvp("is_protocol_layer", m_is_protocol_layer));
            archive(::cereal::make_nvp("next_fi_macro_id", m.next_fi_macro_id));
            archive(::cereal::make_nvp("next_header_format", m.next_header_format));
            archive(::cereal::make_nvp("header_format", m.header_format));
        m.next_stage_size_width = m_next_stage_size_width;
        m.next_stage_size_offset = m_next_stage_size_offset;
        m.next_stage_protocol_or_type_offset = m_next_stage_protocol_or_type_offset;
        m.use_additional_size = m_use_additional_size;
        m.base_size = m_base_size;
        m.is_next_protocol_layer = m_is_next_protocol_layer;
        m.is_protocol_layer = m_is_protocol_layer;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_nw_2_table_light_fi_nw_table_hit_payload_t& m)
{
    serializer_class<npl_light_fi_nw_2_table_light_fi_nw_table_hit_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_nw_2_table_light_fi_nw_table_hit_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_nw_2_table_light_fi_nw_table_hit_payload_t& m)
{
    serializer_class<npl_light_fi_nw_2_table_light_fi_nw_table_hit_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_nw_2_table_light_fi_nw_table_hit_payload_t&);



template<>
class serializer_class<npl_light_fi_nw_2_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_nw_2_table_key_t& m) {
        uint64_t m_next_protocol_field = m.next_protocol_field;
            archive(::cereal::make_nvp("current_header_type", m.current_header_type));
            archive(::cereal::make_nvp("next_protocol_field", m_next_protocol_field));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_nw_2_table_key_t& m) {
        uint64_t m_next_protocol_field;
            archive(::cereal::make_nvp("current_header_type", m.current_header_type));
            archive(::cereal::make_nvp("next_protocol_field", m_next_protocol_field));
        m.next_protocol_field = m_next_protocol_field;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_nw_2_table_key_t& m)
{
    serializer_class<npl_light_fi_nw_2_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_nw_2_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_nw_2_table_key_t& m)
{
    serializer_class<npl_light_fi_nw_2_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_nw_2_table_key_t&);



template<>
class serializer_class<npl_light_fi_nw_2_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_nw_2_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_nw_2_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_nw_2_table_value_t& m)
{
    serializer_class<npl_light_fi_nw_2_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_nw_2_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_nw_2_table_value_t& m)
{
    serializer_class<npl_light_fi_nw_2_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_nw_2_table_value_t&);



template<>
class serializer_class<npl_light_fi_nw_2_table_value_t::npl_light_fi_nw_2_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_nw_2_table_value_t::npl_light_fi_nw_2_table_payloads_t& m) {
            archive(::cereal::make_nvp("light_fi_nw_table_hit", m.light_fi_nw_table_hit));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_nw_2_table_value_t::npl_light_fi_nw_2_table_payloads_t& m) {
            archive(::cereal::make_nvp("light_fi_nw_table_hit", m.light_fi_nw_table_hit));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_nw_2_table_value_t::npl_light_fi_nw_2_table_payloads_t& m)
{
    serializer_class<npl_light_fi_nw_2_table_value_t::npl_light_fi_nw_2_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_nw_2_table_value_t::npl_light_fi_nw_2_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_nw_2_table_value_t::npl_light_fi_nw_2_table_payloads_t& m)
{
    serializer_class<npl_light_fi_nw_2_table_value_t::npl_light_fi_nw_2_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_nw_2_table_value_t::npl_light_fi_nw_2_table_payloads_t&);



template<>
class serializer_class<npl_light_fi_nw_3_table_light_fi_nw_table_hit_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_nw_3_table_light_fi_nw_table_hit_payload_t& m) {
        uint64_t m_next_stage_size_width = m.next_stage_size_width;
        uint64_t m_next_stage_size_offset = m.next_stage_size_offset;
        uint64_t m_next_stage_protocol_or_type_offset = m.next_stage_protocol_or_type_offset;
        uint64_t m_use_additional_size = m.use_additional_size;
        uint64_t m_base_size = m.base_size;
        uint64_t m_is_next_protocol_layer = m.is_next_protocol_layer;
        uint64_t m_is_protocol_layer = m.is_protocol_layer;
            archive(::cereal::make_nvp("next_stage_size_width", m_next_stage_size_width));
            archive(::cereal::make_nvp("next_stage_size_offset", m_next_stage_size_offset));
            archive(::cereal::make_nvp("next_stage_protocol_or_type_offset", m_next_stage_protocol_or_type_offset));
            archive(::cereal::make_nvp("use_additional_size", m_use_additional_size));
            archive(::cereal::make_nvp("base_size", m_base_size));
            archive(::cereal::make_nvp("is_next_protocol_layer", m_is_next_protocol_layer));
            archive(::cereal::make_nvp("is_protocol_layer", m_is_protocol_layer));
            archive(::cereal::make_nvp("next_fi_macro_id", m.next_fi_macro_id));
            archive(::cereal::make_nvp("next_header_format", m.next_header_format));
            archive(::cereal::make_nvp("header_format", m.header_format));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_nw_3_table_light_fi_nw_table_hit_payload_t& m) {
        uint64_t m_next_stage_size_width;
        uint64_t m_next_stage_size_offset;
        uint64_t m_next_stage_protocol_or_type_offset;
        uint64_t m_use_additional_size;
        uint64_t m_base_size;
        uint64_t m_is_next_protocol_layer;
        uint64_t m_is_protocol_layer;
            archive(::cereal::make_nvp("next_stage_size_width", m_next_stage_size_width));
            archive(::cereal::make_nvp("next_stage_size_offset", m_next_stage_size_offset));
            archive(::cereal::make_nvp("next_stage_protocol_or_type_offset", m_next_stage_protocol_or_type_offset));
            archive(::cereal::make_nvp("use_additional_size", m_use_additional_size));
            archive(::cereal::make_nvp("base_size", m_base_size));
            archive(::cereal::make_nvp("is_next_protocol_layer", m_is_next_protocol_layer));
            archive(::cereal::make_nvp("is_protocol_layer", m_is_protocol_layer));
            archive(::cereal::make_nvp("next_fi_macro_id", m.next_fi_macro_id));
            archive(::cereal::make_nvp("next_header_format", m.next_header_format));
            archive(::cereal::make_nvp("header_format", m.header_format));
        m.next_stage_size_width = m_next_stage_size_width;
        m.next_stage_size_offset = m_next_stage_size_offset;
        m.next_stage_protocol_or_type_offset = m_next_stage_protocol_or_type_offset;
        m.use_additional_size = m_use_additional_size;
        m.base_size = m_base_size;
        m.is_next_protocol_layer = m_is_next_protocol_layer;
        m.is_protocol_layer = m_is_protocol_layer;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_nw_3_table_light_fi_nw_table_hit_payload_t& m)
{
    serializer_class<npl_light_fi_nw_3_table_light_fi_nw_table_hit_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_nw_3_table_light_fi_nw_table_hit_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_nw_3_table_light_fi_nw_table_hit_payload_t& m)
{
    serializer_class<npl_light_fi_nw_3_table_light_fi_nw_table_hit_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_nw_3_table_light_fi_nw_table_hit_payload_t&);



template<>
class serializer_class<npl_light_fi_nw_3_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_nw_3_table_key_t& m) {
        uint64_t m_next_protocol_field = m.next_protocol_field;
            archive(::cereal::make_nvp("current_header_type", m.current_header_type));
            archive(::cereal::make_nvp("next_protocol_field", m_next_protocol_field));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_nw_3_table_key_t& m) {
        uint64_t m_next_protocol_field;
            archive(::cereal::make_nvp("current_header_type", m.current_header_type));
            archive(::cereal::make_nvp("next_protocol_field", m_next_protocol_field));
        m.next_protocol_field = m_next_protocol_field;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_nw_3_table_key_t& m)
{
    serializer_class<npl_light_fi_nw_3_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_nw_3_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_nw_3_table_key_t& m)
{
    serializer_class<npl_light_fi_nw_3_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_nw_3_table_key_t&);



template<>
class serializer_class<npl_light_fi_nw_3_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_nw_3_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_nw_3_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_nw_3_table_value_t& m)
{
    serializer_class<npl_light_fi_nw_3_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_nw_3_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_nw_3_table_value_t& m)
{
    serializer_class<npl_light_fi_nw_3_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_nw_3_table_value_t&);



template<>
class serializer_class<npl_light_fi_nw_3_table_value_t::npl_light_fi_nw_3_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_nw_3_table_value_t::npl_light_fi_nw_3_table_payloads_t& m) {
            archive(::cereal::make_nvp("light_fi_nw_table_hit", m.light_fi_nw_table_hit));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_nw_3_table_value_t::npl_light_fi_nw_3_table_payloads_t& m) {
            archive(::cereal::make_nvp("light_fi_nw_table_hit", m.light_fi_nw_table_hit));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_nw_3_table_value_t::npl_light_fi_nw_3_table_payloads_t& m)
{
    serializer_class<npl_light_fi_nw_3_table_value_t::npl_light_fi_nw_3_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_nw_3_table_value_t::npl_light_fi_nw_3_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_nw_3_table_value_t::npl_light_fi_nw_3_table_payloads_t& m)
{
    serializer_class<npl_light_fi_nw_3_table_value_t::npl_light_fi_nw_3_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_nw_3_table_value_t::npl_light_fi_nw_3_table_payloads_t&);



template<>
class serializer_class<npl_light_fi_stages_cfg_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_stages_cfg_table_key_t& m) {
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_stages_cfg_table_key_t& m) {
        uint64_t m_macro_id;
            archive(::cereal::make_nvp("macro_id", m_macro_id));
        m.macro_id = m_macro_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_stages_cfg_table_key_t& m)
{
    serializer_class<npl_light_fi_stages_cfg_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_stages_cfg_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_stages_cfg_table_key_t& m)
{
    serializer_class<npl_light_fi_stages_cfg_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_stages_cfg_table_key_t&);



template<>
class serializer_class<npl_light_fi_stages_cfg_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_stages_cfg_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_stages_cfg_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_stages_cfg_table_value_t& m)
{
    serializer_class<npl_light_fi_stages_cfg_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_stages_cfg_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_stages_cfg_table_value_t& m)
{
    serializer_class<npl_light_fi_stages_cfg_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_stages_cfg_table_value_t&);



template<>
class serializer_class<npl_light_fi_stages_cfg_table_value_t::npl_light_fi_stages_cfg_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_stages_cfg_table_value_t::npl_light_fi_stages_cfg_table_payloads_t& m) {
            archive(::cereal::make_nvp("light_fi_stage_cfg", m.light_fi_stage_cfg));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_stages_cfg_table_value_t::npl_light_fi_stages_cfg_table_payloads_t& m) {
            archive(::cereal::make_nvp("light_fi_stage_cfg", m.light_fi_stage_cfg));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_stages_cfg_table_value_t::npl_light_fi_stages_cfg_table_payloads_t& m)
{
    serializer_class<npl_light_fi_stages_cfg_table_value_t::npl_light_fi_stages_cfg_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_stages_cfg_table_value_t::npl_light_fi_stages_cfg_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_stages_cfg_table_value_t::npl_light_fi_stages_cfg_table_payloads_t& m)
{
    serializer_class<npl_light_fi_stages_cfg_table_value_t::npl_light_fi_stages_cfg_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_stages_cfg_table_value_t::npl_light_fi_stages_cfg_table_payloads_t&);



template<>
class serializer_class<npl_light_fi_tm_table_light_fi_leaba_table_hit_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_tm_table_light_fi_leaba_table_hit_payload_t& m) {
        uint64_t m_use_additional_size = m.use_additional_size;
        uint64_t m_base_size = m.base_size;
        uint64_t m_is_next_protocol_layer = m.is_next_protocol_layer;
        uint64_t m_is_protocol_layer = m.is_protocol_layer;
        uint64_t m_npe_macro_id = m.npe_macro_id;
        uint64_t m_npe_macro_id_valid = m.npe_macro_id_valid;
            archive(::cereal::make_nvp("use_additional_size", m_use_additional_size));
            archive(::cereal::make_nvp("base_size", m_base_size));
            archive(::cereal::make_nvp("is_next_protocol_layer", m_is_next_protocol_layer));
            archive(::cereal::make_nvp("is_protocol_layer", m_is_protocol_layer));
            archive(::cereal::make_nvp("next_fi_macro_id", m.next_fi_macro_id));
            archive(::cereal::make_nvp("npe_macro_id", m_npe_macro_id));
            archive(::cereal::make_nvp("npe_macro_id_valid", m_npe_macro_id_valid));
            archive(::cereal::make_nvp("next_header_format", m.next_header_format));
            archive(::cereal::make_nvp("header_format", m.header_format));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_tm_table_light_fi_leaba_table_hit_payload_t& m) {
        uint64_t m_use_additional_size;
        uint64_t m_base_size;
        uint64_t m_is_next_protocol_layer;
        uint64_t m_is_protocol_layer;
        uint64_t m_npe_macro_id;
        uint64_t m_npe_macro_id_valid;
            archive(::cereal::make_nvp("use_additional_size", m_use_additional_size));
            archive(::cereal::make_nvp("base_size", m_base_size));
            archive(::cereal::make_nvp("is_next_protocol_layer", m_is_next_protocol_layer));
            archive(::cereal::make_nvp("is_protocol_layer", m_is_protocol_layer));
            archive(::cereal::make_nvp("next_fi_macro_id", m.next_fi_macro_id));
            archive(::cereal::make_nvp("npe_macro_id", m_npe_macro_id));
            archive(::cereal::make_nvp("npe_macro_id_valid", m_npe_macro_id_valid));
            archive(::cereal::make_nvp("next_header_format", m.next_header_format));
            archive(::cereal::make_nvp("header_format", m.header_format));
        m.use_additional_size = m_use_additional_size;
        m.base_size = m_base_size;
        m.is_next_protocol_layer = m_is_next_protocol_layer;
        m.is_protocol_layer = m_is_protocol_layer;
        m.npe_macro_id = m_npe_macro_id;
        m.npe_macro_id_valid = m_npe_macro_id_valid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_tm_table_light_fi_leaba_table_hit_payload_t& m)
{
    serializer_class<npl_light_fi_tm_table_light_fi_leaba_table_hit_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_tm_table_light_fi_leaba_table_hit_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_tm_table_light_fi_leaba_table_hit_payload_t& m)
{
    serializer_class<npl_light_fi_tm_table_light_fi_leaba_table_hit_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_tm_table_light_fi_leaba_table_hit_payload_t&);



template<>
class serializer_class<npl_light_fi_tm_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_tm_table_key_t& m) {
        uint64_t m_tm_header_type = m.tm_header_type;
            archive(::cereal::make_nvp("tm_header_type", m_tm_header_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_tm_table_key_t& m) {
        uint64_t m_tm_header_type;
            archive(::cereal::make_nvp("tm_header_type", m_tm_header_type));
        m.tm_header_type = m_tm_header_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_tm_table_key_t& m)
{
    serializer_class<npl_light_fi_tm_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_tm_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_tm_table_key_t& m)
{
    serializer_class<npl_light_fi_tm_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_tm_table_key_t&);



template<>
class serializer_class<npl_light_fi_tm_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_tm_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_tm_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_tm_table_value_t& m)
{
    serializer_class<npl_light_fi_tm_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_tm_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_tm_table_value_t& m)
{
    serializer_class<npl_light_fi_tm_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_tm_table_value_t&);



template<>
class serializer_class<npl_light_fi_tm_table_value_t::npl_light_fi_tm_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_tm_table_value_t::npl_light_fi_tm_table_payloads_t& m) {
            archive(::cereal::make_nvp("light_fi_leaba_table_hit", m.light_fi_leaba_table_hit));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_tm_table_value_t::npl_light_fi_tm_table_payloads_t& m) {
            archive(::cereal::make_nvp("light_fi_leaba_table_hit", m.light_fi_leaba_table_hit));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_tm_table_value_t::npl_light_fi_tm_table_payloads_t& m)
{
    serializer_class<npl_light_fi_tm_table_value_t::npl_light_fi_tm_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_tm_table_value_t::npl_light_fi_tm_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_tm_table_value_t::npl_light_fi_tm_table_payloads_t& m)
{
    serializer_class<npl_light_fi_tm_table_value_t::npl_light_fi_tm_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_tm_table_value_t::npl_light_fi_tm_table_payloads_t&);



template<>
class serializer_class<npl_link_relay_attributes_table_relay_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_link_relay_attributes_table_relay_payload_t& m) {
            archive(::cereal::make_nvp("relay_table_payload", m.relay_table_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_link_relay_attributes_table_relay_payload_t& m) {
            archive(::cereal::make_nvp("relay_table_payload", m.relay_table_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_link_relay_attributes_table_relay_payload_t& m)
{
    serializer_class<npl_link_relay_attributes_table_relay_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_link_relay_attributes_table_relay_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_link_relay_attributes_table_relay_payload_t& m)
{
    serializer_class<npl_link_relay_attributes_table_relay_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_link_relay_attributes_table_relay_payload_t&);



template<>
class serializer_class<npl_link_relay_attributes_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_link_relay_attributes_table_key_t& m) {
        uint64_t m_service_relay_attributes_table_key_11_0_ = m.service_relay_attributes_table_key_11_0_;
            archive(::cereal::make_nvp("service_relay_attributes_table_key_11_0_", m_service_relay_attributes_table_key_11_0_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_link_relay_attributes_table_key_t& m) {
        uint64_t m_service_relay_attributes_table_key_11_0_;
            archive(::cereal::make_nvp("service_relay_attributes_table_key_11_0_", m_service_relay_attributes_table_key_11_0_));
        m.service_relay_attributes_table_key_11_0_ = m_service_relay_attributes_table_key_11_0_;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_link_relay_attributes_table_key_t& m)
{
    serializer_class<npl_link_relay_attributes_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_link_relay_attributes_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_link_relay_attributes_table_key_t& m)
{
    serializer_class<npl_link_relay_attributes_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_link_relay_attributes_table_key_t&);



template<>
class serializer_class<npl_link_relay_attributes_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_link_relay_attributes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_link_relay_attributes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_link_relay_attributes_table_value_t& m)
{
    serializer_class<npl_link_relay_attributes_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_link_relay_attributes_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_link_relay_attributes_table_value_t& m)
{
    serializer_class<npl_link_relay_attributes_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_link_relay_attributes_table_value_t&);



template<>
class serializer_class<npl_link_relay_attributes_table_value_t::npl_link_relay_attributes_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_link_relay_attributes_table_value_t::npl_link_relay_attributes_table_payloads_t& m) {
            archive(::cereal::make_nvp("relay", m.relay));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_link_relay_attributes_table_value_t::npl_link_relay_attributes_table_payloads_t& m) {
            archive(::cereal::make_nvp("relay", m.relay));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_link_relay_attributes_table_value_t::npl_link_relay_attributes_table_payloads_t& m)
{
    serializer_class<npl_link_relay_attributes_table_value_t::npl_link_relay_attributes_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_link_relay_attributes_table_value_t::npl_link_relay_attributes_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_link_relay_attributes_table_value_t::npl_link_relay_attributes_table_payloads_t& m)
{
    serializer_class<npl_link_relay_attributes_table_value_t::npl_link_relay_attributes_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_link_relay_attributes_table_value_t::npl_link_relay_attributes_table_payloads_t&);



template<>
class serializer_class<npl_link_relay_id_static_table_relay_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_link_relay_id_static_table_relay_payload_t& m) {
        uint64_t m_relay_id_or_l3_lp_add_attr = m.relay_id_or_l3_lp_add_attr;
            archive(::cereal::make_nvp("relay_id_or_l3_lp_add_attr", m_relay_id_or_l3_lp_add_attr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_link_relay_id_static_table_relay_payload_t& m) {
        uint64_t m_relay_id_or_l3_lp_add_attr;
            archive(::cereal::make_nvp("relay_id_or_l3_lp_add_attr", m_relay_id_or_l3_lp_add_attr));
        m.relay_id_or_l3_lp_add_attr = m_relay_id_or_l3_lp_add_attr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_link_relay_id_static_table_relay_payload_t& m)
{
    serializer_class<npl_link_relay_id_static_table_relay_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_link_relay_id_static_table_relay_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_link_relay_id_static_table_relay_payload_t& m)
{
    serializer_class<npl_link_relay_id_static_table_relay_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_link_relay_id_static_table_relay_payload_t&);



template<>
class serializer_class<npl_link_relay_id_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_link_relay_id_static_table_key_t& m) {
        uint64_t m_service_relay_attributes_table_key_11_0_ = m.service_relay_attributes_table_key_11_0_;
            archive(::cereal::make_nvp("service_relay_attributes_table_key_11_0_", m_service_relay_attributes_table_key_11_0_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_link_relay_id_static_table_key_t& m) {
        uint64_t m_service_relay_attributes_table_key_11_0_;
            archive(::cereal::make_nvp("service_relay_attributes_table_key_11_0_", m_service_relay_attributes_table_key_11_0_));
        m.service_relay_attributes_table_key_11_0_ = m_service_relay_attributes_table_key_11_0_;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_link_relay_id_static_table_key_t& m)
{
    serializer_class<npl_link_relay_id_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_link_relay_id_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_link_relay_id_static_table_key_t& m)
{
    serializer_class<npl_link_relay_id_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_link_relay_id_static_table_key_t&);



template<>
class serializer_class<npl_link_relay_id_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_link_relay_id_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_link_relay_id_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_link_relay_id_static_table_value_t& m)
{
    serializer_class<npl_link_relay_id_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_link_relay_id_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_link_relay_id_static_table_value_t& m)
{
    serializer_class<npl_link_relay_id_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_link_relay_id_static_table_value_t&);



template<>
class serializer_class<npl_link_relay_id_static_table_value_t::npl_link_relay_id_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_link_relay_id_static_table_value_t::npl_link_relay_id_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("relay", m.relay));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_link_relay_id_static_table_value_t::npl_link_relay_id_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("relay", m.relay));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_link_relay_id_static_table_value_t::npl_link_relay_id_static_table_payloads_t& m)
{
    serializer_class<npl_link_relay_id_static_table_value_t::npl_link_relay_id_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_link_relay_id_static_table_value_t::npl_link_relay_id_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_link_relay_id_static_table_value_t::npl_link_relay_id_static_table_payloads_t& m)
{
    serializer_class<npl_link_relay_id_static_table_value_t::npl_link_relay_id_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_link_relay_id_static_table_value_t::npl_link_relay_id_static_table_payloads_t&);



template<>
class serializer_class<npl_link_up_vector_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_link_up_vector_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_link_up_vector_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_link_up_vector_key_t& m)
{
    serializer_class<npl_link_up_vector_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_link_up_vector_key_t&);

template <class Archive>
void
load(Archive& archive, npl_link_up_vector_key_t& m)
{
    serializer_class<npl_link_up_vector_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_link_up_vector_key_t&);



template<>
class serializer_class<npl_link_up_vector_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_link_up_vector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_link_up_vector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_link_up_vector_value_t& m)
{
    serializer_class<npl_link_up_vector_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_link_up_vector_value_t&);

template <class Archive>
void
load(Archive& archive, npl_link_up_vector_value_t& m)
{
    serializer_class<npl_link_up_vector_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_link_up_vector_value_t&);



template<>
class serializer_class<npl_link_up_vector_value_t::npl_link_up_vector_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_link_up_vector_value_t::npl_link_up_vector_payloads_t& m) {
            archive(::cereal::make_nvp("link_up_vector_result", m.link_up_vector_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_link_up_vector_value_t::npl_link_up_vector_payloads_t& m) {
            archive(::cereal::make_nvp("link_up_vector_result", m.link_up_vector_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_link_up_vector_value_t::npl_link_up_vector_payloads_t& m)
{
    serializer_class<npl_link_up_vector_value_t::npl_link_up_vector_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_link_up_vector_value_t::npl_link_up_vector_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_link_up_vector_value_t::npl_link_up_vector_payloads_t& m)
{
    serializer_class<npl_link_up_vector_value_t::npl_link_up_vector_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_link_up_vector_value_t::npl_link_up_vector_payloads_t&);



template<>
class serializer_class<npl_local_mc_fwd_next_macro_static_table_set_macro_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_local_mc_fwd_next_macro_static_table_set_macro_payload_t& m) {
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_local_mc_fwd_next_macro_static_table_set_macro_payload_t& m) {
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
save(Archive& archive, const npl_local_mc_fwd_next_macro_static_table_set_macro_payload_t& m)
{
    serializer_class<npl_local_mc_fwd_next_macro_static_table_set_macro_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_local_mc_fwd_next_macro_static_table_set_macro_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_local_mc_fwd_next_macro_static_table_set_macro_payload_t& m)
{
    serializer_class<npl_local_mc_fwd_next_macro_static_table_set_macro_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_local_mc_fwd_next_macro_static_table_set_macro_payload_t&);



template<>
class serializer_class<npl_local_mc_fwd_next_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_local_mc_fwd_next_macro_static_table_key_t& m) {
        uint64_t m_current_proto_type = m.current_proto_type;
        uint64_t m_next_proto_type = m.next_proto_type;
            archive(::cereal::make_nvp("post_fwd_stage", m.post_fwd_stage));
            archive(::cereal::make_nvp("current_proto_type", m_current_proto_type));
            archive(::cereal::make_nvp("next_proto_type", m_next_proto_type));
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_local_mc_fwd_next_macro_static_table_key_t& m) {
        uint64_t m_current_proto_type;
        uint64_t m_next_proto_type;
            archive(::cereal::make_nvp("post_fwd_stage", m.post_fwd_stage));
            archive(::cereal::make_nvp("current_proto_type", m_current_proto_type));
            archive(::cereal::make_nvp("next_proto_type", m_next_proto_type));
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
        m.current_proto_type = m_current_proto_type;
        m.next_proto_type = m_next_proto_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_local_mc_fwd_next_macro_static_table_key_t& m)
{
    serializer_class<npl_local_mc_fwd_next_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_local_mc_fwd_next_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_local_mc_fwd_next_macro_static_table_key_t& m)
{
    serializer_class<npl_local_mc_fwd_next_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_local_mc_fwd_next_macro_static_table_key_t&);



template<>
class serializer_class<npl_local_mc_fwd_next_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_local_mc_fwd_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_local_mc_fwd_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_local_mc_fwd_next_macro_static_table_value_t& m)
{
    serializer_class<npl_local_mc_fwd_next_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_local_mc_fwd_next_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_local_mc_fwd_next_macro_static_table_value_t& m)
{
    serializer_class<npl_local_mc_fwd_next_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_local_mc_fwd_next_macro_static_table_value_t&);



template<>
class serializer_class<npl_local_mc_fwd_next_macro_static_table_value_t::npl_local_mc_fwd_next_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_local_mc_fwd_next_macro_static_table_value_t::npl_local_mc_fwd_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_macro", m.set_macro));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_local_mc_fwd_next_macro_static_table_value_t::npl_local_mc_fwd_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_macro", m.set_macro));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_local_mc_fwd_next_macro_static_table_value_t::npl_local_mc_fwd_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_local_mc_fwd_next_macro_static_table_value_t::npl_local_mc_fwd_next_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_local_mc_fwd_next_macro_static_table_value_t::npl_local_mc_fwd_next_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_local_mc_fwd_next_macro_static_table_value_t::npl_local_mc_fwd_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_local_mc_fwd_next_macro_static_table_value_t::npl_local_mc_fwd_next_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_local_mc_fwd_next_macro_static_table_value_t::npl_local_mc_fwd_next_macro_static_table_payloads_t&);



template<>
class serializer_class<npl_lp_over_lag_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lp_over_lag_table_key_t& m) {
        uint64_t m_destination = m.destination;
        uint64_t m_l3_dlp_msbs = m.l3_dlp_msbs;
        uint64_t m_l3_dlp_lsbs = m.l3_dlp_lsbs;
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("l3_dlp_msbs", m_l3_dlp_msbs));
            archive(::cereal::make_nvp("l3_dlp_lsbs", m_l3_dlp_lsbs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lp_over_lag_table_key_t& m) {
        uint64_t m_destination;
        uint64_t m_l3_dlp_msbs;
        uint64_t m_l3_dlp_lsbs;
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("l3_dlp_msbs", m_l3_dlp_msbs));
            archive(::cereal::make_nvp("l3_dlp_lsbs", m_l3_dlp_lsbs));
        m.destination = m_destination;
        m.l3_dlp_msbs = m_l3_dlp_msbs;
        m.l3_dlp_lsbs = m_l3_dlp_lsbs;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lp_over_lag_table_key_t& m)
{
    serializer_class<npl_lp_over_lag_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lp_over_lag_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_lp_over_lag_table_key_t& m)
{
    serializer_class<npl_lp_over_lag_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lp_over_lag_table_key_t&);



template<>
class serializer_class<npl_lp_over_lag_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lp_over_lag_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lp_over_lag_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lp_over_lag_table_value_t& m)
{
    serializer_class<npl_lp_over_lag_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lp_over_lag_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_lp_over_lag_table_value_t& m)
{
    serializer_class<npl_lp_over_lag_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lp_over_lag_table_value_t&);



template<>
class serializer_class<npl_lp_over_lag_table_value_t::npl_lp_over_lag_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lp_over_lag_table_value_t::npl_lp_over_lag_table_payloads_t& m) {
        uint64_t m_bvn_destination = m.bvn_destination;
            archive(::cereal::make_nvp("bvn_destination", m_bvn_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lp_over_lag_table_value_t::npl_lp_over_lag_table_payloads_t& m) {
        uint64_t m_bvn_destination;
            archive(::cereal::make_nvp("bvn_destination", m_bvn_destination));
        m.bvn_destination = m_bvn_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lp_over_lag_table_value_t::npl_lp_over_lag_table_payloads_t& m)
{
    serializer_class<npl_lp_over_lag_table_value_t::npl_lp_over_lag_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lp_over_lag_table_value_t::npl_lp_over_lag_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_lp_over_lag_table_value_t::npl_lp_over_lag_table_payloads_t& m)
{
    serializer_class<npl_lp_over_lag_table_value_t::npl_lp_over_lag_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lp_over_lag_table_value_t::npl_lp_over_lag_table_payloads_t&);



template<>
class serializer_class<npl_lpts_2nd_lookup_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lpts_2nd_lookup_table_key_t& m) {
        uint64_t m_lpts_second_lookup_key = m.lpts_second_lookup_key;
            archive(::cereal::make_nvp("lpts_second_lookup_key", m_lpts_second_lookup_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lpts_2nd_lookup_table_key_t& m) {
        uint64_t m_lpts_second_lookup_key;
            archive(::cereal::make_nvp("lpts_second_lookup_key", m_lpts_second_lookup_key));
        m.lpts_second_lookup_key = m_lpts_second_lookup_key;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lpts_2nd_lookup_table_key_t& m)
{
    serializer_class<npl_lpts_2nd_lookup_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lpts_2nd_lookup_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_lpts_2nd_lookup_table_key_t& m)
{
    serializer_class<npl_lpts_2nd_lookup_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lpts_2nd_lookup_table_key_t&);



template<>
class serializer_class<npl_lpts_2nd_lookup_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lpts_2nd_lookup_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lpts_2nd_lookup_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lpts_2nd_lookup_table_value_t& m)
{
    serializer_class<npl_lpts_2nd_lookup_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lpts_2nd_lookup_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_lpts_2nd_lookup_table_value_t& m)
{
    serializer_class<npl_lpts_2nd_lookup_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lpts_2nd_lookup_table_value_t&);



template<>
class serializer_class<npl_lpts_2nd_lookup_table_value_t::npl_lpts_2nd_lookup_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lpts_2nd_lookup_table_value_t::npl_lpts_2nd_lookup_table_payloads_t& m) {
            archive(::cereal::make_nvp("lpts_payload", m.lpts_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lpts_2nd_lookup_table_value_t::npl_lpts_2nd_lookup_table_payloads_t& m) {
            archive(::cereal::make_nvp("lpts_payload", m.lpts_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lpts_2nd_lookup_table_value_t::npl_lpts_2nd_lookup_table_payloads_t& m)
{
    serializer_class<npl_lpts_2nd_lookup_table_value_t::npl_lpts_2nd_lookup_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lpts_2nd_lookup_table_value_t::npl_lpts_2nd_lookup_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_lpts_2nd_lookup_table_value_t::npl_lpts_2nd_lookup_table_payloads_t& m)
{
    serializer_class<npl_lpts_2nd_lookup_table_value_t::npl_lpts_2nd_lookup_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lpts_2nd_lookup_table_value_t::npl_lpts_2nd_lookup_table_payloads_t&);



template<>
class serializer_class<npl_lpts_meter_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lpts_meter_table_key_t& m) {
        uint64_t m_meter_index_msb = m.meter_index_msb;
        uint64_t m_meter_index_lsb = m.meter_index_lsb;
            archive(::cereal::make_nvp("meter_index_msb", m_meter_index_msb));
            archive(::cereal::make_nvp("meter_index_lsb", m_meter_index_lsb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lpts_meter_table_key_t& m) {
        uint64_t m_meter_index_msb;
        uint64_t m_meter_index_lsb;
            archive(::cereal::make_nvp("meter_index_msb", m_meter_index_msb));
            archive(::cereal::make_nvp("meter_index_lsb", m_meter_index_lsb));
        m.meter_index_msb = m_meter_index_msb;
        m.meter_index_lsb = m_meter_index_lsb;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lpts_meter_table_key_t& m)
{
    serializer_class<npl_lpts_meter_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lpts_meter_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_lpts_meter_table_key_t& m)
{
    serializer_class<npl_lpts_meter_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lpts_meter_table_key_t&);



template<>
class serializer_class<npl_lpts_meter_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lpts_meter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lpts_meter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lpts_meter_table_value_t& m)
{
    serializer_class<npl_lpts_meter_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lpts_meter_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_lpts_meter_table_value_t& m)
{
    serializer_class<npl_lpts_meter_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lpts_meter_table_value_t&);



template<>
class serializer_class<npl_lpts_meter_table_value_t::npl_lpts_meter_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lpts_meter_table_value_t::npl_lpts_meter_table_payloads_t& m) {
            archive(::cereal::make_nvp("counter_ptr", m.counter_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lpts_meter_table_value_t::npl_lpts_meter_table_payloads_t& m) {
            archive(::cereal::make_nvp("counter_ptr", m.counter_ptr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lpts_meter_table_value_t::npl_lpts_meter_table_payloads_t& m)
{
    serializer_class<npl_lpts_meter_table_value_t::npl_lpts_meter_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lpts_meter_table_value_t::npl_lpts_meter_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_lpts_meter_table_value_t::npl_lpts_meter_table_payloads_t& m)
{
    serializer_class<npl_lpts_meter_table_value_t::npl_lpts_meter_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lpts_meter_table_value_t::npl_lpts_meter_table_payloads_t&);



template<>
class serializer_class<npl_lpts_og_application_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lpts_og_application_table_key_t& m) {
        uint64_t m_ip_version = m.ip_version;
        uint64_t m_ipv4_l4_protocol = m.ipv4_l4_protocol;
        uint64_t m_ipv6_l4_protocol = m.ipv6_l4_protocol;
        uint64_t m_fragmented = m.fragmented;
            archive(::cereal::make_nvp("ip_version", m_ip_version));
            archive(::cereal::make_nvp("ipv4_l4_protocol", m_ipv4_l4_protocol));
            archive(::cereal::make_nvp("ipv6_l4_protocol", m_ipv6_l4_protocol));
            archive(::cereal::make_nvp("l4_ports", m.l4_ports));
            archive(::cereal::make_nvp("fragmented", m_fragmented));
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lpts_og_application_table_key_t& m) {
        uint64_t m_ip_version;
        uint64_t m_ipv4_l4_protocol;
        uint64_t m_ipv6_l4_protocol;
        uint64_t m_fragmented;
            archive(::cereal::make_nvp("ip_version", m_ip_version));
            archive(::cereal::make_nvp("ipv4_l4_protocol", m_ipv4_l4_protocol));
            archive(::cereal::make_nvp("ipv6_l4_protocol", m_ipv6_l4_protocol));
            archive(::cereal::make_nvp("l4_ports", m.l4_ports));
            archive(::cereal::make_nvp("fragmented", m_fragmented));
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
        m.ip_version = m_ip_version;
        m.ipv4_l4_protocol = m_ipv4_l4_protocol;
        m.ipv6_l4_protocol = m_ipv6_l4_protocol;
        m.fragmented = m_fragmented;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lpts_og_application_table_key_t& m)
{
    serializer_class<npl_lpts_og_application_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lpts_og_application_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_lpts_og_application_table_key_t& m)
{
    serializer_class<npl_lpts_og_application_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lpts_og_application_table_key_t&);



template<>
class serializer_class<npl_lpts_og_application_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lpts_og_application_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lpts_og_application_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lpts_og_application_table_value_t& m)
{
    serializer_class<npl_lpts_og_application_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lpts_og_application_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_lpts_og_application_table_value_t& m)
{
    serializer_class<npl_lpts_og_application_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lpts_og_application_table_value_t&);



template<>
class serializer_class<npl_lpts_og_application_table_value_t::npl_lpts_og_application_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lpts_og_application_table_value_t::npl_lpts_og_application_table_payloads_t& m) {
            archive(::cereal::make_nvp("og_app_config", m.og_app_config));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lpts_og_application_table_value_t::npl_lpts_og_application_table_payloads_t& m) {
            archive(::cereal::make_nvp("og_app_config", m.og_app_config));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lpts_og_application_table_value_t::npl_lpts_og_application_table_payloads_t& m)
{
    serializer_class<npl_lpts_og_application_table_value_t::npl_lpts_og_application_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lpts_og_application_table_value_t::npl_lpts_og_application_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_lpts_og_application_table_value_t::npl_lpts_og_application_table_payloads_t& m)
{
    serializer_class<npl_lpts_og_application_table_value_t::npl_lpts_og_application_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lpts_og_application_table_value_t::npl_lpts_og_application_table_payloads_t&);



template<>
class serializer_class<npl_lr_filter_write_ptr_reg_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lr_filter_write_ptr_reg_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lr_filter_write_ptr_reg_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lr_filter_write_ptr_reg_key_t& m)
{
    serializer_class<npl_lr_filter_write_ptr_reg_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lr_filter_write_ptr_reg_key_t&);

template <class Archive>
void
load(Archive& archive, npl_lr_filter_write_ptr_reg_key_t& m)
{
    serializer_class<npl_lr_filter_write_ptr_reg_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lr_filter_write_ptr_reg_key_t&);



template<>
class serializer_class<npl_lr_filter_write_ptr_reg_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lr_filter_write_ptr_reg_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lr_filter_write_ptr_reg_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lr_filter_write_ptr_reg_value_t& m)
{
    serializer_class<npl_lr_filter_write_ptr_reg_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lr_filter_write_ptr_reg_value_t&);

template <class Archive>
void
load(Archive& archive, npl_lr_filter_write_ptr_reg_value_t& m)
{
    serializer_class<npl_lr_filter_write_ptr_reg_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lr_filter_write_ptr_reg_value_t&);



template<>
class serializer_class<npl_lr_filter_write_ptr_reg_value_t::npl_lr_filter_write_ptr_reg_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lr_filter_write_ptr_reg_value_t::npl_lr_filter_write_ptr_reg_payloads_t& m) {
            archive(::cereal::make_nvp("learn_record_filter_vars_write_ptr", m.learn_record_filter_vars_write_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lr_filter_write_ptr_reg_value_t::npl_lr_filter_write_ptr_reg_payloads_t& m) {
            archive(::cereal::make_nvp("learn_record_filter_vars_write_ptr", m.learn_record_filter_vars_write_ptr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lr_filter_write_ptr_reg_value_t::npl_lr_filter_write_ptr_reg_payloads_t& m)
{
    serializer_class<npl_lr_filter_write_ptr_reg_value_t::npl_lr_filter_write_ptr_reg_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lr_filter_write_ptr_reg_value_t::npl_lr_filter_write_ptr_reg_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_lr_filter_write_ptr_reg_value_t::npl_lr_filter_write_ptr_reg_payloads_t& m)
{
    serializer_class<npl_lr_filter_write_ptr_reg_value_t::npl_lr_filter_write_ptr_reg_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lr_filter_write_ptr_reg_value_t::npl_lr_filter_write_ptr_reg_payloads_t&);



template<>
class serializer_class<npl_lr_write_ptr_reg_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lr_write_ptr_reg_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lr_write_ptr_reg_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lr_write_ptr_reg_key_t& m)
{
    serializer_class<npl_lr_write_ptr_reg_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lr_write_ptr_reg_key_t&);

template <class Archive>
void
load(Archive& archive, npl_lr_write_ptr_reg_key_t& m)
{
    serializer_class<npl_lr_write_ptr_reg_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lr_write_ptr_reg_key_t&);



template<>
class serializer_class<npl_lr_write_ptr_reg_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lr_write_ptr_reg_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lr_write_ptr_reg_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lr_write_ptr_reg_value_t& m)
{
    serializer_class<npl_lr_write_ptr_reg_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lr_write_ptr_reg_value_t&);

template <class Archive>
void
load(Archive& archive, npl_lr_write_ptr_reg_value_t& m)
{
    serializer_class<npl_lr_write_ptr_reg_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lr_write_ptr_reg_value_t&);



template<>
class serializer_class<npl_lr_write_ptr_reg_value_t::npl_lr_write_ptr_reg_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lr_write_ptr_reg_value_t::npl_lr_write_ptr_reg_payloads_t& m) {
            archive(::cereal::make_nvp("learn_record_fifo_vars_write_ptr", m.learn_record_fifo_vars_write_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lr_write_ptr_reg_value_t::npl_lr_write_ptr_reg_payloads_t& m) {
            archive(::cereal::make_nvp("learn_record_fifo_vars_write_ptr", m.learn_record_fifo_vars_write_ptr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lr_write_ptr_reg_value_t::npl_lr_write_ptr_reg_payloads_t& m)
{
    serializer_class<npl_lr_write_ptr_reg_value_t::npl_lr_write_ptr_reg_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lr_write_ptr_reg_value_t::npl_lr_write_ptr_reg_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_lr_write_ptr_reg_value_t::npl_lr_write_ptr_reg_payloads_t& m)
{
    serializer_class<npl_lr_write_ptr_reg_value_t::npl_lr_write_ptr_reg_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lr_write_ptr_reg_value_t::npl_lr_write_ptr_reg_payloads_t&);



template<>
class serializer_class<npl_mac_af_npp_attributes_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_af_npp_attributes_table_key_t& m) {
        uint64_t m_npp_attributes_index = m.npp_attributes_index;
            archive(::cereal::make_nvp("npp_attributes_index", m_npp_attributes_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_af_npp_attributes_table_key_t& m) {
        uint64_t m_npp_attributes_index;
            archive(::cereal::make_nvp("npp_attributes_index", m_npp_attributes_index));
        m.npp_attributes_index = m_npp_attributes_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_af_npp_attributes_table_key_t& m)
{
    serializer_class<npl_mac_af_npp_attributes_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_af_npp_attributes_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_af_npp_attributes_table_key_t& m)
{
    serializer_class<npl_mac_af_npp_attributes_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_af_npp_attributes_table_key_t&);



template<>
class serializer_class<npl_mac_af_npp_attributes_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_af_npp_attributes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_af_npp_attributes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_af_npp_attributes_table_value_t& m)
{
    serializer_class<npl_mac_af_npp_attributes_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_af_npp_attributes_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_af_npp_attributes_table_value_t& m)
{
    serializer_class<npl_mac_af_npp_attributes_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_af_npp_attributes_table_value_t&);



template<>
class serializer_class<npl_mac_af_npp_attributes_table_value_t::npl_mac_af_npp_attributes_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_af_npp_attributes_table_value_t::npl_mac_af_npp_attributes_table_payloads_t& m) {
            archive(::cereal::make_nvp("mac_af_npp_attributes", m.mac_af_npp_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_af_npp_attributes_table_value_t::npl_mac_af_npp_attributes_table_payloads_t& m) {
            archive(::cereal::make_nvp("mac_af_npp_attributes", m.mac_af_npp_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_af_npp_attributes_table_value_t::npl_mac_af_npp_attributes_table_payloads_t& m)
{
    serializer_class<npl_mac_af_npp_attributes_table_value_t::npl_mac_af_npp_attributes_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_af_npp_attributes_table_value_t::npl_mac_af_npp_attributes_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_af_npp_attributes_table_value_t::npl_mac_af_npp_attributes_table_payloads_t& m)
{
    serializer_class<npl_mac_af_npp_attributes_table_value_t::npl_mac_af_npp_attributes_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_af_npp_attributes_table_value_t::npl_mac_af_npp_attributes_table_payloads_t&);



template<>
class serializer_class<npl_mac_da_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_da_table_key_t& m) {
            archive(::cereal::make_nvp("packet_ethernet_header_da", m.packet_ethernet_header_da));
            archive(::cereal::make_nvp("next_protocol_type", m.next_protocol_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_da_table_key_t& m) {
            archive(::cereal::make_nvp("packet_ethernet_header_da", m.packet_ethernet_header_da));
            archive(::cereal::make_nvp("next_protocol_type", m.next_protocol_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_da_table_key_t& m)
{
    serializer_class<npl_mac_da_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_da_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_da_table_key_t& m)
{
    serializer_class<npl_mac_da_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_da_table_key_t&);



template<>
class serializer_class<npl_mac_da_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_da_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_da_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_da_table_value_t& m)
{
    serializer_class<npl_mac_da_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_da_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_da_table_value_t& m)
{
    serializer_class<npl_mac_da_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_da_table_value_t&);



template<>
class serializer_class<npl_mac_da_table_value_t::npl_mac_da_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_da_table_value_t::npl_mac_da_table_payloads_t& m) {
            archive(::cereal::make_nvp("mac_da", m.mac_da));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_da_table_value_t::npl_mac_da_table_payloads_t& m) {
            archive(::cereal::make_nvp("mac_da", m.mac_da));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_da_table_value_t::npl_mac_da_table_payloads_t& m)
{
    serializer_class<npl_mac_da_table_value_t::npl_mac_da_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_da_table_value_t::npl_mac_da_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_da_table_value_t::npl_mac_da_table_payloads_t& m)
{
    serializer_class<npl_mac_da_table_value_t::npl_mac_da_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_da_table_value_t::npl_mac_da_table_payloads_t&);



template<>
class serializer_class<npl_mac_ethernet_rate_limit_type_static_table_update_ethernet_rate_limit_type_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_ethernet_rate_limit_type_static_table_update_ethernet_rate_limit_type_payload_t& m) {
            archive(::cereal::make_nvp("ethernet_rate_limiter_type", m.ethernet_rate_limiter_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_ethernet_rate_limit_type_static_table_update_ethernet_rate_limit_type_payload_t& m) {
            archive(::cereal::make_nvp("ethernet_rate_limiter_type", m.ethernet_rate_limiter_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_ethernet_rate_limit_type_static_table_update_ethernet_rate_limit_type_payload_t& m)
{
    serializer_class<npl_mac_ethernet_rate_limit_type_static_table_update_ethernet_rate_limit_type_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_ethernet_rate_limit_type_static_table_update_ethernet_rate_limit_type_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_ethernet_rate_limit_type_static_table_update_ethernet_rate_limit_type_payload_t& m)
{
    serializer_class<npl_mac_ethernet_rate_limit_type_static_table_update_ethernet_rate_limit_type_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_ethernet_rate_limit_type_static_table_update_ethernet_rate_limit_type_payload_t&);



template<>
class serializer_class<npl_mac_ethernet_rate_limit_type_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_ethernet_rate_limit_type_static_table_key_t& m) {
        uint64_t m_is_bc = m.is_bc;
        uint64_t m_is_mc = m.is_mc;
        uint64_t m_mac_forwarding_hit = m.mac_forwarding_hit;
            archive(::cereal::make_nvp("is_bc", m_is_bc));
            archive(::cereal::make_nvp("is_mc", m_is_mc));
            archive(::cereal::make_nvp("mac_forwarding_hit", m_mac_forwarding_hit));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_ethernet_rate_limit_type_static_table_key_t& m) {
        uint64_t m_is_bc;
        uint64_t m_is_mc;
        uint64_t m_mac_forwarding_hit;
            archive(::cereal::make_nvp("is_bc", m_is_bc));
            archive(::cereal::make_nvp("is_mc", m_is_mc));
            archive(::cereal::make_nvp("mac_forwarding_hit", m_mac_forwarding_hit));
        m.is_bc = m_is_bc;
        m.is_mc = m_is_mc;
        m.mac_forwarding_hit = m_mac_forwarding_hit;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_ethernet_rate_limit_type_static_table_key_t& m)
{
    serializer_class<npl_mac_ethernet_rate_limit_type_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_ethernet_rate_limit_type_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_ethernet_rate_limit_type_static_table_key_t& m)
{
    serializer_class<npl_mac_ethernet_rate_limit_type_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_ethernet_rate_limit_type_static_table_key_t&);



template<>
class serializer_class<npl_mac_ethernet_rate_limit_type_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_ethernet_rate_limit_type_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_ethernet_rate_limit_type_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_ethernet_rate_limit_type_static_table_value_t& m)
{
    serializer_class<npl_mac_ethernet_rate_limit_type_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_ethernet_rate_limit_type_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_ethernet_rate_limit_type_static_table_value_t& m)
{
    serializer_class<npl_mac_ethernet_rate_limit_type_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_ethernet_rate_limit_type_static_table_value_t&);



template<>
class serializer_class<npl_mac_ethernet_rate_limit_type_static_table_value_t::npl_mac_ethernet_rate_limit_type_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_ethernet_rate_limit_type_static_table_value_t::npl_mac_ethernet_rate_limit_type_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_ethernet_rate_limit_type", m.update_ethernet_rate_limit_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_ethernet_rate_limit_type_static_table_value_t::npl_mac_ethernet_rate_limit_type_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_ethernet_rate_limit_type", m.update_ethernet_rate_limit_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_ethernet_rate_limit_type_static_table_value_t::npl_mac_ethernet_rate_limit_type_static_table_payloads_t& m)
{
    serializer_class<npl_mac_ethernet_rate_limit_type_static_table_value_t::npl_mac_ethernet_rate_limit_type_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_ethernet_rate_limit_type_static_table_value_t::npl_mac_ethernet_rate_limit_type_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_ethernet_rate_limit_type_static_table_value_t::npl_mac_ethernet_rate_limit_type_static_table_payloads_t& m)
{
    serializer_class<npl_mac_ethernet_rate_limit_type_static_table_value_t::npl_mac_ethernet_rate_limit_type_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_ethernet_rate_limit_type_static_table_value_t::npl_mac_ethernet_rate_limit_type_static_table_payloads_t&);



template<>
class serializer_class<npl_mac_forwarding_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_forwarding_table_key_t& m) {
            archive(::cereal::make_nvp("mac_forwarding_key", m.mac_forwarding_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_forwarding_table_key_t& m) {
            archive(::cereal::make_nvp("mac_forwarding_key", m.mac_forwarding_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_forwarding_table_key_t& m)
{
    serializer_class<npl_mac_forwarding_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_forwarding_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_forwarding_table_key_t& m)
{
    serializer_class<npl_mac_forwarding_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_forwarding_table_key_t&);



template<>
class serializer_class<npl_mac_forwarding_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_forwarding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_forwarding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_forwarding_table_value_t& m)
{
    serializer_class<npl_mac_forwarding_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_forwarding_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_forwarding_table_value_t& m)
{
    serializer_class<npl_mac_forwarding_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_forwarding_table_value_t&);



template<>
class serializer_class<npl_mac_forwarding_table_value_t::npl_mac_forwarding_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_forwarding_table_value_t::npl_mac_forwarding_table_payloads_t& m) {
            archive(::cereal::make_nvp("mact_result", m.mact_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_forwarding_table_value_t::npl_mac_forwarding_table_payloads_t& m) {
            archive(::cereal::make_nvp("mact_result", m.mact_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_forwarding_table_value_t::npl_mac_forwarding_table_payloads_t& m)
{
    serializer_class<npl_mac_forwarding_table_value_t::npl_mac_forwarding_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_forwarding_table_value_t::npl_mac_forwarding_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_forwarding_table_value_t::npl_mac_forwarding_table_payloads_t& m)
{
    serializer_class<npl_mac_forwarding_table_value_t::npl_mac_forwarding_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_forwarding_table_value_t::npl_mac_forwarding_table_payloads_t&);



template<>
class serializer_class<npl_mac_forwarding_w_metadata_table_found_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_forwarding_w_metadata_table_found_payload_t& m) {
            archive(::cereal::make_nvp("dest_metadata", m.dest_metadata));
            archive(::cereal::make_nvp("dest", m.dest));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_forwarding_w_metadata_table_found_payload_t& m) {
            archive(::cereal::make_nvp("dest_metadata", m.dest_metadata));
            archive(::cereal::make_nvp("dest", m.dest));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_forwarding_w_metadata_table_found_payload_t& m)
{
    serializer_class<npl_mac_forwarding_w_metadata_table_found_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_forwarding_w_metadata_table_found_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_forwarding_w_metadata_table_found_payload_t& m)
{
    serializer_class<npl_mac_forwarding_w_metadata_table_found_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_forwarding_w_metadata_table_found_payload_t&);



template<>
class serializer_class<npl_mac_forwarding_w_metadata_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_forwarding_w_metadata_table_key_t& m) {
            archive(::cereal::make_nvp("mac_forwarding_key", m.mac_forwarding_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_forwarding_w_metadata_table_key_t& m) {
            archive(::cereal::make_nvp("mac_forwarding_key", m.mac_forwarding_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_forwarding_w_metadata_table_key_t& m)
{
    serializer_class<npl_mac_forwarding_w_metadata_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_forwarding_w_metadata_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_forwarding_w_metadata_table_key_t& m)
{
    serializer_class<npl_mac_forwarding_w_metadata_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_forwarding_w_metadata_table_key_t&);



template<>
class serializer_class<npl_mac_forwarding_w_metadata_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_forwarding_w_metadata_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_forwarding_w_metadata_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_forwarding_w_metadata_table_value_t& m)
{
    serializer_class<npl_mac_forwarding_w_metadata_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_forwarding_w_metadata_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_forwarding_w_metadata_table_value_t& m)
{
    serializer_class<npl_mac_forwarding_w_metadata_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_forwarding_w_metadata_table_value_t&);



template<>
class serializer_class<npl_mac_forwarding_w_metadata_table_value_t::npl_mac_forwarding_w_metadata_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_forwarding_w_metadata_table_value_t::npl_mac_forwarding_w_metadata_table_payloads_t& m) {
            archive(::cereal::make_nvp("found", m.found));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_forwarding_w_metadata_table_value_t::npl_mac_forwarding_w_metadata_table_payloads_t& m) {
            archive(::cereal::make_nvp("found", m.found));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_forwarding_w_metadata_table_value_t::npl_mac_forwarding_w_metadata_table_payloads_t& m)
{
    serializer_class<npl_mac_forwarding_w_metadata_table_value_t::npl_mac_forwarding_w_metadata_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_forwarding_w_metadata_table_value_t::npl_mac_forwarding_w_metadata_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_forwarding_w_metadata_table_value_t::npl_mac_forwarding_w_metadata_table_payloads_t& m)
{
    serializer_class<npl_mac_forwarding_w_metadata_table_value_t::npl_mac_forwarding_w_metadata_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_forwarding_w_metadata_table_value_t::npl_mac_forwarding_w_metadata_table_payloads_t&);



template<>
class serializer_class<npl_mac_mc_em_termination_attributes_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_mc_em_termination_attributes_table_key_t& m) {
        uint64_t m_l2_relay_attributes_id = m.l2_relay_attributes_id;
            archive(::cereal::make_nvp("l2_relay_attributes_id", m_l2_relay_attributes_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_mc_em_termination_attributes_table_key_t& m) {
        uint64_t m_l2_relay_attributes_id;
            archive(::cereal::make_nvp("l2_relay_attributes_id", m_l2_relay_attributes_id));
        m.l2_relay_attributes_id = m_l2_relay_attributes_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_mc_em_termination_attributes_table_key_t& m)
{
    serializer_class<npl_mac_mc_em_termination_attributes_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_mc_em_termination_attributes_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_mc_em_termination_attributes_table_key_t& m)
{
    serializer_class<npl_mac_mc_em_termination_attributes_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_mc_em_termination_attributes_table_key_t&);



template<>
class serializer_class<npl_mac_mc_em_termination_attributes_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_mc_em_termination_attributes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_mc_em_termination_attributes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_mc_em_termination_attributes_table_value_t& m)
{
    serializer_class<npl_mac_mc_em_termination_attributes_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_mc_em_termination_attributes_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_mc_em_termination_attributes_table_value_t& m)
{
    serializer_class<npl_mac_mc_em_termination_attributes_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_mc_em_termination_attributes_table_value_t&);



template<>
class serializer_class<npl_mac_mc_em_termination_attributes_table_value_t::npl_mac_mc_em_termination_attributes_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_mc_em_termination_attributes_table_value_t::npl_mac_mc_em_termination_attributes_table_payloads_t& m) {
            archive(::cereal::make_nvp("termination_attributes", m.termination_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_mc_em_termination_attributes_table_value_t::npl_mac_mc_em_termination_attributes_table_payloads_t& m) {
            archive(::cereal::make_nvp("termination_attributes", m.termination_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_mc_em_termination_attributes_table_value_t::npl_mac_mc_em_termination_attributes_table_payloads_t& m)
{
    serializer_class<npl_mac_mc_em_termination_attributes_table_value_t::npl_mac_mc_em_termination_attributes_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_mc_em_termination_attributes_table_value_t::npl_mac_mc_em_termination_attributes_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_mc_em_termination_attributes_table_value_t::npl_mac_mc_em_termination_attributes_table_payloads_t& m)
{
    serializer_class<npl_mac_mc_em_termination_attributes_table_value_t::npl_mac_mc_em_termination_attributes_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_mc_em_termination_attributes_table_value_t::npl_mac_mc_em_termination_attributes_table_payloads_t&);



template<>
class serializer_class<npl_mac_mc_tcam_termination_attributes_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_mc_tcam_termination_attributes_table_key_t& m) {
        uint64_t m_l2_relay_attributes_id = m.l2_relay_attributes_id;
            archive(::cereal::make_nvp("l2_relay_attributes_id", m_l2_relay_attributes_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_mc_tcam_termination_attributes_table_key_t& m) {
        uint64_t m_l2_relay_attributes_id;
            archive(::cereal::make_nvp("l2_relay_attributes_id", m_l2_relay_attributes_id));
        m.l2_relay_attributes_id = m_l2_relay_attributes_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_mc_tcam_termination_attributes_table_key_t& m)
{
    serializer_class<npl_mac_mc_tcam_termination_attributes_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_mc_tcam_termination_attributes_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_mc_tcam_termination_attributes_table_key_t& m)
{
    serializer_class<npl_mac_mc_tcam_termination_attributes_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_mc_tcam_termination_attributes_table_key_t&);



template<>
class serializer_class<npl_mac_mc_tcam_termination_attributes_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_mc_tcam_termination_attributes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_mc_tcam_termination_attributes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_mc_tcam_termination_attributes_table_value_t& m)
{
    serializer_class<npl_mac_mc_tcam_termination_attributes_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_mc_tcam_termination_attributes_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_mc_tcam_termination_attributes_table_value_t& m)
{
    serializer_class<npl_mac_mc_tcam_termination_attributes_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_mc_tcam_termination_attributes_table_value_t&);



template<>
class serializer_class<npl_mac_mc_tcam_termination_attributes_table_value_t::npl_mac_mc_tcam_termination_attributes_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_mc_tcam_termination_attributes_table_value_t::npl_mac_mc_tcam_termination_attributes_table_payloads_t& m) {
            archive(::cereal::make_nvp("termination_attributes", m.termination_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_mc_tcam_termination_attributes_table_value_t::npl_mac_mc_tcam_termination_attributes_table_payloads_t& m) {
            archive(::cereal::make_nvp("termination_attributes", m.termination_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_mc_tcam_termination_attributes_table_value_t::npl_mac_mc_tcam_termination_attributes_table_payloads_t& m)
{
    serializer_class<npl_mac_mc_tcam_termination_attributes_table_value_t::npl_mac_mc_tcam_termination_attributes_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_mc_tcam_termination_attributes_table_value_t::npl_mac_mc_tcam_termination_attributes_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_mc_tcam_termination_attributes_table_value_t::npl_mac_mc_tcam_termination_attributes_table_payloads_t& m)
{
    serializer_class<npl_mac_mc_tcam_termination_attributes_table_value_t::npl_mac_mc_tcam_termination_attributes_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_mc_tcam_termination_attributes_table_value_t::npl_mac_mc_tcam_termination_attributes_table_payloads_t&);



template<>
class serializer_class<npl_mac_qos_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_qos_mapping_table_key_t& m) {
        uint64_t m_qos_key = m.qos_key;
        uint64_t m_qos_id = m.qos_id;
            archive(::cereal::make_nvp("qos_key", m_qos_key));
            archive(::cereal::make_nvp("qos_id", m_qos_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_qos_mapping_table_key_t& m) {
        uint64_t m_qos_key;
        uint64_t m_qos_id;
            archive(::cereal::make_nvp("qos_key", m_qos_key));
            archive(::cereal::make_nvp("qos_id", m_qos_id));
        m.qos_key = m_qos_key;
        m.qos_id = m_qos_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_qos_mapping_table_key_t& m)
{
    serializer_class<npl_mac_qos_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_qos_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_qos_mapping_table_key_t& m)
{
    serializer_class<npl_mac_qos_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_qos_mapping_table_key_t&);



template<>
class serializer_class<npl_mac_qos_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_qos_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_qos_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_qos_mapping_table_value_t& m)
{
    serializer_class<npl_mac_qos_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_qos_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_qos_mapping_table_value_t& m)
{
    serializer_class<npl_mac_qos_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_qos_mapping_table_value_t&);



template<>
class serializer_class<npl_mac_qos_mapping_table_value_t::npl_mac_qos_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_qos_mapping_table_value_t::npl_mac_qos_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("ingress_mac_qos_mapping_result", m.ingress_mac_qos_mapping_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_qos_mapping_table_value_t::npl_mac_qos_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("ingress_mac_qos_mapping_result", m.ingress_mac_qos_mapping_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_qos_mapping_table_value_t::npl_mac_qos_mapping_table_payloads_t& m)
{
    serializer_class<npl_mac_qos_mapping_table_value_t::npl_mac_qos_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_qos_mapping_table_value_t::npl_mac_qos_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_qos_mapping_table_value_t::npl_mac_qos_mapping_table_payloads_t& m)
{
    serializer_class<npl_mac_qos_mapping_table_value_t::npl_mac_qos_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_qos_mapping_table_value_t::npl_mac_qos_mapping_table_payloads_t&);



template<>
class serializer_class<npl_mac_relay_g_ipv4_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_relay_g_ipv4_table_key_t& m) {
        uint64_t m_dip_27_0 = m.dip_27_0;
            archive(::cereal::make_nvp("relay_id", m.relay_id));
            archive(::cereal::make_nvp("dip_27_0", m_dip_27_0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_relay_g_ipv4_table_key_t& m) {
        uint64_t m_dip_27_0;
            archive(::cereal::make_nvp("relay_id", m.relay_id));
            archive(::cereal::make_nvp("dip_27_0", m_dip_27_0));
        m.dip_27_0 = m_dip_27_0;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_relay_g_ipv4_table_key_t& m)
{
    serializer_class<npl_mac_relay_g_ipv4_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_relay_g_ipv4_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_relay_g_ipv4_table_key_t& m)
{
    serializer_class<npl_mac_relay_g_ipv4_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_relay_g_ipv4_table_key_t&);



template<>
class serializer_class<npl_mac_relay_g_ipv4_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_relay_g_ipv4_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_relay_g_ipv4_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_relay_g_ipv4_table_value_t& m)
{
    serializer_class<npl_mac_relay_g_ipv4_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_relay_g_ipv4_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_relay_g_ipv4_table_value_t& m)
{
    serializer_class<npl_mac_relay_g_ipv4_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_relay_g_ipv4_table_value_t&);



template<>
class serializer_class<npl_mac_relay_g_ipv4_table_value_t::npl_mac_relay_g_ipv4_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_relay_g_ipv4_table_value_t::npl_mac_relay_g_ipv4_table_payloads_t& m) {
            archive(::cereal::make_nvp("mac_relay_g_destination", m.mac_relay_g_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_relay_g_ipv4_table_value_t::npl_mac_relay_g_ipv4_table_payloads_t& m) {
            archive(::cereal::make_nvp("mac_relay_g_destination", m.mac_relay_g_destination));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_relay_g_ipv4_table_value_t::npl_mac_relay_g_ipv4_table_payloads_t& m)
{
    serializer_class<npl_mac_relay_g_ipv4_table_value_t::npl_mac_relay_g_ipv4_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_relay_g_ipv4_table_value_t::npl_mac_relay_g_ipv4_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_relay_g_ipv4_table_value_t::npl_mac_relay_g_ipv4_table_payloads_t& m)
{
    serializer_class<npl_mac_relay_g_ipv4_table_value_t::npl_mac_relay_g_ipv4_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_relay_g_ipv4_table_value_t::npl_mac_relay_g_ipv4_table_payloads_t&);



template<>
class serializer_class<npl_mac_relay_g_ipv6_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_relay_g_ipv6_table_key_t& m) {
            archive(::cereal::make_nvp("relay_id", m.relay_id));
            archive(::cereal::make_nvp("dip_119_0", m.dip_119_0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_relay_g_ipv6_table_key_t& m) {
            archive(::cereal::make_nvp("relay_id", m.relay_id));
            archive(::cereal::make_nvp("dip_119_0", m.dip_119_0));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_relay_g_ipv6_table_key_t& m)
{
    serializer_class<npl_mac_relay_g_ipv6_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_relay_g_ipv6_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_relay_g_ipv6_table_key_t& m)
{
    serializer_class<npl_mac_relay_g_ipv6_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_relay_g_ipv6_table_key_t&);



template<>
class serializer_class<npl_mac_relay_g_ipv6_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_relay_g_ipv6_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_relay_g_ipv6_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_relay_g_ipv6_table_value_t& m)
{
    serializer_class<npl_mac_relay_g_ipv6_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_relay_g_ipv6_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_relay_g_ipv6_table_value_t& m)
{
    serializer_class<npl_mac_relay_g_ipv6_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_relay_g_ipv6_table_value_t&);



template<>
class serializer_class<npl_mac_relay_g_ipv6_table_value_t::npl_mac_relay_g_ipv6_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_relay_g_ipv6_table_value_t::npl_mac_relay_g_ipv6_table_payloads_t& m) {
            archive(::cereal::make_nvp("mac_relay_g_destination", m.mac_relay_g_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_relay_g_ipv6_table_value_t::npl_mac_relay_g_ipv6_table_payloads_t& m) {
            archive(::cereal::make_nvp("mac_relay_g_destination", m.mac_relay_g_destination));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_relay_g_ipv6_table_value_t::npl_mac_relay_g_ipv6_table_payloads_t& m)
{
    serializer_class<npl_mac_relay_g_ipv6_table_value_t::npl_mac_relay_g_ipv6_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_relay_g_ipv6_table_value_t::npl_mac_relay_g_ipv6_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_relay_g_ipv6_table_value_t::npl_mac_relay_g_ipv6_table_payloads_t& m)
{
    serializer_class<npl_mac_relay_g_ipv6_table_value_t::npl_mac_relay_g_ipv6_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_relay_g_ipv6_table_value_t::npl_mac_relay_g_ipv6_table_payloads_t&);



template<>
class serializer_class<npl_mac_relay_to_vni_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_relay_to_vni_table_key_t& m) {
            archive(::cereal::make_nvp("l2_relay_id", m.l2_relay_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_relay_to_vni_table_key_t& m) {
            archive(::cereal::make_nvp("l2_relay_id", m.l2_relay_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_relay_to_vni_table_key_t& m)
{
    serializer_class<npl_mac_relay_to_vni_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_relay_to_vni_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_relay_to_vni_table_key_t& m)
{
    serializer_class<npl_mac_relay_to_vni_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_relay_to_vni_table_key_t&);



template<>
class serializer_class<npl_mac_relay_to_vni_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_relay_to_vni_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_relay_to_vni_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_relay_to_vni_table_value_t& m)
{
    serializer_class<npl_mac_relay_to_vni_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_relay_to_vni_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_relay_to_vni_table_value_t& m)
{
    serializer_class<npl_mac_relay_to_vni_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_relay_to_vni_table_value_t&);



template<>
class serializer_class<npl_mac_relay_to_vni_table_value_t::npl_mac_relay_to_vni_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_relay_to_vni_table_value_t::npl_mac_relay_to_vni_table_payloads_t& m) {
            archive(::cereal::make_nvp("vxlan_relay_encap_data", m.vxlan_relay_encap_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_relay_to_vni_table_value_t::npl_mac_relay_to_vni_table_payloads_t& m) {
            archive(::cereal::make_nvp("vxlan_relay_encap_data", m.vxlan_relay_encap_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_relay_to_vni_table_value_t::npl_mac_relay_to_vni_table_payloads_t& m)
{
    serializer_class<npl_mac_relay_to_vni_table_value_t::npl_mac_relay_to_vni_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_relay_to_vni_table_value_t::npl_mac_relay_to_vni_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_relay_to_vni_table_value_t::npl_mac_relay_to_vni_table_payloads_t& m)
{
    serializer_class<npl_mac_relay_to_vni_table_value_t::npl_mac_relay_to_vni_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_relay_to_vni_table_value_t::npl_mac_relay_to_vni_table_payloads_t&);



template<>
class serializer_class<npl_mac_termination_em_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_termination_em_table_key_t& m) {
        uint64_t m_ethernet_header_da_18_0_ = m.ethernet_header_da_18_0_;
        uint64_t m_da_prefix = m.da_prefix;
            archive(::cereal::make_nvp("relay_id", m.relay_id));
            archive(::cereal::make_nvp("ethernet_header_da_18_0_", m_ethernet_header_da_18_0_));
            archive(::cereal::make_nvp("da_prefix", m_da_prefix));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_termination_em_table_key_t& m) {
        uint64_t m_ethernet_header_da_18_0_;
        uint64_t m_da_prefix;
            archive(::cereal::make_nvp("relay_id", m.relay_id));
            archive(::cereal::make_nvp("ethernet_header_da_18_0_", m_ethernet_header_da_18_0_));
            archive(::cereal::make_nvp("da_prefix", m_da_prefix));
        m.ethernet_header_da_18_0_ = m_ethernet_header_da_18_0_;
        m.da_prefix = m_da_prefix;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_termination_em_table_key_t& m)
{
    serializer_class<npl_mac_termination_em_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_termination_em_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_termination_em_table_key_t& m)
{
    serializer_class<npl_mac_termination_em_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_termination_em_table_key_t&);



template<>
class serializer_class<npl_mac_termination_em_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_termination_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_termination_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_termination_em_table_value_t& m)
{
    serializer_class<npl_mac_termination_em_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_termination_em_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_termination_em_table_value_t& m)
{
    serializer_class<npl_mac_termination_em_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_termination_em_table_value_t&);



template<>
class serializer_class<npl_mac_termination_em_table_value_t::npl_mac_termination_em_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_termination_em_table_value_t::npl_mac_termination_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("termination_attributes", m.termination_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_termination_em_table_value_t::npl_mac_termination_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("termination_attributes", m.termination_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_termination_em_table_value_t::npl_mac_termination_em_table_payloads_t& m)
{
    serializer_class<npl_mac_termination_em_table_value_t::npl_mac_termination_em_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_termination_em_table_value_t::npl_mac_termination_em_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_termination_em_table_value_t::npl_mac_termination_em_table_payloads_t& m)
{
    serializer_class<npl_mac_termination_em_table_value_t::npl_mac_termination_em_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_termination_em_table_value_t::npl_mac_termination_em_table_payloads_t&);



template<>
class serializer_class<npl_mac_termination_next_macro_static_table_mac_termination_next_macro_action_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_termination_next_macro_static_table_mac_termination_next_macro_action_payload_t& m) {
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_termination_next_macro_static_table_mac_termination_next_macro_action_payload_t& m) {
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
save(Archive& archive, const npl_mac_termination_next_macro_static_table_mac_termination_next_macro_action_payload_t& m)
{
    serializer_class<npl_mac_termination_next_macro_static_table_mac_termination_next_macro_action_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_termination_next_macro_static_table_mac_termination_next_macro_action_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_termination_next_macro_static_table_mac_termination_next_macro_action_payload_t& m)
{
    serializer_class<npl_mac_termination_next_macro_static_table_mac_termination_next_macro_action_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_termination_next_macro_static_table_mac_termination_next_macro_action_payload_t&);



template<>
class serializer_class<npl_mac_termination_next_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_termination_next_macro_static_table_key_t& m) {
        uint64_t m_mac_relay_local_vars_mac_next_macro_packed_data = m.mac_relay_local_vars_mac_next_macro_packed_data;
            archive(::cereal::make_nvp("mac_relay_local_vars_mac_next_macro_packed_data", m_mac_relay_local_vars_mac_next_macro_packed_data));
            archive(::cereal::make_nvp("ipv4_ipv6_init_rtf_stage", m.ipv4_ipv6_init_rtf_stage));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_termination_next_macro_static_table_key_t& m) {
        uint64_t m_mac_relay_local_vars_mac_next_macro_packed_data;
            archive(::cereal::make_nvp("mac_relay_local_vars_mac_next_macro_packed_data", m_mac_relay_local_vars_mac_next_macro_packed_data));
            archive(::cereal::make_nvp("ipv4_ipv6_init_rtf_stage", m.ipv4_ipv6_init_rtf_stage));
        m.mac_relay_local_vars_mac_next_macro_packed_data = m_mac_relay_local_vars_mac_next_macro_packed_data;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_termination_next_macro_static_table_key_t& m)
{
    serializer_class<npl_mac_termination_next_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_termination_next_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_termination_next_macro_static_table_key_t& m)
{
    serializer_class<npl_mac_termination_next_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_termination_next_macro_static_table_key_t&);



template<>
class serializer_class<npl_mac_termination_next_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_termination_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_termination_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_termination_next_macro_static_table_value_t& m)
{
    serializer_class<npl_mac_termination_next_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_termination_next_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_termination_next_macro_static_table_value_t& m)
{
    serializer_class<npl_mac_termination_next_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_termination_next_macro_static_table_value_t&);



template<>
class serializer_class<npl_mac_termination_next_macro_static_table_value_t::npl_mac_termination_next_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_termination_next_macro_static_table_value_t::npl_mac_termination_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("mac_termination_next_macro_action", m.mac_termination_next_macro_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_termination_next_macro_static_table_value_t::npl_mac_termination_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("mac_termination_next_macro_action", m.mac_termination_next_macro_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_termination_next_macro_static_table_value_t::npl_mac_termination_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_mac_termination_next_macro_static_table_value_t::npl_mac_termination_next_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_termination_next_macro_static_table_value_t::npl_mac_termination_next_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_termination_next_macro_static_table_value_t::npl_mac_termination_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_mac_termination_next_macro_static_table_value_t::npl_mac_termination_next_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_termination_next_macro_static_table_value_t::npl_mac_termination_next_macro_static_table_payloads_t&);



template<>
class serializer_class<npl_mac_termination_no_da_em_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_termination_no_da_em_table_key_t& m) {
            archive(::cereal::make_nvp("service_relay_attributes_table_key", m.service_relay_attributes_table_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_termination_no_da_em_table_key_t& m) {
            archive(::cereal::make_nvp("service_relay_attributes_table_key", m.service_relay_attributes_table_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_termination_no_da_em_table_key_t& m)
{
    serializer_class<npl_mac_termination_no_da_em_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_termination_no_da_em_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_termination_no_da_em_table_key_t& m)
{
    serializer_class<npl_mac_termination_no_da_em_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_termination_no_da_em_table_key_t&);



template<>
class serializer_class<npl_mac_termination_no_da_em_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_termination_no_da_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_termination_no_da_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_termination_no_da_em_table_value_t& m)
{
    serializer_class<npl_mac_termination_no_da_em_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_termination_no_da_em_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_termination_no_da_em_table_value_t& m)
{
    serializer_class<npl_mac_termination_no_da_em_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_termination_no_da_em_table_value_t&);



template<>
class serializer_class<npl_mac_termination_no_da_em_table_value_t::npl_mac_termination_no_da_em_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_termination_no_da_em_table_value_t::npl_mac_termination_no_da_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("termination_attributes", m.termination_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_termination_no_da_em_table_value_t::npl_mac_termination_no_da_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("termination_attributes", m.termination_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_termination_no_da_em_table_value_t::npl_mac_termination_no_da_em_table_payloads_t& m)
{
    serializer_class<npl_mac_termination_no_da_em_table_value_t::npl_mac_termination_no_da_em_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_termination_no_da_em_table_value_t::npl_mac_termination_no_da_em_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_termination_no_da_em_table_value_t::npl_mac_termination_no_da_em_table_payloads_t& m)
{
    serializer_class<npl_mac_termination_no_da_em_table_value_t::npl_mac_termination_no_da_em_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_termination_no_da_em_table_value_t::npl_mac_termination_no_da_em_table_payloads_t&);



template<>
class serializer_class<npl_mac_termination_tcam_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_termination_tcam_table_key_t& m) {
        uint64_t m_ethernet_header_da_18_0_ = m.ethernet_header_da_18_0_;
        uint64_t m_da_prefix = m.da_prefix;
            archive(::cereal::make_nvp("service_relay_attributes_table_key", m.service_relay_attributes_table_key));
            archive(::cereal::make_nvp("ethernet_header_da_18_0_", m_ethernet_header_da_18_0_));
            archive(::cereal::make_nvp("da_prefix", m_da_prefix));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_termination_tcam_table_key_t& m) {
        uint64_t m_ethernet_header_da_18_0_;
        uint64_t m_da_prefix;
            archive(::cereal::make_nvp("service_relay_attributes_table_key", m.service_relay_attributes_table_key));
            archive(::cereal::make_nvp("ethernet_header_da_18_0_", m_ethernet_header_da_18_0_));
            archive(::cereal::make_nvp("da_prefix", m_da_prefix));
        m.ethernet_header_da_18_0_ = m_ethernet_header_da_18_0_;
        m.da_prefix = m_da_prefix;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_termination_tcam_table_key_t& m)
{
    serializer_class<npl_mac_termination_tcam_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_termination_tcam_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_termination_tcam_table_key_t& m)
{
    serializer_class<npl_mac_termination_tcam_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_termination_tcam_table_key_t&);



template<>
class serializer_class<npl_mac_termination_tcam_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_termination_tcam_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_termination_tcam_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_termination_tcam_table_value_t& m)
{
    serializer_class<npl_mac_termination_tcam_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_termination_tcam_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_termination_tcam_table_value_t& m)
{
    serializer_class<npl_mac_termination_tcam_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_termination_tcam_table_value_t&);



template<>
class serializer_class<npl_mac_termination_tcam_table_value_t::npl_mac_termination_tcam_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_termination_tcam_table_value_t::npl_mac_termination_tcam_table_payloads_t& m) {
            archive(::cereal::make_nvp("termination_attributes", m.termination_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_termination_tcam_table_value_t::npl_mac_termination_tcam_table_payloads_t& m) {
            archive(::cereal::make_nvp("termination_attributes", m.termination_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_termination_tcam_table_value_t::npl_mac_termination_tcam_table_payloads_t& m)
{
    serializer_class<npl_mac_termination_tcam_table_value_t::npl_mac_termination_tcam_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_termination_tcam_table_value_t::npl_mac_termination_tcam_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_termination_tcam_table_value_t::npl_mac_termination_tcam_table_payloads_t& m)
{
    serializer_class<npl_mac_termination_tcam_table_value_t::npl_mac_termination_tcam_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_termination_tcam_table_value_t::npl_mac_termination_tcam_table_payloads_t&);



template<>
class serializer_class<npl_map_ene_subcode_to8bit_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_ene_subcode_to8bit_static_table_key_t& m) {
        uint64_t m_tx_npu_header_ingress_punt_encap_data_mirror_local_encap_format = m.tx_npu_header_ingress_punt_encap_data_mirror_local_encap_format;
            archive(::cereal::make_nvp("tx_npu_header_ingress_punt_encap_data_mirror_local_encap_format", m_tx_npu_header_ingress_punt_encap_data_mirror_local_encap_format));
            archive(::cereal::make_nvp("tx_npu_header_encap_punt_mc_expand_encap_lpts_flow_type", m.tx_npu_header_encap_punt_mc_expand_encap_lpts_flow_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_ene_subcode_to8bit_static_table_key_t& m) {
        uint64_t m_tx_npu_header_ingress_punt_encap_data_mirror_local_encap_format;
            archive(::cereal::make_nvp("tx_npu_header_ingress_punt_encap_data_mirror_local_encap_format", m_tx_npu_header_ingress_punt_encap_data_mirror_local_encap_format));
            archive(::cereal::make_nvp("tx_npu_header_encap_punt_mc_expand_encap_lpts_flow_type", m.tx_npu_header_encap_punt_mc_expand_encap_lpts_flow_type));
        m.tx_npu_header_ingress_punt_encap_data_mirror_local_encap_format = m_tx_npu_header_ingress_punt_encap_data_mirror_local_encap_format;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_ene_subcode_to8bit_static_table_key_t& m)
{
    serializer_class<npl_map_ene_subcode_to8bit_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_ene_subcode_to8bit_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_map_ene_subcode_to8bit_static_table_key_t& m)
{
    serializer_class<npl_map_ene_subcode_to8bit_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_ene_subcode_to8bit_static_table_key_t&);



template<>
class serializer_class<npl_map_ene_subcode_to8bit_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_ene_subcode_to8bit_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_ene_subcode_to8bit_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_ene_subcode_to8bit_static_table_value_t& m)
{
    serializer_class<npl_map_ene_subcode_to8bit_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_ene_subcode_to8bit_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_map_ene_subcode_to8bit_static_table_value_t& m)
{
    serializer_class<npl_map_ene_subcode_to8bit_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_ene_subcode_to8bit_static_table_value_t&);



template<>
class serializer_class<npl_map_ene_subcode_to8bit_static_table_value_t::npl_map_ene_subcode_to8bit_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_ene_subcode_to8bit_static_table_value_t::npl_map_ene_subcode_to8bit_static_table_payloads_t& m) {
        uint64_t m_tx_punt_local_var_local_ene_punt_sub_code = m.tx_punt_local_var_local_ene_punt_sub_code;
            archive(::cereal::make_nvp("tx_punt_local_var_local_ene_punt_sub_code", m_tx_punt_local_var_local_ene_punt_sub_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_ene_subcode_to8bit_static_table_value_t::npl_map_ene_subcode_to8bit_static_table_payloads_t& m) {
        uint64_t m_tx_punt_local_var_local_ene_punt_sub_code;
            archive(::cereal::make_nvp("tx_punt_local_var_local_ene_punt_sub_code", m_tx_punt_local_var_local_ene_punt_sub_code));
        m.tx_punt_local_var_local_ene_punt_sub_code = m_tx_punt_local_var_local_ene_punt_sub_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_ene_subcode_to8bit_static_table_value_t::npl_map_ene_subcode_to8bit_static_table_payloads_t& m)
{
    serializer_class<npl_map_ene_subcode_to8bit_static_table_value_t::npl_map_ene_subcode_to8bit_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_ene_subcode_to8bit_static_table_value_t::npl_map_ene_subcode_to8bit_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_map_ene_subcode_to8bit_static_table_value_t::npl_map_ene_subcode_to8bit_static_table_payloads_t& m)
{
    serializer_class<npl_map_ene_subcode_to8bit_static_table_value_t::npl_map_ene_subcode_to8bit_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_ene_subcode_to8bit_static_table_value_t::npl_map_ene_subcode_to8bit_static_table_payloads_t&);



}

