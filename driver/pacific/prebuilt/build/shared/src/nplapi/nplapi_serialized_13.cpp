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

template <class Archive> void save(Archive&, const npl_app_traps_t&);
template <class Archive> void load(Archive&, npl_app_traps_t&);

template <class Archive> void save(Archive&, const npl_bool_t&);
template <class Archive> void load(Archive&, npl_bool_t&);

template <class Archive> void save(Archive&, const npl_burst_size_len_t&);
template <class Archive> void load(Archive&, npl_burst_size_len_t&);

template <class Archive> void save(Archive&, const npl_bvn_profile_t&);
template <class Archive> void load(Archive&, npl_bvn_profile_t&);

template <class Archive> void save(Archive&, const npl_color_aware_mode_len_t&);
template <class Archive> void load(Archive&, npl_color_aware_mode_len_t&);

template <class Archive> void save(Archive&, const npl_color_len_t&);
template <class Archive> void load(Archive&, npl_color_len_t&);

template <class Archive> void save(Archive&, const npl_compressed_counter_t&);
template <class Archive> void load(Archive&, npl_compressed_counter_t&);

template <class Archive> void save(Archive&, const npl_counter_ptr_t&);
template <class Archive> void load(Archive&, npl_counter_ptr_t&);

template <class Archive> void save(Archive&, const npl_destination_t&);
template <class Archive> void load(Archive&, npl_destination_t&);

template <class Archive> void save(Archive&, const npl_ene_no_bos_t&);
template <class Archive> void load(Archive&, npl_ene_no_bos_t&);

template <class Archive> void save(Archive&, const npl_eth_rtf_prop_over_fwd0_t&);
template <class Archive> void load(Archive&, npl_eth_rtf_prop_over_fwd0_t&);

template <class Archive> void save(Archive&, const npl_eth_rtf_prop_over_fwd1_t&);
template <class Archive> void load(Archive&, npl_eth_rtf_prop_over_fwd1_t&);

template <class Archive> void save(Archive&, const npl_ethernet_traps_t&);
template <class Archive> void load(Archive&, npl_ethernet_traps_t&);

template <class Archive> void save(Archive&, const npl_exp_bos_and_label_t&);
template <class Archive> void load(Archive&, npl_exp_bos_and_label_t&);

template <class Archive> void save(Archive&, const npl_fwd_layer_and_rtf_stage_compressed_fields_t&);
template <class Archive> void load(Archive&, npl_fwd_layer_and_rtf_stage_compressed_fields_t&);

template <class Archive> void save(Archive&, const npl_icmp_type_code_t&);
template <class Archive> void load(Archive&, npl_icmp_type_code_t&);

template <class Archive> void save(Archive&, const npl_internal_traps_t&);
template <class Archive> void load(Archive&, npl_internal_traps_t&);

template <class Archive> void save(Archive&, const npl_ip_rtf_iter_prop_over_fwd0_t&);
template <class Archive> void load(Archive&, npl_ip_rtf_iter_prop_over_fwd0_t&);

template <class Archive> void save(Archive&, const npl_ip_rtf_iter_prop_over_fwd1_t&);
template <class Archive> void load(Archive&, npl_ip_rtf_iter_prop_over_fwd1_t&);

template <class Archive> void save(Archive&, const npl_ip_tunnel_dip_t&);
template <class Archive> void load(Archive&, npl_ip_tunnel_dip_t&);

template <class Archive> void save(Archive&, const npl_ipv4_ipv6_init_rtf_stage_t&);
template <class Archive> void load(Archive&, npl_ipv4_ipv6_init_rtf_stage_t&);

template <class Archive> void save(Archive&, const npl_ipv4_traps_t&);
template <class Archive> void load(Archive&, npl_ipv4_traps_t&);

template <class Archive> void save(Archive&, const npl_ipv6_traps_t&);
template <class Archive> void load(Archive&, npl_ipv6_traps_t&);

template <class Archive> void save(Archive&, const npl_l2_lpts_traps_t&);
template <class Archive> void load(Archive&, npl_l2_lpts_traps_t&);

template <class Archive> void save(Archive&, const npl_l2_relay_id_t&);
template <class Archive> void load(Archive&, npl_l2_relay_id_t&);

template <class Archive> void save(Archive&, const npl_l3_traps_t&);
template <class Archive> void load(Archive&, npl_l3_traps_t&);

template <class Archive> void save(Archive&, const npl_lb_key_t&);
template <class Archive> void load(Archive&, npl_lb_key_t&);

template <class Archive> void save(Archive&, const npl_lp_rtf_conf_set_t&);
template <class Archive> void load(Archive&, npl_lp_rtf_conf_set_t&);

template <class Archive> void save(Archive&, const npl_lpts_flow_type_t&);
template <class Archive> void load(Archive&, npl_lpts_flow_type_t&);

template <class Archive> void save(Archive&, const npl_meter_action_profile_len_t&);
template <class Archive> void load(Archive&, npl_meter_action_profile_len_t&);

template <class Archive> void save(Archive&, const npl_meter_count_mode_len_t&);
template <class Archive> void load(Archive&, npl_meter_count_mode_len_t&);

template <class Archive> void save(Archive&, const npl_meter_mode_len_t&);
template <class Archive> void load(Archive&, npl_meter_mode_len_t&);

template <class Archive> void save(Archive&, const npl_meter_profile_len_t&);
template <class Archive> void load(Archive&, npl_meter_profile_len_t&);

template <class Archive> void save(Archive&, const npl_meter_weight_t&);
template <class Archive> void load(Archive&, npl_meter_weight_t&);

template <class Archive> void save(Archive&, const npl_mpls_traps_t&);
template <class Archive> void load(Archive&, npl_mpls_traps_t&);

template <class Archive> void save(Archive&, const npl_oamp_traps_t&);
template <class Archive> void load(Archive&, npl_oamp_traps_t&);

template <class Archive> void save(Archive&, const npl_path_lb_destination1_t&);
template <class Archive> void load(Archive&, npl_path_lb_destination1_t&);

template <class Archive> void save(Archive&, const npl_path_lb_destination_t&);
template <class Archive> void load(Archive&, npl_path_lb_destination_t&);

template <class Archive> void save(Archive&, const npl_path_lb_raw_t&);
template <class Archive> void load(Archive&, npl_path_lb_raw_t&);

template <class Archive> void save(Archive&, const npl_path_lb_stage2_p_nh_11b_asbr_t&);
template <class Archive> void load(Archive&, npl_path_lb_stage2_p_nh_11b_asbr_t&);

template <class Archive> void save(Archive&, const npl_path_lb_stage2_p_nh_te_tunnel14b1_t&);
template <class Archive> void load(Archive&, npl_path_lb_stage2_p_nh_te_tunnel14b1_t&);

template <class Archive> void save(Archive&, const npl_path_lb_stage2_p_nh_te_tunnel14b_t&);
template <class Archive> void load(Archive&, npl_path_lb_stage2_p_nh_te_tunnel14b_t&);

template <class Archive> void save(Archive&, const npl_path_lb_stage3_nh_11b_asbr_t&);
template <class Archive> void load(Archive&, npl_path_lb_stage3_nh_11b_asbr_t&);

template <class Archive> void save(Archive&, const npl_path_lb_stage3_nh_te_tunnel14b1_t&);
template <class Archive> void load(Archive&, npl_path_lb_stage3_nh_te_tunnel14b1_t&);

template <class Archive> void save(Archive&, const npl_path_lb_stage3_nh_te_tunnel14b_t&);
template <class Archive> void load(Archive&, npl_path_lb_stage3_nh_te_tunnel14b_t&);

template <class Archive> void save(Archive&, const npl_pcp_dei_t&);
template <class Archive> void load(Archive&, npl_pcp_dei_t&);

template <class Archive> void save(Archive&, const npl_phb_t&);
template <class Archive> void load(Archive&, npl_phb_t&);

template <class Archive> void save(Archive&, const npl_port_npp_protection_protected_raw_t&);
template <class Archive> void load(Archive&, npl_port_npp_protection_protected_raw_t&);

template<>
class serializer_class<npl_port_npp_protection_table_protection_entry_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_npp_protection_table_protection_entry_t& m) {
            archive(::cereal::make_nvp("raw", m.raw));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_npp_protection_table_protection_entry_t& m) {
            archive(::cereal::make_nvp("raw", m.raw));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_npp_protection_table_protection_entry_t& m)
{
    serializer_class<npl_port_npp_protection_table_protection_entry_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_npp_protection_table_protection_entry_t&);

template <class Archive>
void
load(Archive& archive, npl_port_npp_protection_table_protection_entry_t& m)
{
    serializer_class<npl_port_npp_protection_table_protection_entry_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_npp_protection_table_protection_entry_t&);



template<>
class serializer_class<npl_port_protection_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_protection_id_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_protection_id_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_protection_id_t& m)
{
    serializer_class<npl_port_protection_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_protection_id_t&);

template <class Archive>
void
load(Archive& archive, npl_port_protection_id_t& m)
{
    serializer_class<npl_port_protection_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_protection_id_t&);



template<>
class serializer_class<npl_properties_t_anonymous_union_monitor_or_l3_dlp_ip_type_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_properties_t_anonymous_union_monitor_or_l3_dlp_ip_type_t& m) {
            archive(::cereal::make_nvp("l3_dlp_ip_type", m.l3_dlp_ip_type));
            archive(::cereal::make_nvp("enable_monitor", m.enable_monitor));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_properties_t_anonymous_union_monitor_or_l3_dlp_ip_type_t& m) {
            archive(::cereal::make_nvp("l3_dlp_ip_type", m.l3_dlp_ip_type));
            archive(::cereal::make_nvp("enable_monitor", m.enable_monitor));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_properties_t_anonymous_union_monitor_or_l3_dlp_ip_type_t& m)
{
    serializer_class<npl_properties_t_anonymous_union_monitor_or_l3_dlp_ip_type_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_properties_t_anonymous_union_monitor_or_l3_dlp_ip_type_t&);

template <class Archive>
void
load(Archive& archive, npl_properties_t_anonymous_union_monitor_or_l3_dlp_ip_type_t& m)
{
    serializer_class<npl_properties_t_anonymous_union_monitor_or_l3_dlp_ip_type_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_properties_t_anonymous_union_monitor_or_l3_dlp_ip_type_t&);



template<>
class serializer_class<npl_protection_selector_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_protection_selector_t& m) {
            archive(::cereal::make_nvp("sel", m.sel));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_protection_selector_t& m) {
            archive(::cereal::make_nvp("sel", m.sel));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_protection_selector_t& m)
{
    serializer_class<npl_protection_selector_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_protection_selector_t&);

template <class Archive>
void
load(Archive& archive, npl_protection_selector_t& m)
{
    serializer_class<npl_protection_selector_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_protection_selector_t&);



template<>
class serializer_class<npl_protocol_type_padded_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_protocol_type_padded_t& m) {
        uint64_t m_protocol_type = m.protocol_type;
            archive(::cereal::make_nvp("protocol_type", m_protocol_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_protocol_type_padded_t& m) {
        uint64_t m_protocol_type;
            archive(::cereal::make_nvp("protocol_type", m_protocol_type));
        m.protocol_type = m_protocol_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_protocol_type_padded_t& m)
{
    serializer_class<npl_protocol_type_padded_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_protocol_type_padded_t&);

template <class Archive>
void
load(Archive& archive, npl_protocol_type_padded_t& m)
{
    serializer_class<npl_protocol_type_padded_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_protocol_type_padded_t&);



template<>
class serializer_class<npl_punt_controls_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_controls_t& m) {
        uint64_t m_mirror_local_encap_format = m.mirror_local_encap_format;
            archive(::cereal::make_nvp("punt_format", m.punt_format));
            archive(::cereal::make_nvp("mirror_local_encap_format", m_mirror_local_encap_format));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_controls_t& m) {
        uint64_t m_mirror_local_encap_format;
            archive(::cereal::make_nvp("punt_format", m.punt_format));
            archive(::cereal::make_nvp("mirror_local_encap_format", m_mirror_local_encap_format));
        m.mirror_local_encap_format = m_mirror_local_encap_format;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_controls_t& m)
{
    serializer_class<npl_punt_controls_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_controls_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_controls_t& m)
{
    serializer_class<npl_punt_controls_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_controls_t&);



template<>
class serializer_class<npl_punt_encap_data_lsb_t_anonymous_union_extra_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_encap_data_lsb_t_anonymous_union_extra_t& m) {
        uint64_t m_lpts_meter_index_msb = m.lpts_meter_index_msb;
            archive(::cereal::make_nvp("lpts_meter_index_msb", m_lpts_meter_index_msb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_encap_data_lsb_t_anonymous_union_extra_t& m) {
        uint64_t m_lpts_meter_index_msb;
            archive(::cereal::make_nvp("lpts_meter_index_msb", m_lpts_meter_index_msb));
        m.lpts_meter_index_msb = m_lpts_meter_index_msb;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_encap_data_lsb_t_anonymous_union_extra_t& m)
{
    serializer_class<npl_punt_encap_data_lsb_t_anonymous_union_extra_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_encap_data_lsb_t_anonymous_union_extra_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_encap_data_lsb_t_anonymous_union_extra_t& m)
{
    serializer_class<npl_punt_encap_data_lsb_t_anonymous_union_extra_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_encap_data_lsb_t_anonymous_union_extra_t&);



template<>
class serializer_class<npl_punt_eth_transport_update_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_eth_transport_update_t& m) {
            archive(::cereal::make_nvp("update", m.update));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_eth_transport_update_t& m) {
            archive(::cereal::make_nvp("update", m.update));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_eth_transport_update_t& m)
{
    serializer_class<npl_punt_eth_transport_update_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_eth_transport_update_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_eth_transport_update_t& m)
{
    serializer_class<npl_punt_eth_transport_update_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_eth_transport_update_t&);



template<>
class serializer_class<npl_punt_header_t_anonymous_union_pl_header_offset_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_header_t_anonymous_union_pl_header_offset_t& m) {
        uint64_t m_ingress_next_pl_offset = m.ingress_next_pl_offset;
        uint64_t m_egress_current_pl_offset = m.egress_current_pl_offset;
            archive(::cereal::make_nvp("ingress_next_pl_offset", m_ingress_next_pl_offset));
            archive(::cereal::make_nvp("egress_current_pl_offset", m_egress_current_pl_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_header_t_anonymous_union_pl_header_offset_t& m) {
        uint64_t m_ingress_next_pl_offset;
        uint64_t m_egress_current_pl_offset;
            archive(::cereal::make_nvp("ingress_next_pl_offset", m_ingress_next_pl_offset));
            archive(::cereal::make_nvp("egress_current_pl_offset", m_egress_current_pl_offset));
        m.ingress_next_pl_offset = m_ingress_next_pl_offset;
        m.egress_current_pl_offset = m_egress_current_pl_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_header_t_anonymous_union_pl_header_offset_t& m)
{
    serializer_class<npl_punt_header_t_anonymous_union_pl_header_offset_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_header_t_anonymous_union_pl_header_offset_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_header_t_anonymous_union_pl_header_offset_t& m)
{
    serializer_class<npl_punt_header_t_anonymous_union_pl_header_offset_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_header_t_anonymous_union_pl_header_offset_t&);



template<>
class serializer_class<npl_punt_l2_lp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_l2_lp_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_l2_lp_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_l2_lp_t& m)
{
    serializer_class<npl_punt_l2_lp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_l2_lp_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_l2_lp_t& m)
{
    serializer_class<npl_punt_l2_lp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_l2_lp_t&);



template<>
class serializer_class<npl_punt_npu_host_macro_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_npu_host_macro_data_t& m) {
        uint64_t m_first_fi_macro_id = m.first_fi_macro_id;
        uint64_t m_first_npe_macro_id = m.first_npe_macro_id;
            archive(::cereal::make_nvp("first_fi_macro_id", m_first_fi_macro_id));
            archive(::cereal::make_nvp("first_npe_macro_id", m_first_npe_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_npu_host_macro_data_t& m) {
        uint64_t m_first_fi_macro_id;
        uint64_t m_first_npe_macro_id;
            archive(::cereal::make_nvp("first_fi_macro_id", m_first_fi_macro_id));
            archive(::cereal::make_nvp("first_npe_macro_id", m_first_npe_macro_id));
        m.first_fi_macro_id = m_first_fi_macro_id;
        m.first_npe_macro_id = m_first_npe_macro_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_npu_host_macro_data_t& m)
{
    serializer_class<npl_punt_npu_host_macro_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_npu_host_macro_data_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_npu_host_macro_data_t& m)
{
    serializer_class<npl_punt_npu_host_macro_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_npu_host_macro_data_t&);



template<>
class serializer_class<npl_punt_nw_encap_ptr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_nw_encap_ptr_t& m) {
        uint64_t m_ptr = m.ptr;
            archive(::cereal::make_nvp("ptr", m_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_nw_encap_ptr_t& m) {
        uint64_t m_ptr;
            archive(::cereal::make_nvp("ptr", m_ptr));
        m.ptr = m_ptr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_nw_encap_ptr_t& m)
{
    serializer_class<npl_punt_nw_encap_ptr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_nw_encap_ptr_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_nw_encap_ptr_t& m)
{
    serializer_class<npl_punt_nw_encap_ptr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_nw_encap_ptr_t&);



template<>
class serializer_class<npl_punt_rcy_pack_table_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_rcy_pack_table_payload_t& m) {
        uint64_t m_ive_reset = m.ive_reset;
        uint64_t m_redirect_code = m.redirect_code;
            archive(::cereal::make_nvp("ive_reset", m_ive_reset));
            archive(::cereal::make_nvp("redirect_code", m_redirect_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_rcy_pack_table_payload_t& m) {
        uint64_t m_ive_reset;
        uint64_t m_redirect_code;
            archive(::cereal::make_nvp("ive_reset", m_ive_reset));
            archive(::cereal::make_nvp("redirect_code", m_redirect_code));
        m.ive_reset = m_ive_reset;
        m.redirect_code = m_redirect_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_rcy_pack_table_payload_t& m)
{
    serializer_class<npl_punt_rcy_pack_table_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_rcy_pack_table_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_rcy_pack_table_payload_t& m)
{
    serializer_class<npl_punt_rcy_pack_table_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_rcy_pack_table_payload_t&);



template<>
class serializer_class<npl_punt_ssp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_ssp_t& m) {
        uint64_t m_slice_id = m.slice_id;
        uint64_t m_ssp_12 = m.ssp_12;
            archive(::cereal::make_nvp("slice_id", m_slice_id));
            archive(::cereal::make_nvp("ssp_12", m_ssp_12));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_ssp_t& m) {
        uint64_t m_slice_id;
        uint64_t m_ssp_12;
            archive(::cereal::make_nvp("slice_id", m_slice_id));
            archive(::cereal::make_nvp("ssp_12", m_ssp_12));
        m.slice_id = m_slice_id;
        m.ssp_12 = m_ssp_12;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_ssp_t& m)
{
    serializer_class<npl_punt_ssp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_ssp_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_ssp_t& m)
{
    serializer_class<npl_punt_ssp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_ssp_t&);



template<>
class serializer_class<npl_punt_sub_code_t_anonymous_union_sub_code_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_sub_code_t_anonymous_union_sub_code_t& m) {
            archive(::cereal::make_nvp("lpts_flow_type", m.lpts_flow_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_sub_code_t_anonymous_union_sub_code_t& m) {
            archive(::cereal::make_nvp("lpts_flow_type", m.lpts_flow_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_sub_code_t_anonymous_union_sub_code_t& m)
{
    serializer_class<npl_punt_sub_code_t_anonymous_union_sub_code_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_sub_code_t_anonymous_union_sub_code_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_sub_code_t_anonymous_union_sub_code_t& m)
{
    serializer_class<npl_punt_sub_code_t_anonymous_union_sub_code_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_sub_code_t_anonymous_union_sub_code_t&);



template<>
class serializer_class<npl_pwe_to_l3_lookup_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pwe_to_l3_lookup_result_t& m) {
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("destination", m_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pwe_to_l3_lookup_result_t& m) {
        uint64_t m_destination;
            archive(::cereal::make_nvp("destination", m_destination));
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pwe_to_l3_lookup_result_t& m)
{
    serializer_class<npl_pwe_to_l3_lookup_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pwe_to_l3_lookup_result_t&);

template <class Archive>
void
load(Archive& archive, npl_pwe_to_l3_lookup_result_t& m)
{
    serializer_class<npl_pwe_to_l3_lookup_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pwe_to_l3_lookup_result_t&);



template<>
class serializer_class<npl_qos_and_acl_ids_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_qos_and_acl_ids_t& m) {
        uint64_t m_qos_id = m.qos_id;
        uint64_t m_acl_id = m.acl_id;
            archive(::cereal::make_nvp("qos_id", m_qos_id));
            archive(::cereal::make_nvp("acl_id", m_acl_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_qos_and_acl_ids_t& m) {
        uint64_t m_qos_id;
        uint64_t m_acl_id;
            archive(::cereal::make_nvp("qos_id", m_qos_id));
            archive(::cereal::make_nvp("acl_id", m_acl_id));
        m.qos_id = m_qos_id;
        m.acl_id = m_acl_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_qos_and_acl_ids_t& m)
{
    serializer_class<npl_qos_and_acl_ids_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_qos_and_acl_ids_t&);

template <class Archive>
void
load(Archive& archive, npl_qos_and_acl_ids_t& m)
{
    serializer_class<npl_qos_and_acl_ids_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_qos_and_acl_ids_t&);



template<>
class serializer_class<npl_qos_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_qos_attributes_t& m) {
        uint64_t m_demux_count = m.demux_count;
        uint64_t m_is_group_qos = m.is_group_qos;
        uint64_t m_qos_id = m.qos_id;
            archive(::cereal::make_nvp("demux_count", m_demux_count));
            archive(::cereal::make_nvp("is_group_qos", m_is_group_qos));
            archive(::cereal::make_nvp("q_counter", m.q_counter));
            archive(::cereal::make_nvp("p_counter", m.p_counter));
            archive(::cereal::make_nvp("qos_id", m_qos_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_qos_attributes_t& m) {
        uint64_t m_demux_count;
        uint64_t m_is_group_qos;
        uint64_t m_qos_id;
            archive(::cereal::make_nvp("demux_count", m_demux_count));
            archive(::cereal::make_nvp("is_group_qos", m_is_group_qos));
            archive(::cereal::make_nvp("q_counter", m.q_counter));
            archive(::cereal::make_nvp("p_counter", m.p_counter));
            archive(::cereal::make_nvp("qos_id", m_qos_id));
        m.demux_count = m_demux_count;
        m.is_group_qos = m_is_group_qos;
        m.qos_id = m_qos_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_qos_attributes_t& m)
{
    serializer_class<npl_qos_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_qos_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_qos_attributes_t& m)
{
    serializer_class<npl_qos_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_qos_attributes_t&);



template<>
class serializer_class<npl_qos_encap_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_qos_encap_t& m) {
        uint64_t m_tos = m.tos;
        uint64_t m_pcp_dei = m.pcp_dei;
            archive(::cereal::make_nvp("tos", m_tos));
            archive(::cereal::make_nvp("exp_no_bos", m.exp_no_bos));
            archive(::cereal::make_nvp("pcp_dei", m_pcp_dei));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_qos_encap_t& m) {
        uint64_t m_tos;
        uint64_t m_pcp_dei;
            archive(::cereal::make_nvp("tos", m_tos));
            archive(::cereal::make_nvp("exp_no_bos", m.exp_no_bos));
            archive(::cereal::make_nvp("pcp_dei", m_pcp_dei));
        m.tos = m_tos;
        m.pcp_dei = m_pcp_dei;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_qos_encap_t& m)
{
    serializer_class<npl_qos_encap_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_qos_encap_t&);

template <class Archive>
void
load(Archive& archive, npl_qos_encap_t& m)
{
    serializer_class<npl_qos_encap_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_qos_encap_t&);



template<>
class serializer_class<npl_qos_info_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_qos_info_t& m) {
        uint64_t m_is_group_qos = m.is_group_qos;
        uint64_t m_qos_id = m.qos_id;
            archive(::cereal::make_nvp("is_group_qos", m_is_group_qos));
            archive(::cereal::make_nvp("qos_id", m_qos_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_qos_info_t& m) {
        uint64_t m_is_group_qos;
        uint64_t m_qos_id;
            archive(::cereal::make_nvp("is_group_qos", m_is_group_qos));
            archive(::cereal::make_nvp("qos_id", m_qos_id));
        m.is_group_qos = m_is_group_qos;
        m.qos_id = m_qos_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_qos_info_t& m)
{
    serializer_class<npl_qos_info_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_qos_info_t&);

template <class Archive>
void
load(Archive& archive, npl_qos_info_t& m)
{
    serializer_class<npl_qos_info_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_qos_info_t&);



template<>
class serializer_class<npl_qos_tag_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_qos_tag_t& m) {
        uint64_t m_val = m.val;
            archive(::cereal::make_nvp("val", m_val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_qos_tag_t& m) {
        uint64_t m_val;
            archive(::cereal::make_nvp("val", m_val));
        m.val = m_val;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_qos_tag_t& m)
{
    serializer_class<npl_qos_tag_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_qos_tag_t&);

template <class Archive>
void
load(Archive& archive, npl_qos_tag_t& m)
{
    serializer_class<npl_qos_tag_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_qos_tag_t&);



template<>
class serializer_class<npl_qos_tags_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_qos_tags_t& m) {
            archive(::cereal::make_nvp("mapping_key", m.mapping_key));
            archive(::cereal::make_nvp("outer", m.outer));
            archive(::cereal::make_nvp("inner", m.inner));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_qos_tags_t& m) {
            archive(::cereal::make_nvp("mapping_key", m.mapping_key));
            archive(::cereal::make_nvp("outer", m.outer));
            archive(::cereal::make_nvp("inner", m.inner));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_qos_tags_t& m)
{
    serializer_class<npl_qos_tags_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_qos_tags_t&);

template <class Archive>
void
load(Archive& archive, npl_qos_tags_t& m)
{
    serializer_class<npl_qos_tags_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_qos_tags_t&);



template<>
class serializer_class<npl_quan_13b> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_quan_13b& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_quan_13b& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_quan_13b& m)
{
    serializer_class<npl_quan_13b>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_quan_13b&);

template <class Archive>
void
load(Archive& archive, npl_quan_13b& m)
{
    serializer_class<npl_quan_13b>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_quan_13b&);



template<>
class serializer_class<npl_quan_14b> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_quan_14b& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_quan_14b& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_quan_14b& m)
{
    serializer_class<npl_quan_14b>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_quan_14b&);

template <class Archive>
void
load(Archive& archive, npl_quan_14b& m)
{
    serializer_class<npl_quan_14b>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_quan_14b&);



template<>
class serializer_class<npl_quan_15b> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_quan_15b& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_quan_15b& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_quan_15b& m)
{
    serializer_class<npl_quan_15b>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_quan_15b&);

template <class Archive>
void
load(Archive& archive, npl_quan_15b& m)
{
    serializer_class<npl_quan_15b>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_quan_15b&);



template<>
class serializer_class<npl_quan_19b> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_quan_19b& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_quan_19b& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_quan_19b& m)
{
    serializer_class<npl_quan_19b>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_quan_19b&);

template <class Archive>
void
load(Archive& archive, npl_quan_19b& m)
{
    serializer_class<npl_quan_19b>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_quan_19b&);



template<>
class serializer_class<npl_quan_1b> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_quan_1b& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_quan_1b& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_quan_1b& m)
{
    serializer_class<npl_quan_1b>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_quan_1b&);

template <class Archive>
void
load(Archive& archive, npl_quan_1b& m)
{
    serializer_class<npl_quan_1b>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_quan_1b&);



template<>
class serializer_class<npl_quan_5b> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_quan_5b& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_quan_5b& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_quan_5b& m)
{
    serializer_class<npl_quan_5b>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_quan_5b&);

template <class Archive>
void
load(Archive& archive, npl_quan_5b& m)
{
    serializer_class<npl_quan_5b>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_quan_5b&);



template<>
class serializer_class<npl_quan_8b> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_quan_8b& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_quan_8b& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_quan_8b& m)
{
    serializer_class<npl_quan_8b>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_quan_8b&);

template <class Archive>
void
load(Archive& archive, npl_quan_8b& m)
{
    serializer_class<npl_quan_8b>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_quan_8b&);



template<>
class serializer_class<npl_random_bc_bmp_entry_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_random_bc_bmp_entry_t& m) {
        uint64_t m_rnd_entry = m.rnd_entry;
            archive(::cereal::make_nvp("rnd_entry", m_rnd_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_random_bc_bmp_entry_t& m) {
        uint64_t m_rnd_entry;
            archive(::cereal::make_nvp("rnd_entry", m_rnd_entry));
        m.rnd_entry = m_rnd_entry;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_random_bc_bmp_entry_t& m)
{
    serializer_class<npl_random_bc_bmp_entry_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_random_bc_bmp_entry_t&);

template <class Archive>
void
load(Archive& archive, npl_random_bc_bmp_entry_t& m)
{
    serializer_class<npl_random_bc_bmp_entry_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_random_bc_bmp_entry_t&);



template<>
class serializer_class<npl_rate_limiters_port_packet_type_index_len_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rate_limiters_port_packet_type_index_len_t& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rate_limiters_port_packet_type_index_len_t& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rate_limiters_port_packet_type_index_len_t& m)
{
    serializer_class<npl_rate_limiters_port_packet_type_index_len_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rate_limiters_port_packet_type_index_len_t&);

template <class Archive>
void
load(Archive& archive, npl_rate_limiters_port_packet_type_index_len_t& m)
{
    serializer_class<npl_rate_limiters_port_packet_type_index_len_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rate_limiters_port_packet_type_index_len_t&);



template<>
class serializer_class<npl_raw_lp_over_lag_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_raw_lp_over_lag_result_t& m) {
        uint64_t m_bvn_destination = m.bvn_destination;
            archive(::cereal::make_nvp("bvn_destination", m_bvn_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_raw_lp_over_lag_result_t& m) {
        uint64_t m_bvn_destination;
            archive(::cereal::make_nvp("bvn_destination", m_bvn_destination));
        m.bvn_destination = m_bvn_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_raw_lp_over_lag_result_t& m)
{
    serializer_class<npl_raw_lp_over_lag_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_raw_lp_over_lag_result_t&);

template <class Archive>
void
load(Archive& archive, npl_raw_lp_over_lag_result_t& m)
{
    serializer_class<npl_raw_lp_over_lag_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_raw_lp_over_lag_result_t&);



template<>
class serializer_class<npl_rcy_sm_vlans_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rcy_sm_vlans_t& m) {
        uint64_t m_vid1 = m.vid1;
        uint64_t m_vid2 = m.vid2;
            archive(::cereal::make_nvp("vid1", m_vid1));
            archive(::cereal::make_nvp("vid2", m_vid2));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rcy_sm_vlans_t& m) {
        uint64_t m_vid1;
        uint64_t m_vid2;
            archive(::cereal::make_nvp("vid1", m_vid1));
            archive(::cereal::make_nvp("vid2", m_vid2));
        m.vid1 = m_vid1;
        m.vid2 = m_vid2;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rcy_sm_vlans_t& m)
{
    serializer_class<npl_rcy_sm_vlans_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rcy_sm_vlans_t&);

template <class Archive>
void
load(Archive& archive, npl_rcy_sm_vlans_t& m)
{
    serializer_class<npl_rcy_sm_vlans_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rcy_sm_vlans_t&);



template<>
class serializer_class<npl_reassembly_source_port_map_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_reassembly_source_port_map_key_t& m) {
        uint64_t m_ifg = m.ifg;
        uint64_t m_pif = m.pif;
            archive(::cereal::make_nvp("ifg", m_ifg));
            archive(::cereal::make_nvp("pif", m_pif));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_reassembly_source_port_map_key_t& m) {
        uint64_t m_ifg;
        uint64_t m_pif;
            archive(::cereal::make_nvp("ifg", m_ifg));
            archive(::cereal::make_nvp("pif", m_pif));
        m.ifg = m_ifg;
        m.pif = m_pif;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_reassembly_source_port_map_key_t& m)
{
    serializer_class<npl_reassembly_source_port_map_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_reassembly_source_port_map_key_t&);

template <class Archive>
void
load(Archive& archive, npl_reassembly_source_port_map_key_t& m)
{
    serializer_class<npl_reassembly_source_port_map_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_reassembly_source_port_map_key_t&);



template<>
class serializer_class<npl_reassembly_source_port_map_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_reassembly_source_port_map_result_t& m) {
        uint64_t m_tm_ifc = m.tm_ifc;
            archive(::cereal::make_nvp("tm_ifc", m_tm_ifc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_reassembly_source_port_map_result_t& m) {
        uint64_t m_tm_ifc;
            archive(::cereal::make_nvp("tm_ifc", m_tm_ifc));
        m.tm_ifc = m_tm_ifc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_reassembly_source_port_map_result_t& m)
{
    serializer_class<npl_reassembly_source_port_map_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_reassembly_source_port_map_result_t&);

template <class Archive>
void
load(Archive& archive, npl_reassembly_source_port_map_result_t& m)
{
    serializer_class<npl_reassembly_source_port_map_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_reassembly_source_port_map_result_t&);



template<>
class serializer_class<npl_redirect_code_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_redirect_code_t& m) {
        uint64_t m_val = m.val;
            archive(::cereal::make_nvp("val", m_val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_redirect_code_t& m) {
        uint64_t m_val;
            archive(::cereal::make_nvp("val", m_val));
        m.val = m_val;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_redirect_code_t& m)
{
    serializer_class<npl_redirect_code_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_redirect_code_t&);

template <class Archive>
void
load(Archive& archive, npl_redirect_code_t& m)
{
    serializer_class<npl_redirect_code_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_redirect_code_t&);



template<>
class serializer_class<npl_redirect_destination_reg_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_redirect_destination_reg_t& m) {
            archive(::cereal::make_nvp("port_reg", m.port_reg));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_redirect_destination_reg_t& m) {
            archive(::cereal::make_nvp("port_reg", m.port_reg));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_redirect_destination_reg_t& m)
{
    serializer_class<npl_redirect_destination_reg_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_redirect_destination_reg_t&);

template <class Archive>
void
load(Archive& archive, npl_redirect_destination_reg_t& m)
{
    serializer_class<npl_redirect_destination_reg_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_redirect_destination_reg_t&);



template<>
class serializer_class<npl_relay_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_relay_id_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_relay_id_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_relay_id_t& m)
{
    serializer_class<npl_relay_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_relay_id_t&);

template <class Archive>
void
load(Archive& archive, npl_relay_id_t& m)
{
    serializer_class<npl_relay_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_relay_id_t&);



template<>
class serializer_class<npl_resolution_dlp_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_resolution_dlp_attributes_t& m) {
        uint64_t m_pad = m.pad;
        uint64_t m_monitor = m.monitor;
        uint64_t m_never_use_npu_header_pif_ifg = m.never_use_npu_header_pif_ifg;
            archive(::cereal::make_nvp("pad", m_pad));
            archive(::cereal::make_nvp("monitor", m_monitor));
            archive(::cereal::make_nvp("bvn_profile", m.bvn_profile));
            archive(::cereal::make_nvp("never_use_npu_header_pif_ifg", m_never_use_npu_header_pif_ifg));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_resolution_dlp_attributes_t& m) {
        uint64_t m_pad;
        uint64_t m_monitor;
        uint64_t m_never_use_npu_header_pif_ifg;
            archive(::cereal::make_nvp("pad", m_pad));
            archive(::cereal::make_nvp("monitor", m_monitor));
            archive(::cereal::make_nvp("bvn_profile", m.bvn_profile));
            archive(::cereal::make_nvp("never_use_npu_header_pif_ifg", m_never_use_npu_header_pif_ifg));
        m.pad = m_pad;
        m.monitor = m_monitor;
        m.never_use_npu_header_pif_ifg = m_never_use_npu_header_pif_ifg;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_resolution_dlp_attributes_t& m)
{
    serializer_class<npl_resolution_dlp_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_resolution_dlp_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_resolution_dlp_attributes_t& m)
{
    serializer_class<npl_resolution_dlp_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_resolution_dlp_attributes_t&);



template<>
class serializer_class<npl_resolution_fwd_class_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_resolution_fwd_class_t& m) {
        uint64_t m_tag = m.tag;
            archive(::cereal::make_nvp("tag", m_tag));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_resolution_fwd_class_t& m) {
        uint64_t m_tag;
            archive(::cereal::make_nvp("tag", m_tag));
        m.tag = m_tag;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_resolution_fwd_class_t& m)
{
    serializer_class<npl_resolution_fwd_class_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_resolution_fwd_class_t&);

template <class Archive>
void
load(Archive& archive, npl_resolution_fwd_class_t& m)
{
    serializer_class<npl_resolution_fwd_class_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_resolution_fwd_class_t&);



template<>
class serializer_class<npl_resolution_result_dest_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_resolution_result_dest_data_t& m) {
        uint64_t m_bvn_map_profile = m.bvn_map_profile;
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("lb_key", m.lb_key));
            archive(::cereal::make_nvp("bvn_map_profile", m_bvn_map_profile));
            archive(::cereal::make_nvp("destination", m_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_resolution_result_dest_data_t& m) {
        uint64_t m_bvn_map_profile;
        uint64_t m_destination;
            archive(::cereal::make_nvp("lb_key", m.lb_key));
            archive(::cereal::make_nvp("bvn_map_profile", m_bvn_map_profile));
            archive(::cereal::make_nvp("destination", m_destination));
        m.bvn_map_profile = m_bvn_map_profile;
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_resolution_result_dest_data_t& m)
{
    serializer_class<npl_resolution_result_dest_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_resolution_result_dest_data_t&);

template <class Archive>
void
load(Archive& archive, npl_resolution_result_dest_data_t& m)
{
    serializer_class<npl_resolution_result_dest_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_resolution_result_dest_data_t&);



template<>
class serializer_class<npl_resolution_type_decoding_table_field_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_resolution_type_decoding_table_field_t& m) {
        uint64_t m_destination_in_nibbles = m.destination_in_nibbles;
        uint64_t m_size_in_bits = m.size_in_bits;
        uint64_t m_offset_in_bits = m.offset_in_bits;
            archive(::cereal::make_nvp("destination_in_nibbles", m_destination_in_nibbles));
            archive(::cereal::make_nvp("size_in_bits", m_size_in_bits));
            archive(::cereal::make_nvp("offset_in_bits", m_offset_in_bits));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_resolution_type_decoding_table_field_t& m) {
        uint64_t m_destination_in_nibbles;
        uint64_t m_size_in_bits;
        uint64_t m_offset_in_bits;
            archive(::cereal::make_nvp("destination_in_nibbles", m_destination_in_nibbles));
            archive(::cereal::make_nvp("size_in_bits", m_size_in_bits));
            archive(::cereal::make_nvp("offset_in_bits", m_offset_in_bits));
        m.destination_in_nibbles = m_destination_in_nibbles;
        m.size_in_bits = m_size_in_bits;
        m.offset_in_bits = m_offset_in_bits;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_resolution_type_decoding_table_field_t& m)
{
    serializer_class<npl_resolution_type_decoding_table_field_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_resolution_type_decoding_table_field_t&);

template <class Archive>
void
load(Archive& archive, npl_resolution_type_decoding_table_field_t& m)
{
    serializer_class<npl_resolution_type_decoding_table_field_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_resolution_type_decoding_table_field_t&);



template<>
class serializer_class<npl_resolution_type_decoding_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_resolution_type_decoding_table_result_t& m) {
        uint64_t m_lb_key_offset = m.lb_key_offset;
        uint64_t m_lb_key_overwrite = m.lb_key_overwrite;
        uint64_t m_index_destination_in_nibbles = m.index_destination_in_nibbles;
        uint64_t m_index_size_in_nibbles = m.index_size_in_nibbles;
        uint64_t m_encapsulation_type = m.encapsulation_type;
        uint64_t m_encapsulation_add_type = m.encapsulation_add_type;
        uint64_t m_encapsulation_start = m.encapsulation_start;
        uint64_t m_next_destination_mask = m.next_destination_mask;
        uint64_t m_next_destination_size = m.next_destination_size;
            archive(::cereal::make_nvp("lb_key_offset", m_lb_key_offset));
            archive(::cereal::make_nvp("lb_key_overwrite", m_lb_key_overwrite));
            archive(::cereal::make_nvp("field_1", m.field_1));
            archive(::cereal::make_nvp("field_0", m.field_0));
            archive(::cereal::make_nvp("index_destination_in_nibbles", m_index_destination_in_nibbles));
            archive(::cereal::make_nvp("index_size_in_nibbles", m_index_size_in_nibbles));
            archive(::cereal::make_nvp("encapsulation_type", m_encapsulation_type));
            archive(::cereal::make_nvp("encapsulation_add_type", m_encapsulation_add_type));
            archive(::cereal::make_nvp("encapsulation_start", m_encapsulation_start));
            archive(::cereal::make_nvp("next_destination_mask", m_next_destination_mask));
            archive(::cereal::make_nvp("next_destination_size", m_next_destination_size));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_resolution_type_decoding_table_result_t& m) {
        uint64_t m_lb_key_offset;
        uint64_t m_lb_key_overwrite;
        uint64_t m_index_destination_in_nibbles;
        uint64_t m_index_size_in_nibbles;
        uint64_t m_encapsulation_type;
        uint64_t m_encapsulation_add_type;
        uint64_t m_encapsulation_start;
        uint64_t m_next_destination_mask;
        uint64_t m_next_destination_size;
            archive(::cereal::make_nvp("lb_key_offset", m_lb_key_offset));
            archive(::cereal::make_nvp("lb_key_overwrite", m_lb_key_overwrite));
            archive(::cereal::make_nvp("field_1", m.field_1));
            archive(::cereal::make_nvp("field_0", m.field_0));
            archive(::cereal::make_nvp("index_destination_in_nibbles", m_index_destination_in_nibbles));
            archive(::cereal::make_nvp("index_size_in_nibbles", m_index_size_in_nibbles));
            archive(::cereal::make_nvp("encapsulation_type", m_encapsulation_type));
            archive(::cereal::make_nvp("encapsulation_add_type", m_encapsulation_add_type));
            archive(::cereal::make_nvp("encapsulation_start", m_encapsulation_start));
            archive(::cereal::make_nvp("next_destination_mask", m_next_destination_mask));
            archive(::cereal::make_nvp("next_destination_size", m_next_destination_size));
        m.lb_key_offset = m_lb_key_offset;
        m.lb_key_overwrite = m_lb_key_overwrite;
        m.index_destination_in_nibbles = m_index_destination_in_nibbles;
        m.index_size_in_nibbles = m_index_size_in_nibbles;
        m.encapsulation_type = m_encapsulation_type;
        m.encapsulation_add_type = m_encapsulation_add_type;
        m.encapsulation_start = m_encapsulation_start;
        m.next_destination_mask = m_next_destination_mask;
        m.next_destination_size = m_next_destination_size;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_resolution_type_decoding_table_result_t& m)
{
    serializer_class<npl_resolution_type_decoding_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_resolution_type_decoding_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_resolution_type_decoding_table_result_t& m)
{
    serializer_class<npl_resolution_type_decoding_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_resolution_type_decoding_table_result_t&);



template<>
class serializer_class<npl_rmep_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rmep_data_t& m) {
        uint64_t m_rmep_data = m.rmep_data;
        uint64_t m_rmep_profile = m.rmep_profile;
        uint64_t m_rmep_valid = m.rmep_valid;
            archive(::cereal::make_nvp("rmep_data", m_rmep_data));
            archive(::cereal::make_nvp("rmep_profile", m_rmep_profile));
            archive(::cereal::make_nvp("rmep_valid", m_rmep_valid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rmep_data_t& m) {
        uint64_t m_rmep_data;
        uint64_t m_rmep_profile;
        uint64_t m_rmep_valid;
            archive(::cereal::make_nvp("rmep_data", m_rmep_data));
            archive(::cereal::make_nvp("rmep_profile", m_rmep_profile));
            archive(::cereal::make_nvp("rmep_valid", m_rmep_valid));
        m.rmep_data = m_rmep_data;
        m.rmep_profile = m_rmep_profile;
        m.rmep_valid = m_rmep_valid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rmep_data_t& m)
{
    serializer_class<npl_rmep_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rmep_data_t&);

template <class Archive>
void
load(Archive& archive, npl_rmep_data_t& m)
{
    serializer_class<npl_rmep_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rmep_data_t&);



template<>
class serializer_class<npl_rtf_compressed_fields_for_next_macro_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_compressed_fields_for_next_macro_t& m) {
        uint64_t m_acl_outer = m.acl_outer;
            archive(::cereal::make_nvp("acl_outer", m_acl_outer));
            archive(::cereal::make_nvp("fwd_layer_and_rtf_stage_compressed_fields", m.fwd_layer_and_rtf_stage_compressed_fields));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_compressed_fields_for_next_macro_t& m) {
        uint64_t m_acl_outer;
            archive(::cereal::make_nvp("acl_outer", m_acl_outer));
            archive(::cereal::make_nvp("fwd_layer_and_rtf_stage_compressed_fields", m.fwd_layer_and_rtf_stage_compressed_fields));
        m.acl_outer = m_acl_outer;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_compressed_fields_for_next_macro_t& m)
{
    serializer_class<npl_rtf_compressed_fields_for_next_macro_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_compressed_fields_for_next_macro_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_compressed_fields_for_next_macro_t& m)
{
    serializer_class<npl_rtf_compressed_fields_for_next_macro_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_compressed_fields_for_next_macro_t&);



template<>
class serializer_class<npl_rtf_conf_set_and_stages_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_conf_set_and_stages_t& m) {
            archive(::cereal::make_nvp("rtf_conf_set", m.rtf_conf_set));
            archive(::cereal::make_nvp("ipv4_ipv6_init_rtf_stage", m.ipv4_ipv6_init_rtf_stage));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_conf_set_and_stages_t& m) {
            archive(::cereal::make_nvp("rtf_conf_set", m.rtf_conf_set));
            archive(::cereal::make_nvp("ipv4_ipv6_init_rtf_stage", m.ipv4_ipv6_init_rtf_stage));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_conf_set_and_stages_t& m)
{
    serializer_class<npl_rtf_conf_set_and_stages_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_conf_set_and_stages_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_conf_set_and_stages_t& m)
{
    serializer_class<npl_rtf_conf_set_and_stages_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_conf_set_and_stages_t&);



template<>
class serializer_class<npl_rtf_iter_prop_over_fwd0_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_iter_prop_over_fwd0_t& m) {
            archive(::cereal::make_nvp("ip_rtf", m.ip_rtf));
            archive(::cereal::make_nvp("eth_rtf", m.eth_rtf));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_iter_prop_over_fwd0_t& m) {
            archive(::cereal::make_nvp("ip_rtf", m.ip_rtf));
            archive(::cereal::make_nvp("eth_rtf", m.eth_rtf));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_iter_prop_over_fwd0_t& m)
{
    serializer_class<npl_rtf_iter_prop_over_fwd0_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_iter_prop_over_fwd0_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_iter_prop_over_fwd0_t& m)
{
    serializer_class<npl_rtf_iter_prop_over_fwd0_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_iter_prop_over_fwd0_t&);



template<>
class serializer_class<npl_rtf_iter_prop_over_fwd1_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_iter_prop_over_fwd1_t& m) {
            archive(::cereal::make_nvp("ip_rtf", m.ip_rtf));
            archive(::cereal::make_nvp("eth_rtf", m.eth_rtf));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_iter_prop_over_fwd1_t& m) {
            archive(::cereal::make_nvp("ip_rtf", m.ip_rtf));
            archive(::cereal::make_nvp("eth_rtf", m.eth_rtf));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_iter_prop_over_fwd1_t& m)
{
    serializer_class<npl_rtf_iter_prop_over_fwd1_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_iter_prop_over_fwd1_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_iter_prop_over_fwd1_t& m)
{
    serializer_class<npl_rtf_iter_prop_over_fwd1_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_iter_prop_over_fwd1_t&);



template<>
class serializer_class<npl_rtf_result_profile_0_t_anonymous_union_force_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_result_profile_0_t_anonymous_union_force_t& m) {
            archive(::cereal::make_nvp("destination", m.destination));
            archive(::cereal::make_nvp("drop_counter", m.drop_counter));
            archive(::cereal::make_nvp("permit_ace_cntr", m.permit_ace_cntr));
            archive(::cereal::make_nvp("meter_ptr", m.meter_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_result_profile_0_t_anonymous_union_force_t& m) {
            archive(::cereal::make_nvp("destination", m.destination));
            archive(::cereal::make_nvp("drop_counter", m.drop_counter));
            archive(::cereal::make_nvp("permit_ace_cntr", m.permit_ace_cntr));
            archive(::cereal::make_nvp("meter_ptr", m.meter_ptr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_result_profile_0_t_anonymous_union_force_t& m)
{
    serializer_class<npl_rtf_result_profile_0_t_anonymous_union_force_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_result_profile_0_t_anonymous_union_force_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_result_profile_0_t_anonymous_union_force_t& m)
{
    serializer_class<npl_rtf_result_profile_0_t_anonymous_union_force_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_result_profile_0_t_anonymous_union_force_t&);



template<>
class serializer_class<npl_rtf_result_profile_0_t_anonymous_union_mirror_cmd_or_offset_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_result_profile_0_t_anonymous_union_mirror_cmd_or_offset_t& m) {
        uint64_t m_mirror_cmd = m.mirror_cmd;
        uint64_t m_mirror_offset = m.mirror_offset;
            archive(::cereal::make_nvp("mirror_cmd", m_mirror_cmd));
            archive(::cereal::make_nvp("mirror_offset", m_mirror_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_result_profile_0_t_anonymous_union_mirror_cmd_or_offset_t& m) {
        uint64_t m_mirror_cmd;
        uint64_t m_mirror_offset;
            archive(::cereal::make_nvp("mirror_cmd", m_mirror_cmd));
            archive(::cereal::make_nvp("mirror_offset", m_mirror_offset));
        m.mirror_cmd = m_mirror_cmd;
        m.mirror_offset = m_mirror_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_result_profile_0_t_anonymous_union_mirror_cmd_or_offset_t& m)
{
    serializer_class<npl_rtf_result_profile_0_t_anonymous_union_mirror_cmd_or_offset_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_result_profile_0_t_anonymous_union_mirror_cmd_or_offset_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_result_profile_0_t_anonymous_union_mirror_cmd_or_offset_t& m)
{
    serializer_class<npl_rtf_result_profile_0_t_anonymous_union_mirror_cmd_or_offset_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_result_profile_0_t_anonymous_union_mirror_cmd_or_offset_t&);



template<>
class serializer_class<npl_rtf_result_profile_1_t_anonymous_union_meter_or_counter_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_result_profile_1_t_anonymous_union_meter_or_counter_t& m) {
            archive(::cereal::make_nvp("meter_ptr", m.meter_ptr));
            archive(::cereal::make_nvp("counter_ptr", m.counter_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_result_profile_1_t_anonymous_union_meter_or_counter_t& m) {
            archive(::cereal::make_nvp("meter_ptr", m.meter_ptr));
            archive(::cereal::make_nvp("counter_ptr", m.counter_ptr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_result_profile_1_t_anonymous_union_meter_or_counter_t& m)
{
    serializer_class<npl_rtf_result_profile_1_t_anonymous_union_meter_or_counter_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_result_profile_1_t_anonymous_union_meter_or_counter_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_result_profile_1_t_anonymous_union_meter_or_counter_t& m)
{
    serializer_class<npl_rtf_result_profile_1_t_anonymous_union_meter_or_counter_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_result_profile_1_t_anonymous_union_meter_or_counter_t&);



template<>
class serializer_class<npl_rtf_result_profile_2_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_result_profile_2_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_result_profile_2_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_result_profile_2_t& m)
{
    serializer_class<npl_rtf_result_profile_2_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_result_profile_2_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_result_profile_2_t& m)
{
    serializer_class<npl_rtf_result_profile_2_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_result_profile_2_t&);



template<>
class serializer_class<npl_rtf_result_profile_3_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_result_profile_3_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_result_profile_3_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_result_profile_3_t& m)
{
    serializer_class<npl_rtf_result_profile_3_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_result_profile_3_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_result_profile_3_t& m)
{
    serializer_class<npl_rtf_result_profile_3_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_result_profile_3_t&);



template<>
class serializer_class<npl_rtf_step_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_step_t& m) {
        uint64_t m_val = m.val;
            archive(::cereal::make_nvp("val", m_val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_step_t& m) {
        uint64_t m_val;
            archive(::cereal::make_nvp("val", m_val));
        m.val = m_val;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_step_t& m)
{
    serializer_class<npl_rtf_step_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_step_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_step_t& m)
{
    serializer_class<npl_rtf_step_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_step_t&);



template<>
class serializer_class<npl_rx_meter_block_meter_attribute_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_block_meter_attribute_result_t& m) {
        uint64_t m_commited_coupling_flag = m.commited_coupling_flag;
            archive(::cereal::make_nvp("meter_decision_mapping_profile", m.meter_decision_mapping_profile));
            archive(::cereal::make_nvp("commited_coupling_flag", m_commited_coupling_flag));
            archive(::cereal::make_nvp("profile", m.profile));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_block_meter_attribute_result_t& m) {
        uint64_t m_commited_coupling_flag;
            archive(::cereal::make_nvp("meter_decision_mapping_profile", m.meter_decision_mapping_profile));
            archive(::cereal::make_nvp("commited_coupling_flag", m_commited_coupling_flag));
            archive(::cereal::make_nvp("profile", m.profile));
        m.commited_coupling_flag = m_commited_coupling_flag;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_block_meter_attribute_result_t& m)
{
    serializer_class<npl_rx_meter_block_meter_attribute_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_block_meter_attribute_result_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_block_meter_attribute_result_t& m)
{
    serializer_class<npl_rx_meter_block_meter_attribute_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_block_meter_attribute_result_t&);



template<>
class serializer_class<npl_rx_meter_block_meter_profile_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_block_meter_profile_result_t& m) {
            archive(::cereal::make_nvp("ebs", m.ebs));
            archive(::cereal::make_nvp("cbs", m.cbs));
            archive(::cereal::make_nvp("color_aware_mode", m.color_aware_mode));
            archive(::cereal::make_nvp("meter_mode", m.meter_mode));
            archive(::cereal::make_nvp("meter_count_mode", m.meter_count_mode));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_block_meter_profile_result_t& m) {
            archive(::cereal::make_nvp("ebs", m.ebs));
            archive(::cereal::make_nvp("cbs", m.cbs));
            archive(::cereal::make_nvp("color_aware_mode", m.color_aware_mode));
            archive(::cereal::make_nvp("meter_mode", m.meter_mode));
            archive(::cereal::make_nvp("meter_count_mode", m.meter_count_mode));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_block_meter_profile_result_t& m)
{
    serializer_class<npl_rx_meter_block_meter_profile_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_block_meter_profile_result_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_block_meter_profile_result_t& m)
{
    serializer_class<npl_rx_meter_block_meter_profile_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_block_meter_profile_result_t&);



template<>
class serializer_class<npl_rx_meter_block_meter_shaper_configuration_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_block_meter_shaper_configuration_result_t& m) {
            archive(::cereal::make_nvp("eir_weight", m.eir_weight));
            archive(::cereal::make_nvp("cir_weight", m.cir_weight));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_block_meter_shaper_configuration_result_t& m) {
            archive(::cereal::make_nvp("eir_weight", m.eir_weight));
            archive(::cereal::make_nvp("cir_weight", m.cir_weight));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_block_meter_shaper_configuration_result_t& m)
{
    serializer_class<npl_rx_meter_block_meter_shaper_configuration_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_block_meter_shaper_configuration_result_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_block_meter_shaper_configuration_result_t& m)
{
    serializer_class<npl_rx_meter_block_meter_shaper_configuration_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_block_meter_shaper_configuration_result_t&);



template<>
class serializer_class<npl_rx_meter_distributed_meter_profile_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_distributed_meter_profile_result_t& m) {
        uint64_t m_is_distributed_meter = m.is_distributed_meter;
        uint64_t m_tx_message_template_index = m.tx_message_template_index;
        uint64_t m_excess_token_release_thr = m.excess_token_release_thr;
        uint64_t m_excess_token_grant_thr = m.excess_token_grant_thr;
        uint64_t m_committed_token_release_thr = m.committed_token_release_thr;
        uint64_t m_committed_token_grant_thr = m.committed_token_grant_thr;
        uint64_t m_is_cascade = m.is_cascade;
            archive(::cereal::make_nvp("is_distributed_meter", m_is_distributed_meter));
            archive(::cereal::make_nvp("tx_message_template_index", m_tx_message_template_index));
            archive(::cereal::make_nvp("excess_token_release_thr", m_excess_token_release_thr));
            archive(::cereal::make_nvp("excess_token_grant_thr", m_excess_token_grant_thr));
            archive(::cereal::make_nvp("committed_token_release_thr", m_committed_token_release_thr));
            archive(::cereal::make_nvp("committed_token_grant_thr", m_committed_token_grant_thr));
            archive(::cereal::make_nvp("is_cascade", m_is_cascade));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_distributed_meter_profile_result_t& m) {
        uint64_t m_is_distributed_meter;
        uint64_t m_tx_message_template_index;
        uint64_t m_excess_token_release_thr;
        uint64_t m_excess_token_grant_thr;
        uint64_t m_committed_token_release_thr;
        uint64_t m_committed_token_grant_thr;
        uint64_t m_is_cascade;
            archive(::cereal::make_nvp("is_distributed_meter", m_is_distributed_meter));
            archive(::cereal::make_nvp("tx_message_template_index", m_tx_message_template_index));
            archive(::cereal::make_nvp("excess_token_release_thr", m_excess_token_release_thr));
            archive(::cereal::make_nvp("excess_token_grant_thr", m_excess_token_grant_thr));
            archive(::cereal::make_nvp("committed_token_release_thr", m_committed_token_release_thr));
            archive(::cereal::make_nvp("committed_token_grant_thr", m_committed_token_grant_thr));
            archive(::cereal::make_nvp("is_cascade", m_is_cascade));
        m.is_distributed_meter = m_is_distributed_meter;
        m.tx_message_template_index = m_tx_message_template_index;
        m.excess_token_release_thr = m_excess_token_release_thr;
        m.excess_token_grant_thr = m_excess_token_grant_thr;
        m.committed_token_release_thr = m_committed_token_release_thr;
        m.committed_token_grant_thr = m_committed_token_grant_thr;
        m.is_cascade = m_is_cascade;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_distributed_meter_profile_result_t& m)
{
    serializer_class<npl_rx_meter_distributed_meter_profile_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_distributed_meter_profile_result_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_distributed_meter_profile_result_t& m)
{
    serializer_class<npl_rx_meter_distributed_meter_profile_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_distributed_meter_profile_result_t&);



template<>
class serializer_class<npl_rx_meter_exact_meter_decision_mapping_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_exact_meter_decision_mapping_result_t& m) {
        uint64_t m_congestion_experienced = m.congestion_experienced;
        uint64_t m_cgm_rx_dp = m.cgm_rx_dp;
        uint64_t m_meter_drop = m.meter_drop;
            archive(::cereal::make_nvp("congestion_experienced", m_congestion_experienced));
            archive(::cereal::make_nvp("rx_counter_color", m.rx_counter_color));
            archive(::cereal::make_nvp("outgoing_color", m.outgoing_color));
            archive(::cereal::make_nvp("cgm_rx_dp", m_cgm_rx_dp));
            archive(::cereal::make_nvp("meter_drop", m_meter_drop));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_exact_meter_decision_mapping_result_t& m) {
        uint64_t m_congestion_experienced;
        uint64_t m_cgm_rx_dp;
        uint64_t m_meter_drop;
            archive(::cereal::make_nvp("congestion_experienced", m_congestion_experienced));
            archive(::cereal::make_nvp("rx_counter_color", m.rx_counter_color));
            archive(::cereal::make_nvp("outgoing_color", m.outgoing_color));
            archive(::cereal::make_nvp("cgm_rx_dp", m_cgm_rx_dp));
            archive(::cereal::make_nvp("meter_drop", m_meter_drop));
        m.congestion_experienced = m_congestion_experienced;
        m.cgm_rx_dp = m_cgm_rx_dp;
        m.meter_drop = m_meter_drop;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_exact_meter_decision_mapping_result_t& m)
{
    serializer_class<npl_rx_meter_exact_meter_decision_mapping_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_exact_meter_decision_mapping_result_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_exact_meter_decision_mapping_result_t& m)
{
    serializer_class<npl_rx_meter_exact_meter_decision_mapping_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_exact_meter_decision_mapping_result_t&);



template<>
class serializer_class<npl_rx_meter_meter_profile_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_meter_profile_result_t& m) {
            archive(::cereal::make_nvp("ebs", m.ebs));
            archive(::cereal::make_nvp("cbs", m.cbs));
            archive(::cereal::make_nvp("color_aware_mode", m.color_aware_mode));
            archive(::cereal::make_nvp("meter_mode", m.meter_mode));
            archive(::cereal::make_nvp("meter_count_mode", m.meter_count_mode));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_meter_profile_result_t& m) {
            archive(::cereal::make_nvp("ebs", m.ebs));
            archive(::cereal::make_nvp("cbs", m.cbs));
            archive(::cereal::make_nvp("color_aware_mode", m.color_aware_mode));
            archive(::cereal::make_nvp("meter_mode", m.meter_mode));
            archive(::cereal::make_nvp("meter_count_mode", m.meter_count_mode));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_meter_profile_result_t& m)
{
    serializer_class<npl_rx_meter_meter_profile_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_meter_profile_result_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_meter_profile_result_t& m)
{
    serializer_class<npl_rx_meter_meter_profile_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_meter_profile_result_t&);



template<>
class serializer_class<npl_rx_meter_meter_shaper_configuration_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_meter_shaper_configuration_result_t& m) {
            archive(::cereal::make_nvp("eir_weight", m.eir_weight));
            archive(::cereal::make_nvp("cir_weight", m.cir_weight));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_meter_shaper_configuration_result_t& m) {
            archive(::cereal::make_nvp("eir_weight", m.eir_weight));
            archive(::cereal::make_nvp("cir_weight", m.cir_weight));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_meter_shaper_configuration_result_t& m)
{
    serializer_class<npl_rx_meter_meter_shaper_configuration_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_meter_shaper_configuration_result_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_meter_shaper_configuration_result_t& m)
{
    serializer_class<npl_rx_meter_meter_shaper_configuration_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_meter_shaper_configuration_result_t&);



template<>
class serializer_class<npl_rx_meter_meters_attribute_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_meters_attribute_result_t& m) {
        uint64_t m_commited_coupling_flag = m.commited_coupling_flag;
            archive(::cereal::make_nvp("meter_decision_mapping_profile", m.meter_decision_mapping_profile));
            archive(::cereal::make_nvp("commited_coupling_flag", m_commited_coupling_flag));
            archive(::cereal::make_nvp("profile", m.profile));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_meters_attribute_result_t& m) {
        uint64_t m_commited_coupling_flag;
            archive(::cereal::make_nvp("meter_decision_mapping_profile", m.meter_decision_mapping_profile));
            archive(::cereal::make_nvp("commited_coupling_flag", m_commited_coupling_flag));
            archive(::cereal::make_nvp("profile", m.profile));
        m.commited_coupling_flag = m_commited_coupling_flag;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_meters_attribute_result_t& m)
{
    serializer_class<npl_rx_meter_meters_attribute_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_meters_attribute_result_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_meters_attribute_result_t& m)
{
    serializer_class<npl_rx_meter_meters_attribute_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_meters_attribute_result_t&);



template<>
class serializer_class<npl_rx_meter_rate_limiter_shaper_configuration_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_rate_limiter_shaper_configuration_result_t& m) {
            archive(::cereal::make_nvp("cir_weight", m.cir_weight));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_rate_limiter_shaper_configuration_result_t& m) {
            archive(::cereal::make_nvp("cir_weight", m.cir_weight));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_rate_limiter_shaper_configuration_result_t& m)
{
    serializer_class<npl_rx_meter_rate_limiter_shaper_configuration_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_rate_limiter_shaper_configuration_result_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_rate_limiter_shaper_configuration_result_t& m)
{
    serializer_class<npl_rx_meter_rate_limiter_shaper_configuration_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_rate_limiter_shaper_configuration_result_t&);



template<>
class serializer_class<npl_rx_meter_stat_meter_decision_mapping_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_stat_meter_decision_mapping_result_t& m) {
        uint64_t m_congestion_experienced = m.congestion_experienced;
        uint64_t m_cgm_rx_dp = m.cgm_rx_dp;
        uint64_t m_meter_drop = m.meter_drop;
            archive(::cereal::make_nvp("congestion_experienced", m_congestion_experienced));
            archive(::cereal::make_nvp("rx_counter_color", m.rx_counter_color));
            archive(::cereal::make_nvp("outgoing_color", m.outgoing_color));
            archive(::cereal::make_nvp("cgm_rx_dp", m_cgm_rx_dp));
            archive(::cereal::make_nvp("meter_drop", m_meter_drop));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_stat_meter_decision_mapping_result_t& m) {
        uint64_t m_congestion_experienced;
        uint64_t m_cgm_rx_dp;
        uint64_t m_meter_drop;
            archive(::cereal::make_nvp("congestion_experienced", m_congestion_experienced));
            archive(::cereal::make_nvp("rx_counter_color", m.rx_counter_color));
            archive(::cereal::make_nvp("outgoing_color", m.outgoing_color));
            archive(::cereal::make_nvp("cgm_rx_dp", m_cgm_rx_dp));
            archive(::cereal::make_nvp("meter_drop", m_meter_drop));
        m.congestion_experienced = m_congestion_experienced;
        m.cgm_rx_dp = m_cgm_rx_dp;
        m.meter_drop = m_meter_drop;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_stat_meter_decision_mapping_result_t& m)
{
    serializer_class<npl_rx_meter_stat_meter_decision_mapping_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_stat_meter_decision_mapping_result_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_stat_meter_decision_mapping_result_t& m)
{
    serializer_class<npl_rx_meter_stat_meter_decision_mapping_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_stat_meter_decision_mapping_result_t&);



template<>
class serializer_class<npl_rx_obm_punt_src_and_code_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_obm_punt_src_and_code_data_t& m) {
            archive(::cereal::make_nvp("phb", m.phb));
            archive(::cereal::make_nvp("meter_ptr", m.meter_ptr));
            archive(::cereal::make_nvp("cntr_ptr", m.cntr_ptr));
            archive(::cereal::make_nvp("punt_bvn_dest", m.punt_bvn_dest));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_obm_punt_src_and_code_data_t& m) {
            archive(::cereal::make_nvp("phb", m.phb));
            archive(::cereal::make_nvp("meter_ptr", m.meter_ptr));
            archive(::cereal::make_nvp("cntr_ptr", m.cntr_ptr));
            archive(::cereal::make_nvp("punt_bvn_dest", m.punt_bvn_dest));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_obm_punt_src_and_code_data_t& m)
{
    serializer_class<npl_rx_obm_punt_src_and_code_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_obm_punt_src_and_code_data_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_obm_punt_src_and_code_data_t& m)
{
    serializer_class<npl_rx_obm_punt_src_and_code_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_obm_punt_src_and_code_data_t&);



template<>
class serializer_class<npl_rxpdr_dsp_lookup_table_entry_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rxpdr_dsp_lookup_table_entry_t& m) {
        uint64_t m_tc_map_profile = m.tc_map_profile;
        uint64_t m_base_voq_num = m.base_voq_num;
        uint64_t m_dest_device = m.dest_device;
            archive(::cereal::make_nvp("tc_map_profile", m_tc_map_profile));
            archive(::cereal::make_nvp("base_voq_num", m_base_voq_num));
            archive(::cereal::make_nvp("dest_device", m_dest_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rxpdr_dsp_lookup_table_entry_t& m) {
        uint64_t m_tc_map_profile;
        uint64_t m_base_voq_num;
        uint64_t m_dest_device;
            archive(::cereal::make_nvp("tc_map_profile", m_tc_map_profile));
            archive(::cereal::make_nvp("base_voq_num", m_base_voq_num));
            archive(::cereal::make_nvp("dest_device", m_dest_device));
        m.tc_map_profile = m_tc_map_profile;
        m.base_voq_num = m_base_voq_num;
        m.dest_device = m_dest_device;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rxpdr_dsp_lookup_table_entry_t& m)
{
    serializer_class<npl_rxpdr_dsp_lookup_table_entry_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rxpdr_dsp_lookup_table_entry_t&);

template <class Archive>
void
load(Archive& archive, npl_rxpdr_dsp_lookup_table_entry_t& m)
{
    serializer_class<npl_rxpdr_dsp_lookup_table_entry_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rxpdr_dsp_lookup_table_entry_t&);



template<>
class serializer_class<npl_rxpdr_dsp_tc_map_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rxpdr_dsp_tc_map_result_t& m) {
        uint64_t m_is_flb = m.is_flb;
        uint64_t m_tc_offset = m.tc_offset;
            archive(::cereal::make_nvp("is_flb", m_is_flb));
            archive(::cereal::make_nvp("tc_offset", m_tc_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rxpdr_dsp_tc_map_result_t& m) {
        uint64_t m_is_flb;
        uint64_t m_tc_offset;
            archive(::cereal::make_nvp("is_flb", m_is_flb));
            archive(::cereal::make_nvp("tc_offset", m_tc_offset));
        m.is_flb = m_is_flb;
        m.tc_offset = m_tc_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rxpdr_dsp_tc_map_result_t& m)
{
    serializer_class<npl_rxpdr_dsp_tc_map_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rxpdr_dsp_tc_map_result_t&);

template <class Archive>
void
load(Archive& archive, npl_rxpdr_dsp_tc_map_result_t& m)
{
    serializer_class<npl_rxpdr_dsp_tc_map_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rxpdr_dsp_tc_map_result_t&);



template<>
class serializer_class<npl_rxpdr_ibm_tc_map_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rxpdr_ibm_tc_map_result_t& m) {
        uint64_t m_is_flb = m.is_flb;
        uint64_t m_tc_offset = m.tc_offset;
            archive(::cereal::make_nvp("is_flb", m_is_flb));
            archive(::cereal::make_nvp("tc_offset", m_tc_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rxpdr_ibm_tc_map_result_t& m) {
        uint64_t m_is_flb;
        uint64_t m_tc_offset;
            archive(::cereal::make_nvp("is_flb", m_is_flb));
            archive(::cereal::make_nvp("tc_offset", m_tc_offset));
        m.is_flb = m_is_flb;
        m.tc_offset = m_tc_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rxpdr_ibm_tc_map_result_t& m)
{
    serializer_class<npl_rxpdr_ibm_tc_map_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rxpdr_ibm_tc_map_result_t&);

template <class Archive>
void
load(Archive& archive, npl_rxpdr_ibm_tc_map_result_t& m)
{
    serializer_class<npl_rxpdr_ibm_tc_map_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rxpdr_ibm_tc_map_result_t&);



template<>
class serializer_class<npl_scanner_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_scanner_id_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_scanner_id_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_scanner_id_t& m)
{
    serializer_class<npl_scanner_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_scanner_id_t&);

template <class Archive>
void
load(Archive& archive, npl_scanner_id_t& m)
{
    serializer_class<npl_scanner_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_scanner_id_t&);



template<>
class serializer_class<npl_sec_acl_attributes_t_anonymous_union_slp_dlp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sec_acl_attributes_t_anonymous_union_slp_dlp_t& m) {
        uint64_t m_global_dlp_id = m.global_dlp_id;
        uint64_t m_global_slp_id = m.global_slp_id;
        uint64_t m_is_l2 = m.is_l2;
            archive(::cereal::make_nvp("global_dlp_id", m_global_dlp_id));
            archive(::cereal::make_nvp("global_slp_id", m_global_slp_id));
            archive(::cereal::make_nvp("is_l2", m_is_l2));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sec_acl_attributes_t_anonymous_union_slp_dlp_t& m) {
        uint64_t m_global_dlp_id;
        uint64_t m_global_slp_id;
        uint64_t m_is_l2;
            archive(::cereal::make_nvp("global_dlp_id", m_global_dlp_id));
            archive(::cereal::make_nvp("global_slp_id", m_global_slp_id));
            archive(::cereal::make_nvp("is_l2", m_is_l2));
        m.global_dlp_id = m_global_dlp_id;
        m.global_slp_id = m_global_slp_id;
        m.is_l2 = m_is_l2;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sec_acl_attributes_t_anonymous_union_slp_dlp_t& m)
{
    serializer_class<npl_sec_acl_attributes_t_anonymous_union_slp_dlp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sec_acl_attributes_t_anonymous_union_slp_dlp_t&);

template <class Archive>
void
load(Archive& archive, npl_sec_acl_attributes_t_anonymous_union_slp_dlp_t& m)
{
    serializer_class<npl_sec_acl_attributes_t_anonymous_union_slp_dlp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sec_acl_attributes_t_anonymous_union_slp_dlp_t&);



template<>
class serializer_class<npl_sec_acl_ids_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sec_acl_ids_t& m) {
        uint64_t m_acl_v4_id = m.acl_v4_id;
        uint64_t m_acl_v6_id = m.acl_v6_id;
            archive(::cereal::make_nvp("acl_v4_id", m_acl_v4_id));
            archive(::cereal::make_nvp("acl_v6_id", m_acl_v6_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sec_acl_ids_t& m) {
        uint64_t m_acl_v4_id;
        uint64_t m_acl_v6_id;
            archive(::cereal::make_nvp("acl_v4_id", m_acl_v4_id));
            archive(::cereal::make_nvp("acl_v6_id", m_acl_v6_id));
        m.acl_v4_id = m_acl_v4_id;
        m.acl_v6_id = m_acl_v6_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sec_acl_ids_t& m)
{
    serializer_class<npl_sec_acl_ids_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sec_acl_ids_t&);

template <class Archive>
void
load(Archive& archive, npl_sec_acl_ids_t& m)
{
    serializer_class<npl_sec_acl_ids_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sec_acl_ids_t&);



template<>
class serializer_class<npl_select_macros_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_select_macros_t& m) {
        uint64_t m_npe_macro_offset = m.npe_macro_offset;
        uint64_t m_fi_macro_offset = m.fi_macro_offset;
            archive(::cereal::make_nvp("npe_macro_offset", m_npe_macro_offset));
            archive(::cereal::make_nvp("fi_macro_offset", m_fi_macro_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_select_macros_t& m) {
        uint64_t m_npe_macro_offset;
        uint64_t m_fi_macro_offset;
            archive(::cereal::make_nvp("npe_macro_offset", m_npe_macro_offset));
            archive(::cereal::make_nvp("fi_macro_offset", m_fi_macro_offset));
        m.npe_macro_offset = m_npe_macro_offset;
        m.fi_macro_offset = m_fi_macro_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_select_macros_t& m)
{
    serializer_class<npl_select_macros_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_select_macros_t&);

template <class Archive>
void
load(Archive& archive, npl_select_macros_t& m)
{
    serializer_class<npl_select_macros_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_select_macros_t&);



template<>
class serializer_class<npl_service_flags_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_flags_t& m) {
        uint64_t m_push_entropy_label = m.push_entropy_label;
        uint64_t m_add_ipv6_explicit_null = m.add_ipv6_explicit_null;
            archive(::cereal::make_nvp("push_entropy_label", m_push_entropy_label));
            archive(::cereal::make_nvp("add_ipv6_explicit_null", m_add_ipv6_explicit_null));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_flags_t& m) {
        uint64_t m_push_entropy_label;
        uint64_t m_add_ipv6_explicit_null;
            archive(::cereal::make_nvp("push_entropy_label", m_push_entropy_label));
            archive(::cereal::make_nvp("add_ipv6_explicit_null", m_add_ipv6_explicit_null));
        m.push_entropy_label = m_push_entropy_label;
        m.add_ipv6_explicit_null = m_add_ipv6_explicit_null;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_flags_t& m)
{
    serializer_class<npl_service_flags_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_flags_t&);

template <class Archive>
void
load(Archive& archive, npl_service_flags_t& m)
{
    serializer_class<npl_service_flags_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_flags_t&);



template<>
class serializer_class<npl_sgacl_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgacl_payload_t& m) {
        uint64_t m_drop = m.drop;
            archive(::cereal::make_nvp("drop", m_drop));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgacl_payload_t& m) {
        uint64_t m_drop;
            archive(::cereal::make_nvp("drop", m_drop));
        m.drop = m_drop;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgacl_payload_t& m)
{
    serializer_class<npl_sgacl_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgacl_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_sgacl_payload_t& m)
{
    serializer_class<npl_sgacl_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgacl_payload_t&);



template<>
class serializer_class<npl_sip_ip_tunnel_termination_attr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sip_ip_tunnel_termination_attr_t& m) {
        uint64_t m_my_dip_index = m.my_dip_index;
        uint64_t m_vxlan_tunnel_loopback = m.vxlan_tunnel_loopback;
            archive(::cereal::make_nvp("my_dip_index", m_my_dip_index));
            archive(::cereal::make_nvp("vxlan_tunnel_loopback", m_vxlan_tunnel_loopback));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sip_ip_tunnel_termination_attr_t& m) {
        uint64_t m_my_dip_index;
        uint64_t m_vxlan_tunnel_loopback;
            archive(::cereal::make_nvp("my_dip_index", m_my_dip_index));
            archive(::cereal::make_nvp("vxlan_tunnel_loopback", m_vxlan_tunnel_loopback));
        m.my_dip_index = m_my_dip_index;
        m.vxlan_tunnel_loopback = m_vxlan_tunnel_loopback;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sip_ip_tunnel_termination_attr_t& m)
{
    serializer_class<npl_sip_ip_tunnel_termination_attr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sip_ip_tunnel_termination_attr_t&);

template <class Archive>
void
load(Archive& archive, npl_sip_ip_tunnel_termination_attr_t& m)
{
    serializer_class<npl_sip_ip_tunnel_termination_attr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sip_ip_tunnel_termination_attr_t&);



template<>
class serializer_class<npl_slp_based_fwd_and_per_vrf_mpls_fwd_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_slp_based_fwd_and_per_vrf_mpls_fwd_t& m) {
        uint64_t m_slp_based_forwarding = m.slp_based_forwarding;
        uint64_t m_per_vrf_mpls_fwd = m.per_vrf_mpls_fwd;
            archive(::cereal::make_nvp("slp_based_forwarding", m_slp_based_forwarding));
            archive(::cereal::make_nvp("per_vrf_mpls_fwd", m_per_vrf_mpls_fwd));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_slp_based_fwd_and_per_vrf_mpls_fwd_t& m) {
        uint64_t m_slp_based_forwarding;
        uint64_t m_per_vrf_mpls_fwd;
            archive(::cereal::make_nvp("slp_based_forwarding", m_slp_based_forwarding));
            archive(::cereal::make_nvp("per_vrf_mpls_fwd", m_per_vrf_mpls_fwd));
        m.slp_based_forwarding = m_slp_based_forwarding;
        m.per_vrf_mpls_fwd = m_per_vrf_mpls_fwd;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_slp_based_fwd_and_per_vrf_mpls_fwd_t& m)
{
    serializer_class<npl_slp_based_fwd_and_per_vrf_mpls_fwd_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_slp_based_fwd_and_per_vrf_mpls_fwd_t&);

template <class Archive>
void
load(Archive& archive, npl_slp_based_fwd_and_per_vrf_mpls_fwd_t& m)
{
    serializer_class<npl_slp_based_fwd_and_per_vrf_mpls_fwd_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_slp_based_fwd_and_per_vrf_mpls_fwd_t&);



template<>
class serializer_class<npl_slp_fwd_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_slp_fwd_result_t& m) {
        uint64_t m_mpls_label_present = m.mpls_label_present;
        uint64_t m_mpls_label = m.mpls_label;
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("mpls_label_present", m_mpls_label_present));
            archive(::cereal::make_nvp("mpls_label", m_mpls_label));
            archive(::cereal::make_nvp("destination", m_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_slp_fwd_result_t& m) {
        uint64_t m_mpls_label_present;
        uint64_t m_mpls_label;
        uint64_t m_destination;
            archive(::cereal::make_nvp("mpls_label_present", m_mpls_label_present));
            archive(::cereal::make_nvp("mpls_label", m_mpls_label));
            archive(::cereal::make_nvp("destination", m_destination));
        m.mpls_label_present = m_mpls_label_present;
        m.mpls_label = m_mpls_label;
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_slp_fwd_result_t& m)
{
    serializer_class<npl_slp_fwd_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_slp_fwd_result_t&);

template <class Archive>
void
load(Archive& archive, npl_slp_fwd_result_t& m)
{
    serializer_class<npl_slp_fwd_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_slp_fwd_result_t&);



template<>
class serializer_class<npl_snoop_code_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_snoop_code_t& m) {
        uint64_t m_val = m.val;
            archive(::cereal::make_nvp("val", m_val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_snoop_code_t& m) {
        uint64_t m_val;
            archive(::cereal::make_nvp("val", m_val));
        m.val = m_val;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_snoop_code_t& m)
{
    serializer_class<npl_snoop_code_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_snoop_code_t&);

template <class Archive>
void
load(Archive& archive, npl_snoop_code_t& m)
{
    serializer_class<npl_snoop_code_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_snoop_code_t&);



template<>
class serializer_class<npl_soft_lb_wa_enable_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_soft_lb_wa_enable_t& m) {
        uint64_t m_is_next_header_gre = m.is_next_header_gre;
        uint64_t m_soft_lb_enable = m.soft_lb_enable;
            archive(::cereal::make_nvp("is_next_header_gre", m_is_next_header_gre));
            archive(::cereal::make_nvp("soft_lb_enable", m_soft_lb_enable));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_soft_lb_wa_enable_t& m) {
        uint64_t m_is_next_header_gre;
        uint64_t m_soft_lb_enable;
            archive(::cereal::make_nvp("is_next_header_gre", m_is_next_header_gre));
            archive(::cereal::make_nvp("soft_lb_enable", m_soft_lb_enable));
        m.is_next_header_gre = m_is_next_header_gre;
        m.soft_lb_enable = m_soft_lb_enable;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_soft_lb_wa_enable_t& m)
{
    serializer_class<npl_soft_lb_wa_enable_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_soft_lb_wa_enable_t&);

template <class Archive>
void
load(Archive& archive, npl_soft_lb_wa_enable_t& m)
{
    serializer_class<npl_soft_lb_wa_enable_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_soft_lb_wa_enable_t&);



template<>
class serializer_class<npl_source_if_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_source_if_t& m) {
        uint64_t m_ifg = m.ifg;
        uint64_t m_pif = m.pif;
            archive(::cereal::make_nvp("ifg", m_ifg));
            archive(::cereal::make_nvp("pif", m_pif));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_source_if_t& m) {
        uint64_t m_ifg;
        uint64_t m_pif;
            archive(::cereal::make_nvp("ifg", m_ifg));
            archive(::cereal::make_nvp("pif", m_pif));
        m.ifg = m_ifg;
        m.pif = m_pif;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_source_if_t& m)
{
    serializer_class<npl_source_if_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_source_if_t&);

template <class Archive>
void
load(Archive& archive, npl_source_if_t& m)
{
    serializer_class<npl_source_if_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_source_if_t&);



template<>
class serializer_class<npl_split_voq_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_split_voq_t& m) {
        uint64_t m_split_voq_enabled = m.split_voq_enabled;
        uint64_t m_source_group_offset = m.source_group_offset;
            archive(::cereal::make_nvp("split_voq_enabled", m_split_voq_enabled));
            archive(::cereal::make_nvp("source_group_offset", m_source_group_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_split_voq_t& m) {
        uint64_t m_split_voq_enabled;
        uint64_t m_source_group_offset;
            archive(::cereal::make_nvp("split_voq_enabled", m_split_voq_enabled));
            archive(::cereal::make_nvp("source_group_offset", m_source_group_offset));
        m.split_voq_enabled = m_split_voq_enabled;
        m.source_group_offset = m_source_group_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_split_voq_t& m)
{
    serializer_class<npl_split_voq_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_split_voq_t&);

template <class Archive>
void
load(Archive& archive, npl_split_voq_t& m)
{
    serializer_class<npl_split_voq_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_split_voq_t&);



template<>
class serializer_class<npl_sport_or_l4_protocol_t_anonymous_union_sport_or_l4_protocol_type_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sport_or_l4_protocol_t_anonymous_union_sport_or_l4_protocol_type_t& m) {
        uint64_t m_src_port = m.src_port;
        uint64_t m_ipv4_protocol = m.ipv4_protocol;
        uint64_t m_ipv6_next_header = m.ipv6_next_header;
            archive(::cereal::make_nvp("src_port", m_src_port));
            archive(::cereal::make_nvp("ipv4_protocol", m_ipv4_protocol));
            archive(::cereal::make_nvp("ipv6_next_header", m_ipv6_next_header));
            archive(::cereal::make_nvp("icmp_type_code", m.icmp_type_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sport_or_l4_protocol_t_anonymous_union_sport_or_l4_protocol_type_t& m) {
        uint64_t m_src_port;
        uint64_t m_ipv4_protocol;
        uint64_t m_ipv6_next_header;
            archive(::cereal::make_nvp("src_port", m_src_port));
            archive(::cereal::make_nvp("ipv4_protocol", m_ipv4_protocol));
            archive(::cereal::make_nvp("ipv6_next_header", m_ipv6_next_header));
            archive(::cereal::make_nvp("icmp_type_code", m.icmp_type_code));
        m.src_port = m_src_port;
        m.ipv4_protocol = m_ipv4_protocol;
        m.ipv6_next_header = m_ipv6_next_header;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sport_or_l4_protocol_t_anonymous_union_sport_or_l4_protocol_type_t& m)
{
    serializer_class<npl_sport_or_l4_protocol_t_anonymous_union_sport_or_l4_protocol_type_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sport_or_l4_protocol_t_anonymous_union_sport_or_l4_protocol_type_t&);

template <class Archive>
void
load(Archive& archive, npl_sport_or_l4_protocol_t_anonymous_union_sport_or_l4_protocol_type_t& m)
{
    serializer_class<npl_sport_or_l4_protocol_t_anonymous_union_sport_or_l4_protocol_type_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sport_or_l4_protocol_t_anonymous_union_sport_or_l4_protocol_type_t&);



template<>
class serializer_class<npl_stage2_lb_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_lb_table_result_t& m) {
            archive(::cereal::make_nvp("stage3_nh_11b_asbr", m.stage3_nh_11b_asbr));
            archive(::cereal::make_nvp("stage2_p_nh_11b_asbr", m.stage2_p_nh_11b_asbr));
            archive(::cereal::make_nvp("stage3_nh_te_tunnel14b", m.stage3_nh_te_tunnel14b));
            archive(::cereal::make_nvp("stage3_nh_te_tunnel14b1", m.stage3_nh_te_tunnel14b1));
            archive(::cereal::make_nvp("stage2_p_nh_te_tunnel14b", m.stage2_p_nh_te_tunnel14b));
            archive(::cereal::make_nvp("stage2_p_nh_te_tunnel14b1", m.stage2_p_nh_te_tunnel14b1));
            archive(::cereal::make_nvp("destination", m.destination));
            archive(::cereal::make_nvp("destination1", m.destination1));
            archive(::cereal::make_nvp("raw", m.raw));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_lb_table_result_t& m) {
            archive(::cereal::make_nvp("stage3_nh_11b_asbr", m.stage3_nh_11b_asbr));
            archive(::cereal::make_nvp("stage2_p_nh_11b_asbr", m.stage2_p_nh_11b_asbr));
            archive(::cereal::make_nvp("stage3_nh_te_tunnel14b", m.stage3_nh_te_tunnel14b));
            archive(::cereal::make_nvp("stage3_nh_te_tunnel14b1", m.stage3_nh_te_tunnel14b1));
            archive(::cereal::make_nvp("stage2_p_nh_te_tunnel14b", m.stage2_p_nh_te_tunnel14b));
            archive(::cereal::make_nvp("stage2_p_nh_te_tunnel14b1", m.stage2_p_nh_te_tunnel14b1));
            archive(::cereal::make_nvp("destination", m.destination));
            archive(::cereal::make_nvp("destination1", m.destination1));
            archive(::cereal::make_nvp("raw", m.raw));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_lb_table_result_t& m)
{
    serializer_class<npl_stage2_lb_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_lb_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_lb_table_result_t& m)
{
    serializer_class<npl_stage2_lb_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_lb_table_result_t&);



template<>
class serializer_class<npl_stage3_lb_bvn_l3_dlp_dlp_attr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_lb_bvn_l3_dlp_dlp_attr_t& m) {
        uint64_t m_dlp_attr = m.dlp_attr;
        uint64_t m_l3_dlp = m.l3_dlp;
        uint64_t m_bvn = m.bvn;
            archive(::cereal::make_nvp("dlp_attr", m_dlp_attr));
            archive(::cereal::make_nvp("l3_dlp", m_l3_dlp));
            archive(::cereal::make_nvp("bvn", m_bvn));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_lb_bvn_l3_dlp_dlp_attr_t& m) {
        uint64_t m_dlp_attr;
        uint64_t m_l3_dlp;
        uint64_t m_bvn;
            archive(::cereal::make_nvp("dlp_attr", m_dlp_attr));
            archive(::cereal::make_nvp("l3_dlp", m_l3_dlp));
            archive(::cereal::make_nvp("bvn", m_bvn));
            archive(::cereal::make_nvp("type", m.type));
        m.dlp_attr = m_dlp_attr;
        m.l3_dlp = m_l3_dlp;
        m.bvn = m_bvn;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_lb_bvn_l3_dlp_dlp_attr_t& m)
{
    serializer_class<npl_stage3_lb_bvn_l3_dlp_dlp_attr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_lb_bvn_l3_dlp_dlp_attr_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_lb_bvn_l3_dlp_dlp_attr_t& m)
{
    serializer_class<npl_stage3_lb_bvn_l3_dlp_dlp_attr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_lb_bvn_l3_dlp_dlp_attr_t&);



template<>
class serializer_class<npl_stage3_lb_destination_l3_dlp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_lb_destination_l3_dlp_t& m) {
        uint64_t m_l3_dlp = m.l3_dlp;
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("l3_dlp", m_l3_dlp));
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_lb_destination_l3_dlp_t& m) {
        uint64_t m_l3_dlp;
        uint64_t m_destination;
            archive(::cereal::make_nvp("l3_dlp", m_l3_dlp));
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
        m.l3_dlp = m_l3_dlp;
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_lb_destination_l3_dlp_t& m)
{
    serializer_class<npl_stage3_lb_destination_l3_dlp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_lb_destination_l3_dlp_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_lb_destination_l3_dlp_t& m)
{
    serializer_class<npl_stage3_lb_destination_l3_dlp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_lb_destination_l3_dlp_t&);



template<>
class serializer_class<npl_stage3_lb_dsp_l3_dlp_dlp_attr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_lb_dsp_l3_dlp_dlp_attr_t& m) {
        uint64_t m_dlp_attr = m.dlp_attr;
        uint64_t m_l3_dlp = m.l3_dlp;
        uint64_t m_dsp = m.dsp;
            archive(::cereal::make_nvp("dlp_attr", m_dlp_attr));
            archive(::cereal::make_nvp("l3_dlp", m_l3_dlp));
            archive(::cereal::make_nvp("dsp", m_dsp));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_lb_dsp_l3_dlp_dlp_attr_t& m) {
        uint64_t m_dlp_attr;
        uint64_t m_l3_dlp;
        uint64_t m_dsp;
            archive(::cereal::make_nvp("dlp_attr", m_dlp_attr));
            archive(::cereal::make_nvp("l3_dlp", m_l3_dlp));
            archive(::cereal::make_nvp("dsp", m_dsp));
            archive(::cereal::make_nvp("type", m.type));
        m.dlp_attr = m_dlp_attr;
        m.l3_dlp = m_l3_dlp;
        m.dsp = m_dsp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_lb_dsp_l3_dlp_dlp_attr_t& m)
{
    serializer_class<npl_stage3_lb_dsp_l3_dlp_dlp_attr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_lb_dsp_l3_dlp_dlp_attr_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_lb_dsp_l3_dlp_dlp_attr_t& m)
{
    serializer_class<npl_stage3_lb_dsp_l3_dlp_dlp_attr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_lb_dsp_l3_dlp_dlp_attr_t&);



template<>
class serializer_class<npl_stage3_lb_dspa_l3_dlp_dlp_attr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_lb_dspa_l3_dlp_dlp_attr_t& m) {
        uint64_t m_dlp_attr = m.dlp_attr;
        uint64_t m_l3_dlp = m.l3_dlp;
        uint64_t m_dspa = m.dspa;
            archive(::cereal::make_nvp("dlp_attr", m_dlp_attr));
            archive(::cereal::make_nvp("l3_dlp", m_l3_dlp));
            archive(::cereal::make_nvp("dspa", m_dspa));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_lb_dspa_l3_dlp_dlp_attr_t& m) {
        uint64_t m_dlp_attr;
        uint64_t m_l3_dlp;
        uint64_t m_dspa;
            archive(::cereal::make_nvp("dlp_attr", m_dlp_attr));
            archive(::cereal::make_nvp("l3_dlp", m_l3_dlp));
            archive(::cereal::make_nvp("dspa", m_dspa));
            archive(::cereal::make_nvp("type", m.type));
        m.dlp_attr = m_dlp_attr;
        m.l3_dlp = m_l3_dlp;
        m.dspa = m_dspa;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_lb_dspa_l3_dlp_dlp_attr_t& m)
{
    serializer_class<npl_stage3_lb_dspa_l3_dlp_dlp_attr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_lb_dspa_l3_dlp_dlp_attr_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_lb_dspa_l3_dlp_dlp_attr_t& m)
{
    serializer_class<npl_stage3_lb_dspa_l3_dlp_dlp_attr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_lb_dspa_l3_dlp_dlp_attr_t&);



template<>
class serializer_class<npl_stage3_lb_raw_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_lb_raw_t& m) {
        uint64_t m_payload = m.payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_lb_raw_t& m) {
        uint64_t m_payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
        m.payload = m_payload;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_lb_raw_t& m)
{
    serializer_class<npl_stage3_lb_raw_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_lb_raw_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_lb_raw_t& m)
{
    serializer_class<npl_stage3_lb_raw_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_lb_raw_t&);



template<>
class serializer_class<npl_stage3_lb_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_lb_table_result_t& m) {
            archive(::cereal::make_nvp("bvn_l3_dlp_dlp_attr", m.bvn_l3_dlp_dlp_attr));
            archive(::cereal::make_nvp("dsp_l3_dlp_dlp_attr", m.dsp_l3_dlp_dlp_attr));
            archive(::cereal::make_nvp("dspa_l3_dlp_dlp_attr", m.dspa_l3_dlp_dlp_attr));
            archive(::cereal::make_nvp("destination_l3_dlp", m.destination_l3_dlp));
            archive(::cereal::make_nvp("raw", m.raw));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_lb_table_result_t& m) {
            archive(::cereal::make_nvp("bvn_l3_dlp_dlp_attr", m.bvn_l3_dlp_dlp_attr));
            archive(::cereal::make_nvp("dsp_l3_dlp_dlp_attr", m.dsp_l3_dlp_dlp_attr));
            archive(::cereal::make_nvp("dspa_l3_dlp_dlp_attr", m.dspa_l3_dlp_dlp_attr));
            archive(::cereal::make_nvp("destination_l3_dlp", m.destination_l3_dlp));
            archive(::cereal::make_nvp("raw", m.raw));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_lb_table_result_t& m)
{
    serializer_class<npl_stage3_lb_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_lb_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_lb_table_result_t& m)
{
    serializer_class<npl_stage3_lb_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_lb_table_result_t&);



template<>
class serializer_class<npl_stat_bank_index_len_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stat_bank_index_len_t& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stat_bank_index_len_t& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stat_bank_index_len_t& m)
{
    serializer_class<npl_stat_bank_index_len_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stat_bank_index_len_t&);

template <class Archive>
void
load(Archive& archive, npl_stat_bank_index_len_t& m)
{
    serializer_class<npl_stat_bank_index_len_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stat_bank_index_len_t&);



template<>
class serializer_class<npl_stat_meter_index_len_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stat_meter_index_len_t& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stat_meter_index_len_t& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stat_meter_index_len_t& m)
{
    serializer_class<npl_stat_meter_index_len_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stat_meter_index_len_t&);

template <class Archive>
void
load(Archive& archive, npl_stat_meter_index_len_t& m)
{
    serializer_class<npl_stat_meter_index_len_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stat_meter_index_len_t&);



template<>
class serializer_class<npl_std_ip_em_lpm_result_destination_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_std_ip_em_lpm_result_destination_t& m) {
            archive(::cereal::make_nvp("destination", m.destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_std_ip_em_lpm_result_destination_t& m) {
            archive(::cereal::make_nvp("destination", m.destination));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_std_ip_em_lpm_result_destination_t& m)
{
    serializer_class<npl_std_ip_em_lpm_result_destination_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_std_ip_em_lpm_result_destination_t&);

template <class Archive>
void
load(Archive& archive, npl_std_ip_em_lpm_result_destination_t& m)
{
    serializer_class<npl_std_ip_em_lpm_result_destination_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_std_ip_em_lpm_result_destination_t&);



template<>
class serializer_class<npl_std_ip_em_lpm_result_destination_with_default_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_std_ip_em_lpm_result_destination_with_default_t& m) {
        uint64_t m_is_default = m.is_default;
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("is_default", m_is_default));
            archive(::cereal::make_nvp("destination", m_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_std_ip_em_lpm_result_destination_with_default_t& m) {
        uint64_t m_is_default;
        uint64_t m_destination;
            archive(::cereal::make_nvp("is_default", m_is_default));
            archive(::cereal::make_nvp("destination", m_destination));
        m.is_default = m_is_default;
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_std_ip_em_lpm_result_destination_with_default_t& m)
{
    serializer_class<npl_std_ip_em_lpm_result_destination_with_default_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_std_ip_em_lpm_result_destination_with_default_t&);

template <class Archive>
void
load(Archive& archive, npl_std_ip_em_lpm_result_destination_with_default_t& m)
{
    serializer_class<npl_std_ip_em_lpm_result_destination_with_default_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_std_ip_em_lpm_result_destination_with_default_t&);



template<>
class serializer_class<npl_stop_on_step_and_next_stage_compressed_fields_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stop_on_step_and_next_stage_compressed_fields_t& m) {
        uint64_t m_stop_on_step = m.stop_on_step;
            archive(::cereal::make_nvp("next_rtf_stage", m.next_rtf_stage));
            archive(::cereal::make_nvp("stop_on_step", m_stop_on_step));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stop_on_step_and_next_stage_compressed_fields_t& m) {
        uint64_t m_stop_on_step;
            archive(::cereal::make_nvp("next_rtf_stage", m.next_rtf_stage));
            archive(::cereal::make_nvp("stop_on_step", m_stop_on_step));
        m.stop_on_step = m_stop_on_step;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stop_on_step_and_next_stage_compressed_fields_t& m)
{
    serializer_class<npl_stop_on_step_and_next_stage_compressed_fields_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stop_on_step_and_next_stage_compressed_fields_t&);

template <class Archive>
void
load(Archive& archive, npl_stop_on_step_and_next_stage_compressed_fields_t& m)
{
    serializer_class<npl_stop_on_step_and_next_stage_compressed_fields_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stop_on_step_and_next_stage_compressed_fields_t&);



template<>
class serializer_class<npl_svi_eve_sub_type_plus_prf_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svi_eve_sub_type_plus_prf_t& m) {
        uint64_t m_prf = m.prf;
            archive(::cereal::make_nvp("sub_type", m.sub_type));
            archive(::cereal::make_nvp("prf", m_prf));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svi_eve_sub_type_plus_prf_t& m) {
        uint64_t m_prf;
            archive(::cereal::make_nvp("sub_type", m.sub_type));
            archive(::cereal::make_nvp("prf", m_prf));
        m.prf = m_prf;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svi_eve_sub_type_plus_prf_t& m)
{
    serializer_class<npl_svi_eve_sub_type_plus_prf_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svi_eve_sub_type_plus_prf_t&);

template <class Archive>
void
load(Archive& archive, npl_svi_eve_sub_type_plus_prf_t& m)
{
    serializer_class<npl_svi_eve_sub_type_plus_prf_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svi_eve_sub_type_plus_prf_t&);



template<>
class serializer_class<npl_svi_eve_vid2_plus_prf_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svi_eve_vid2_plus_prf_t& m) {
        uint64_t m_vid2 = m.vid2;
        uint64_t m_prf = m.prf;
            archive(::cereal::make_nvp("vid2", m_vid2));
            archive(::cereal::make_nvp("prf", m_prf));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svi_eve_vid2_plus_prf_t& m) {
        uint64_t m_vid2;
        uint64_t m_prf;
            archive(::cereal::make_nvp("vid2", m_vid2));
            archive(::cereal::make_nvp("prf", m_prf));
        m.vid2 = m_vid2;
        m.prf = m_prf;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svi_eve_vid2_plus_prf_t& m)
{
    serializer_class<npl_svi_eve_vid2_plus_prf_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svi_eve_vid2_plus_prf_t&);

template <class Archive>
void
load(Archive& archive, npl_svi_eve_vid2_plus_prf_t& m)
{
    serializer_class<npl_svi_eve_vid2_plus_prf_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svi_eve_vid2_plus_prf_t&);



template<>
class serializer_class<npl_svl_traps_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_traps_t& m) {
        uint64_t m_control_protocol = m.control_protocol;
        uint64_t m_control_ipc = m.control_ipc;
        uint64_t m_svl_mc_prune = m.svl_mc_prune;
            archive(::cereal::make_nvp("control_protocol", m_control_protocol));
            archive(::cereal::make_nvp("control_ipc", m_control_ipc));
            archive(::cereal::make_nvp("svl_mc_prune", m_svl_mc_prune));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_traps_t& m) {
        uint64_t m_control_protocol;
        uint64_t m_control_ipc;
        uint64_t m_svl_mc_prune;
            archive(::cereal::make_nvp("control_protocol", m_control_protocol));
            archive(::cereal::make_nvp("control_ipc", m_control_ipc));
            archive(::cereal::make_nvp("svl_mc_prune", m_svl_mc_prune));
        m.control_protocol = m_control_protocol;
        m.control_ipc = m_control_ipc;
        m.svl_mc_prune = m_svl_mc_prune;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_traps_t& m)
{
    serializer_class<npl_svl_traps_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_traps_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_traps_t& m)
{
    serializer_class<npl_svl_traps_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_traps_t&);



template<>
class serializer_class<npl_system_mcid_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_system_mcid_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_system_mcid_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_system_mcid_t& m)
{
    serializer_class<npl_system_mcid_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_system_mcid_t&);

template <class Archive>
void
load(Archive& archive, npl_system_mcid_t& m)
{
    serializer_class<npl_system_mcid_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_system_mcid_t&);



template<>
class serializer_class<npl_te_headend_nhlfe_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_te_headend_nhlfe_t& m) {
            archive(::cereal::make_nvp("lsp_destination", m.lsp_destination));
            archive(::cereal::make_nvp("counter_offset", m.counter_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_te_headend_nhlfe_t& m) {
            archive(::cereal::make_nvp("lsp_destination", m.lsp_destination));
            archive(::cereal::make_nvp("counter_offset", m.counter_offset));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_te_headend_nhlfe_t& m)
{
    serializer_class<npl_te_headend_nhlfe_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_te_headend_nhlfe_t&);

template <class Archive>
void
load(Archive& archive, npl_te_headend_nhlfe_t& m)
{
    serializer_class<npl_te_headend_nhlfe_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_te_headend_nhlfe_t&);



template<>
class serializer_class<npl_te_midpoint_nhlfe_t_anonymous_union_lsp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_te_midpoint_nhlfe_t_anonymous_union_lsp_t& m) {
        uint64_t m_swap_label = m.swap_label;
        uint64_t m_lsp_id = m.lsp_id;
            archive(::cereal::make_nvp("swap_label", m_swap_label));
            archive(::cereal::make_nvp("lsp_id", m_lsp_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_te_midpoint_nhlfe_t_anonymous_union_lsp_t& m) {
        uint64_t m_swap_label;
        uint64_t m_lsp_id;
            archive(::cereal::make_nvp("swap_label", m_swap_label));
            archive(::cereal::make_nvp("lsp_id", m_lsp_id));
        m.swap_label = m_swap_label;
        m.lsp_id = m_lsp_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_te_midpoint_nhlfe_t_anonymous_union_lsp_t& m)
{
    serializer_class<npl_te_midpoint_nhlfe_t_anonymous_union_lsp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_te_midpoint_nhlfe_t_anonymous_union_lsp_t&);

template <class Archive>
void
load(Archive& archive, npl_te_midpoint_nhlfe_t_anonymous_union_lsp_t& m)
{
    serializer_class<npl_te_midpoint_nhlfe_t_anonymous_union_lsp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_te_midpoint_nhlfe_t_anonymous_union_lsp_t&);



template<>
class serializer_class<npl_tm_header_base_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tm_header_base_t& m) {
        uint64_t m_vce = m.vce;
        uint64_t m_tc = m.tc;
        uint64_t m_dp = m.dp;
            archive(::cereal::make_nvp("hdr_type", m.hdr_type));
            archive(::cereal::make_nvp("vce", m_vce));
            archive(::cereal::make_nvp("tc", m_tc));
            archive(::cereal::make_nvp("dp", m_dp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tm_header_base_t& m) {
        uint64_t m_vce;
        uint64_t m_tc;
        uint64_t m_dp;
            archive(::cereal::make_nvp("hdr_type", m.hdr_type));
            archive(::cereal::make_nvp("vce", m_vce));
            archive(::cereal::make_nvp("tc", m_tc));
            archive(::cereal::make_nvp("dp", m_dp));
        m.vce = m_vce;
        m.tc = m_tc;
        m.dp = m_dp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tm_header_base_t& m)
{
    serializer_class<npl_tm_header_base_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tm_header_base_t&);

template <class Archive>
void
load(Archive& archive, npl_tm_header_base_t& m)
{
    serializer_class<npl_tm_header_base_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tm_header_base_t&);



template<>
class serializer_class<npl_tos_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tos_t& m) {
        uint64_t m_dscp = m.dscp;
        uint64_t m_ecn = m.ecn;
            archive(::cereal::make_nvp("dscp", m_dscp));
            archive(::cereal::make_nvp("ecn", m_ecn));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tos_t& m) {
        uint64_t m_dscp;
        uint64_t m_ecn;
            archive(::cereal::make_nvp("dscp", m_dscp));
            archive(::cereal::make_nvp("ecn", m_ecn));
        m.dscp = m_dscp;
        m.ecn = m_ecn;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tos_t& m)
{
    serializer_class<npl_tos_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tos_t&);

template <class Archive>
void
load(Archive& archive, npl_tos_t& m)
{
    serializer_class<npl_tos_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tos_t&);



template<>
class serializer_class<npl_tpid_sa_lsb_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tpid_sa_lsb_t& m) {
        uint64_t m_sa_lsb = m.sa_lsb;
        uint64_t m_tpid = m.tpid;
            archive(::cereal::make_nvp("sa_lsb", m_sa_lsb));
            archive(::cereal::make_nvp("tpid", m_tpid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tpid_sa_lsb_t& m) {
        uint64_t m_sa_lsb;
        uint64_t m_tpid;
            archive(::cereal::make_nvp("sa_lsb", m_sa_lsb));
            archive(::cereal::make_nvp("tpid", m_tpid));
        m.sa_lsb = m_sa_lsb;
        m.tpid = m_tpid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tpid_sa_lsb_t& m)
{
    serializer_class<npl_tpid_sa_lsb_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tpid_sa_lsb_t&);

template <class Archive>
void
load(Archive& archive, npl_tpid_sa_lsb_t& m)
{
    serializer_class<npl_tpid_sa_lsb_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tpid_sa_lsb_t&);



template<>
class serializer_class<npl_trap_conditions_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_trap_conditions_t& m) {
        uint64_t m_non_inject_up = m.non_inject_up;
        uint64_t m_skip_p2p = m.skip_p2p;
            archive(::cereal::make_nvp("non_inject_up", m_non_inject_up));
            archive(::cereal::make_nvp("skip_p2p", m_skip_p2p));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_trap_conditions_t& m) {
        uint64_t m_non_inject_up;
        uint64_t m_skip_p2p;
            archive(::cereal::make_nvp("non_inject_up", m_non_inject_up));
            archive(::cereal::make_nvp("skip_p2p", m_skip_p2p));
        m.non_inject_up = m_non_inject_up;
        m.skip_p2p = m_skip_p2p;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_trap_conditions_t& m)
{
    serializer_class<npl_trap_conditions_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_trap_conditions_t&);

template <class Archive>
void
load(Archive& archive, npl_trap_conditions_t& m)
{
    serializer_class<npl_trap_conditions_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_trap_conditions_t&);



template<>
class serializer_class<npl_traps_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_traps_t& m) {
            archive(::cereal::make_nvp("ethernet", m.ethernet));
            archive(::cereal::make_nvp("ipv4", m.ipv4));
            archive(::cereal::make_nvp("ipv6", m.ipv6));
            archive(::cereal::make_nvp("mpls", m.mpls));
            archive(::cereal::make_nvp("l3", m.l3));
            archive(::cereal::make_nvp("oamp", m.oamp));
            archive(::cereal::make_nvp("app", m.app));
            archive(::cereal::make_nvp("svl", m.svl));
            archive(::cereal::make_nvp("l2_lpts", m.l2_lpts));
            archive(::cereal::make_nvp("internal", m.internal));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_traps_t& m) {
            archive(::cereal::make_nvp("ethernet", m.ethernet));
            archive(::cereal::make_nvp("ipv4", m.ipv4));
            archive(::cereal::make_nvp("ipv6", m.ipv6));
            archive(::cereal::make_nvp("mpls", m.mpls));
            archive(::cereal::make_nvp("l3", m.l3));
            archive(::cereal::make_nvp("oamp", m.oamp));
            archive(::cereal::make_nvp("app", m.app));
            archive(::cereal::make_nvp("svl", m.svl));
            archive(::cereal::make_nvp("l2_lpts", m.l2_lpts));
            archive(::cereal::make_nvp("internal", m.internal));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_traps_t& m)
{
    serializer_class<npl_traps_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_traps_t&);

template <class Archive>
void
load(Archive& archive, npl_traps_t& m)
{
    serializer_class<npl_traps_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_traps_t&);



template<>
class serializer_class<npl_ts_cmd_trans_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ts_cmd_trans_t& m) {
        uint64_t m_update_udp_cs = m.update_udp_cs;
        uint64_t m_reset_udp_cs = m.reset_udp_cs;
            archive(::cereal::make_nvp("op", m.op));
            archive(::cereal::make_nvp("update_udp_cs", m_update_udp_cs));
            archive(::cereal::make_nvp("reset_udp_cs", m_reset_udp_cs));
            archive(::cereal::make_nvp("ifg_ts_cmd", m.ifg_ts_cmd));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ts_cmd_trans_t& m) {
        uint64_t m_update_udp_cs;
        uint64_t m_reset_udp_cs;
            archive(::cereal::make_nvp("op", m.op));
            archive(::cereal::make_nvp("update_udp_cs", m_update_udp_cs));
            archive(::cereal::make_nvp("reset_udp_cs", m_reset_udp_cs));
            archive(::cereal::make_nvp("ifg_ts_cmd", m.ifg_ts_cmd));
        m.update_udp_cs = m_update_udp_cs;
        m.reset_udp_cs = m_reset_udp_cs;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ts_cmd_trans_t& m)
{
    serializer_class<npl_ts_cmd_trans_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ts_cmd_trans_t&);

template <class Archive>
void
load(Archive& archive, npl_ts_cmd_trans_t& m)
{
    serializer_class<npl_ts_cmd_trans_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ts_cmd_trans_t&);



template<>
class serializer_class<npl_ts_command_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ts_command_t& m) {
        uint64_t m_op = m.op;
        uint64_t m_offset = m.offset;
            archive(::cereal::make_nvp("op", m_op));
            archive(::cereal::make_nvp("offset", m_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ts_command_t& m) {
        uint64_t m_op;
        uint64_t m_offset;
            archive(::cereal::make_nvp("op", m_op));
            archive(::cereal::make_nvp("offset", m_offset));
        m.op = m_op;
        m.offset = m_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ts_command_t& m)
{
    serializer_class<npl_ts_command_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ts_command_t&);

template <class Archive>
void
load(Archive& archive, npl_ts_command_t& m)
{
    serializer_class<npl_ts_command_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ts_command_t&);



template<>
class serializer_class<npl_ttl_and_protocol_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ttl_and_protocol_t& m) {
        uint64_t m_ttl = m.ttl;
        uint64_t m_protocol = m.protocol;
            archive(::cereal::make_nvp("ttl", m_ttl));
            archive(::cereal::make_nvp("protocol", m_protocol));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ttl_and_protocol_t& m) {
        uint64_t m_ttl;
        uint64_t m_protocol;
            archive(::cereal::make_nvp("ttl", m_ttl));
            archive(::cereal::make_nvp("protocol", m_protocol));
        m.ttl = m_ttl;
        m.protocol = m_protocol;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ttl_and_protocol_t& m)
{
    serializer_class<npl_ttl_and_protocol_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ttl_and_protocol_t&);

template <class Archive>
void
load(Archive& archive, npl_ttl_and_protocol_t& m)
{
    serializer_class<npl_ttl_and_protocol_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ttl_and_protocol_t&);



template<>
class serializer_class<npl_tunnel_control_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tunnel_control_t& m) {
        uint64_t m_decrement_inner_ttl = m.decrement_inner_ttl;
        uint64_t m_is_tos_from_tunnel = m.is_tos_from_tunnel;
        uint64_t m_lp_set = m.lp_set;
            archive(::cereal::make_nvp("decrement_inner_ttl", m_decrement_inner_ttl));
            archive(::cereal::make_nvp("ttl_mode", m.ttl_mode));
            archive(::cereal::make_nvp("is_tos_from_tunnel", m_is_tos_from_tunnel));
            archive(::cereal::make_nvp("lp_set", m_lp_set));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tunnel_control_t& m) {
        uint64_t m_decrement_inner_ttl;
        uint64_t m_is_tos_from_tunnel;
        uint64_t m_lp_set;
            archive(::cereal::make_nvp("decrement_inner_ttl", m_decrement_inner_ttl));
            archive(::cereal::make_nvp("ttl_mode", m.ttl_mode));
            archive(::cereal::make_nvp("is_tos_from_tunnel", m_is_tos_from_tunnel));
            archive(::cereal::make_nvp("lp_set", m_lp_set));
        m.decrement_inner_ttl = m_decrement_inner_ttl;
        m.is_tos_from_tunnel = m_is_tos_from_tunnel;
        m.lp_set = m_lp_set;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tunnel_control_t& m)
{
    serializer_class<npl_tunnel_control_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tunnel_control_t&);

template <class Archive>
void
load(Archive& archive, npl_tunnel_control_t& m)
{
    serializer_class<npl_tunnel_control_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tunnel_control_t&);



template<>
class serializer_class<npl_tunnel_dlp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tunnel_dlp_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tunnel_dlp_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tunnel_dlp_t& m)
{
    serializer_class<npl_tunnel_dlp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tunnel_dlp_t&);

template <class Archive>
void
load(Archive& archive, npl_tunnel_dlp_t& m)
{
    serializer_class<npl_tunnel_dlp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tunnel_dlp_t&);



template<>
class serializer_class<npl_tunnel_headend_encap_t_anonymous_union_te_asbr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tunnel_headend_encap_t_anonymous_union_te_asbr_t& m) {
        uint64_t m_te_tunnel = m.te_tunnel;
        uint64_t m_asbr = m.asbr;
            archive(::cereal::make_nvp("te_tunnel", m_te_tunnel));
            archive(::cereal::make_nvp("asbr", m_asbr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tunnel_headend_encap_t_anonymous_union_te_asbr_t& m) {
        uint64_t m_te_tunnel;
        uint64_t m_asbr;
            archive(::cereal::make_nvp("te_tunnel", m_te_tunnel));
            archive(::cereal::make_nvp("asbr", m_asbr));
        m.te_tunnel = m_te_tunnel;
        m.asbr = m_asbr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tunnel_headend_encap_t_anonymous_union_te_asbr_t& m)
{
    serializer_class<npl_tunnel_headend_encap_t_anonymous_union_te_asbr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tunnel_headend_encap_t_anonymous_union_te_asbr_t&);

template <class Archive>
void
load(Archive& archive, npl_tunnel_headend_encap_t_anonymous_union_te_asbr_t& m)
{
    serializer_class<npl_tunnel_headend_encap_t_anonymous_union_te_asbr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tunnel_headend_encap_t_anonymous_union_te_asbr_t&);



template<>
class serializer_class<npl_tunnel_type_q_counter_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tunnel_type_q_counter_t& m) {
        uint64_t m_q_counter = m.q_counter;
            archive(::cereal::make_nvp("tunnel_type", m.tunnel_type));
            archive(::cereal::make_nvp("q_counter", m_q_counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tunnel_type_q_counter_t& m) {
        uint64_t m_q_counter;
            archive(::cereal::make_nvp("tunnel_type", m.tunnel_type));
            archive(::cereal::make_nvp("q_counter", m_q_counter));
        m.q_counter = m_q_counter;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tunnel_type_q_counter_t& m)
{
    serializer_class<npl_tunnel_type_q_counter_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tunnel_type_q_counter_t&);

template <class Archive>
void
load(Archive& archive, npl_tunnel_type_q_counter_t& m)
{
    serializer_class<npl_tunnel_type_q_counter_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tunnel_type_q_counter_t&);



template<>
class serializer_class<npl_tx_punt_nw_encap_ptr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_punt_nw_encap_ptr_t& m) {
            archive(::cereal::make_nvp("punt_nw_encap_type", m.punt_nw_encap_type));
            archive(::cereal::make_nvp("punt_nw_encap_ptr", m.punt_nw_encap_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_punt_nw_encap_ptr_t& m) {
            archive(::cereal::make_nvp("punt_nw_encap_type", m.punt_nw_encap_type));
            archive(::cereal::make_nvp("punt_nw_encap_ptr", m.punt_nw_encap_ptr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tx_punt_nw_encap_ptr_t& m)
{
    serializer_class<npl_tx_punt_nw_encap_ptr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_punt_nw_encap_ptr_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_punt_nw_encap_ptr_t& m)
{
    serializer_class<npl_tx_punt_nw_encap_ptr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_punt_nw_encap_ptr_t&);



template<>
class serializer_class<npl_txpp_first_macro_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_first_macro_table_key_t& m) {
        uint64_t m_is_mc = m.is_mc;
        uint64_t m_fwd_type = m.fwd_type;
        uint64_t m_first_encap_type = m.first_encap_type;
        uint64_t m_second_encap_type = m.second_encap_type;
            archive(::cereal::make_nvp("is_mc", m_is_mc));
            archive(::cereal::make_nvp("fwd_type", m_fwd_type));
            archive(::cereal::make_nvp("first_encap_type", m_first_encap_type));
            archive(::cereal::make_nvp("second_encap_type", m_second_encap_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_first_macro_table_key_t& m) {
        uint64_t m_is_mc;
        uint64_t m_fwd_type;
        uint64_t m_first_encap_type;
        uint64_t m_second_encap_type;
            archive(::cereal::make_nvp("is_mc", m_is_mc));
            archive(::cereal::make_nvp("fwd_type", m_fwd_type));
            archive(::cereal::make_nvp("first_encap_type", m_first_encap_type));
            archive(::cereal::make_nvp("second_encap_type", m_second_encap_type));
        m.is_mc = m_is_mc;
        m.fwd_type = m_fwd_type;
        m.first_encap_type = m_first_encap_type;
        m.second_encap_type = m_second_encap_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_first_macro_table_key_t& m)
{
    serializer_class<npl_txpp_first_macro_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_first_macro_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_first_macro_table_key_t& m)
{
    serializer_class<npl_txpp_first_macro_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_first_macro_table_key_t&);



template<>
class serializer_class<npl_udf_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_udf_t& m) {
            archive(::cereal::make_nvp("value", m.value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_udf_t& m) {
            archive(::cereal::make_nvp("value", m.value));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_udf_t& m)
{
    serializer_class<npl_udf_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_udf_t&);

template <class Archive>
void
load(Archive& archive, npl_udf_t& m)
{
    serializer_class<npl_udf_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_udf_t&);



template<>
class serializer_class<npl_udp_encap_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_udp_encap_data_t& m) {
        uint64_t m_sport = m.sport;
        uint64_t m_dport = m.dport;
            archive(::cereal::make_nvp("sport", m_sport));
            archive(::cereal::make_nvp("dport", m_dport));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_udp_encap_data_t& m) {
        uint64_t m_sport;
        uint64_t m_dport;
            archive(::cereal::make_nvp("sport", m_sport));
            archive(::cereal::make_nvp("dport", m_dport));
        m.sport = m_sport;
        m.dport = m_dport;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_udp_encap_data_t& m)
{
    serializer_class<npl_udp_encap_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_udp_encap_data_t&);

template <class Archive>
void
load(Archive& archive, npl_udp_encap_data_t& m)
{
    serializer_class<npl_udp_encap_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_udp_encap_data_t&);



template<>
class serializer_class<npl_unicast_flb_tm_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_unicast_flb_tm_header_t& m) {
        uint64_t m_reserved = m.reserved;
        uint64_t m_dsp = m.dsp;
            archive(::cereal::make_nvp("base", m.base));
            archive(::cereal::make_nvp("reserved", m_reserved));
            archive(::cereal::make_nvp("dsp", m_dsp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_unicast_flb_tm_header_t& m) {
        uint64_t m_reserved;
        uint64_t m_dsp;
            archive(::cereal::make_nvp("base", m.base));
            archive(::cereal::make_nvp("reserved", m_reserved));
            archive(::cereal::make_nvp("dsp", m_dsp));
        m.reserved = m_reserved;
        m.dsp = m_dsp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_unicast_flb_tm_header_t& m)
{
    serializer_class<npl_unicast_flb_tm_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_unicast_flb_tm_header_t&);

template <class Archive>
void
load(Archive& archive, npl_unicast_flb_tm_header_t& m)
{
    serializer_class<npl_unicast_flb_tm_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_unicast_flb_tm_header_t&);



template<>
class serializer_class<npl_unicast_plb_tm_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_unicast_plb_tm_header_t& m) {
        uint64_t m_reserved = m.reserved;
        uint64_t m_destination_device = m.destination_device;
        uint64_t m_destination_slice = m.destination_slice;
        uint64_t m_destination_oq = m.destination_oq;
            archive(::cereal::make_nvp("base", m.base));
            archive(::cereal::make_nvp("reserved", m_reserved));
            archive(::cereal::make_nvp("destination_device", m_destination_device));
            archive(::cereal::make_nvp("destination_slice", m_destination_slice));
            archive(::cereal::make_nvp("destination_oq", m_destination_oq));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_unicast_plb_tm_header_t& m) {
        uint64_t m_reserved;
        uint64_t m_destination_device;
        uint64_t m_destination_slice;
        uint64_t m_destination_oq;
            archive(::cereal::make_nvp("base", m.base));
            archive(::cereal::make_nvp("reserved", m_reserved));
            archive(::cereal::make_nvp("destination_device", m_destination_device));
            archive(::cereal::make_nvp("destination_slice", m_destination_slice));
            archive(::cereal::make_nvp("destination_oq", m_destination_oq));
        m.reserved = m_reserved;
        m.destination_device = m_destination_device;
        m.destination_slice = m_destination_slice;
        m.destination_oq = m_destination_oq;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_unicast_plb_tm_header_t& m)
{
    serializer_class<npl_unicast_plb_tm_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_unicast_plb_tm_header_t&);

template <class Archive>
void
load(Archive& archive, npl_unicast_plb_tm_header_t& m)
{
    serializer_class<npl_unicast_plb_tm_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_unicast_plb_tm_header_t&);



template<>
class serializer_class<npl_unscheduled_recycle_code_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_unscheduled_recycle_code_t& m) {
        uint64_t m_recycle_pkt = m.recycle_pkt;
        uint64_t m_unscheduled_recycle_code_lsb = m.unscheduled_recycle_code_lsb;
            archive(::cereal::make_nvp("recycle_pkt", m_recycle_pkt));
            archive(::cereal::make_nvp("unscheduled_recycle_code_lsb", m_unscheduled_recycle_code_lsb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_unscheduled_recycle_code_t& m) {
        uint64_t m_recycle_pkt;
        uint64_t m_unscheduled_recycle_code_lsb;
            archive(::cereal::make_nvp("recycle_pkt", m_recycle_pkt));
            archive(::cereal::make_nvp("unscheduled_recycle_code_lsb", m_unscheduled_recycle_code_lsb));
        m.recycle_pkt = m_recycle_pkt;
        m.unscheduled_recycle_code_lsb = m_unscheduled_recycle_code_lsb;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_unscheduled_recycle_code_t& m)
{
    serializer_class<npl_unscheduled_recycle_code_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_unscheduled_recycle_code_t&);

template <class Archive>
void
load(Archive& archive, npl_unscheduled_recycle_code_t& m)
{
    serializer_class<npl_unscheduled_recycle_code_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_unscheduled_recycle_code_t&);



template<>
class serializer_class<npl_use_metedata_table_per_packet_format_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_use_metedata_table_per_packet_format_t& m) {
            archive(::cereal::make_nvp("use_metadata_table_for_ip_packet", m.use_metadata_table_for_ip_packet));
            archive(::cereal::make_nvp("use_metadata_table_for_non_ip_packet", m.use_metadata_table_for_non_ip_packet));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_use_metedata_table_per_packet_format_t& m) {
            archive(::cereal::make_nvp("use_metadata_table_for_ip_packet", m.use_metadata_table_for_ip_packet));
            archive(::cereal::make_nvp("use_metadata_table_for_non_ip_packet", m.use_metadata_table_for_non_ip_packet));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_use_metedata_table_per_packet_format_t& m)
{
    serializer_class<npl_use_metedata_table_per_packet_format_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_use_metedata_table_per_packet_format_t&);

template <class Archive>
void
load(Archive& archive, npl_use_metedata_table_per_packet_format_t& m)
{
    serializer_class<npl_use_metedata_table_per_packet_format_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_use_metedata_table_per_packet_format_t&);



template<>
class serializer_class<npl_vid2_or_flood_rcy_sm_vlans_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vid2_or_flood_rcy_sm_vlans_t& m) {
        uint64_t m_vid2 = m.vid2;
            archive(::cereal::make_nvp("vid2", m_vid2));
            archive(::cereal::make_nvp("flood_rcy_sm_vlans", m.flood_rcy_sm_vlans));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vid2_or_flood_rcy_sm_vlans_t& m) {
        uint64_t m_vid2;
            archive(::cereal::make_nvp("vid2", m_vid2));
            archive(::cereal::make_nvp("flood_rcy_sm_vlans", m.flood_rcy_sm_vlans));
        m.vid2 = m_vid2;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vid2_or_flood_rcy_sm_vlans_t& m)
{
    serializer_class<npl_vid2_or_flood_rcy_sm_vlans_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vid2_or_flood_rcy_sm_vlans_t&);

template <class Archive>
void
load(Archive& archive, npl_vid2_or_flood_rcy_sm_vlans_t& m)
{
    serializer_class<npl_vid2_or_flood_rcy_sm_vlans_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vid2_or_flood_rcy_sm_vlans_t&);



template<>
class serializer_class<npl_vlan_and_sa_lsb_encap_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan_and_sa_lsb_encap_t& m) {
        uint64_t m_vlan_id = m.vlan_id;
            archive(::cereal::make_nvp("vlan_id", m_vlan_id));
            archive(::cereal::make_nvp("tpid_sa_lsb", m.tpid_sa_lsb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan_and_sa_lsb_encap_t& m) {
        uint64_t m_vlan_id;
            archive(::cereal::make_nvp("vlan_id", m_vlan_id));
            archive(::cereal::make_nvp("tpid_sa_lsb", m.tpid_sa_lsb));
        m.vlan_id = m_vlan_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan_and_sa_lsb_encap_t& m)
{
    serializer_class<npl_vlan_and_sa_lsb_encap_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan_and_sa_lsb_encap_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan_and_sa_lsb_encap_t& m)
{
    serializer_class<npl_vlan_and_sa_lsb_encap_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan_and_sa_lsb_encap_t&);



template<>
class serializer_class<npl_vlan_edit_secondary_type_with_padding_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan_edit_secondary_type_with_padding_t& m) {
            archive(::cereal::make_nvp("secondary_type", m.secondary_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan_edit_secondary_type_with_padding_t& m) {
            archive(::cereal::make_nvp("secondary_type", m.secondary_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan_edit_secondary_type_with_padding_t& m)
{
    serializer_class<npl_vlan_edit_secondary_type_with_padding_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan_edit_secondary_type_with_padding_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan_edit_secondary_type_with_padding_t& m)
{
    serializer_class<npl_vlan_edit_secondary_type_with_padding_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan_edit_secondary_type_with_padding_t&);



template<>
class serializer_class<npl_vlan_header_flags_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan_header_flags_t& m) {
        uint64_t m_is_priority = m.is_priority;
            archive(::cereal::make_nvp("is_priority", m_is_priority));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan_header_flags_t& m) {
        uint64_t m_is_priority;
            archive(::cereal::make_nvp("is_priority", m_is_priority));
        m.is_priority = m_is_priority;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan_header_flags_t& m)
{
    serializer_class<npl_vlan_header_flags_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan_header_flags_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan_header_flags_t& m)
{
    serializer_class<npl_vlan_header_flags_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan_header_flags_t&);



template<>
class serializer_class<npl_vlan_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan_id_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan_id_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan_id_t& m)
{
    serializer_class<npl_vlan_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan_id_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan_id_t& m)
{
    serializer_class<npl_vlan_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan_id_t&);



template<>
class serializer_class<npl_vlan_profile_and_lp_type_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan_profile_and_lp_type_t& m) {
        uint64_t m_vlan_profile = m.vlan_profile;
            archive(::cereal::make_nvp("l2_lp_type", m.l2_lp_type));
            archive(::cereal::make_nvp("vlan_profile", m_vlan_profile));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan_profile_and_lp_type_t& m) {
        uint64_t m_vlan_profile;
            archive(::cereal::make_nvp("l2_lp_type", m.l2_lp_type));
            archive(::cereal::make_nvp("vlan_profile", m_vlan_profile));
        m.vlan_profile = m_vlan_profile;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan_profile_and_lp_type_t& m)
{
    serializer_class<npl_vlan_profile_and_lp_type_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan_profile_and_lp_type_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan_profile_and_lp_type_t& m)
{
    serializer_class<npl_vlan_profile_and_lp_type_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan_profile_and_lp_type_t&);



template<>
class serializer_class<npl_vlan_tag_tci_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan_tag_tci_t& m) {
            archive(::cereal::make_nvp("pcp_dei", m.pcp_dei));
            archive(::cereal::make_nvp("vid", m.vid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan_tag_tci_t& m) {
            archive(::cereal::make_nvp("pcp_dei", m.pcp_dei));
            archive(::cereal::make_nvp("vid", m.vid));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan_tag_tci_t& m)
{
    serializer_class<npl_vlan_tag_tci_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan_tag_tci_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan_tag_tci_t& m)
{
    serializer_class<npl_vlan_tag_tci_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan_tag_tci_t&);



template<>
class serializer_class<npl_vni_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vni_table_result_t& m) {
        uint64_t m_vlan_profile = m.vlan_profile;
            archive(::cereal::make_nvp("vlan_profile", m_vlan_profile));
            archive(::cereal::make_nvp("l2_relay_attributes_id", m.l2_relay_attributes_id));
            archive(::cereal::make_nvp("vni_counter", m.vni_counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vni_table_result_t& m) {
        uint64_t m_vlan_profile;
            archive(::cereal::make_nvp("vlan_profile", m_vlan_profile));
            archive(::cereal::make_nvp("l2_relay_attributes_id", m.l2_relay_attributes_id));
            archive(::cereal::make_nvp("vni_counter", m.vni_counter));
        m.vlan_profile = m_vlan_profile;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vni_table_result_t& m)
{
    serializer_class<npl_vni_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vni_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_vni_table_result_t& m)
{
    serializer_class<npl_vni_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vni_table_result_t&);



template<>
class serializer_class<npl_voq_cgm_slice_dram_cgm_profile_results_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_dram_cgm_profile_results_t& m) {
            archive(::cereal::make_nvp("wred_probability_region", m.wred_probability_region));
            archive(::cereal::make_nvp("wred_action", m.wred_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_dram_cgm_profile_results_t& m) {
            archive(::cereal::make_nvp("wred_probability_region", m.wred_probability_region));
            archive(::cereal::make_nvp("wred_action", m.wred_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_dram_cgm_profile_results_t& m)
{
    serializer_class<npl_voq_cgm_slice_dram_cgm_profile_results_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_dram_cgm_profile_results_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_dram_cgm_profile_results_t& m)
{
    serializer_class<npl_voq_cgm_slice_dram_cgm_profile_results_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_dram_cgm_profile_results_t&);



template<>
class serializer_class<npl_voq_cgm_slice_profile_buff_region_thresholds_results_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_profile_buff_region_thresholds_results_t& m) {
            archive(::cereal::make_nvp("q_size_buff_region", m.q_size_buff_region));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_profile_buff_region_thresholds_results_t& m) {
            archive(::cereal::make_nvp("q_size_buff_region", m.q_size_buff_region));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_profile_buff_region_thresholds_results_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_buff_region_thresholds_results_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_profile_buff_region_thresholds_results_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_profile_buff_region_thresholds_results_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_buff_region_thresholds_results_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_profile_buff_region_thresholds_results_t&);



template<>
class serializer_class<npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results_t& m) {
            archive(::cereal::make_nvp("pkt_enq_time_region", m.pkt_enq_time_region));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results_t& m) {
            archive(::cereal::make_nvp("pkt_enq_time_region", m.pkt_enq_time_region));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results_t&);



template<>
class serializer_class<npl_voq_cgm_slice_profile_pkt_region_thresholds_results_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_profile_pkt_region_thresholds_results_t& m) {
            archive(::cereal::make_nvp("q_size_pkt_region", m.q_size_pkt_region));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_profile_pkt_region_thresholds_results_t& m) {
            archive(::cereal::make_nvp("q_size_pkt_region", m.q_size_pkt_region));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_profile_pkt_region_thresholds_results_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_pkt_region_thresholds_results_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_profile_pkt_region_thresholds_results_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_profile_pkt_region_thresholds_results_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_pkt_region_thresholds_results_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_profile_pkt_region_thresholds_results_t&);



template<>
class serializer_class<npl_voq_cgm_slice_slice_cgm_profile_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_slice_cgm_profile_result_t& m) {
            archive(::cereal::make_nvp("counter_id", m.counter_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_slice_cgm_profile_result_t& m) {
            archive(::cereal::make_nvp("counter_id", m.counter_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_slice_cgm_profile_result_t& m)
{
    serializer_class<npl_voq_cgm_slice_slice_cgm_profile_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_slice_cgm_profile_result_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_slice_cgm_profile_result_t& m)
{
    serializer_class<npl_voq_cgm_slice_slice_cgm_profile_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_slice_cgm_profile_result_t&);



template<>
class serializer_class<npl_voq_profile_len> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_profile_len& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_profile_len& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_profile_len& m)
{
    serializer_class<npl_voq_profile_len>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_profile_len&);

template <class Archive>
void
load(Archive& archive, npl_voq_profile_len& m)
{
    serializer_class<npl_voq_profile_len>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_profile_len&);



template<>
class serializer_class<npl_vpl_label_and_valid_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vpl_label_and_valid_t& m) {
        uint64_t m_v6_label_vld = m.v6_label_vld;
        uint64_t m_v4_label_vld = m.v4_label_vld;
            archive(::cereal::make_nvp("v6_label_vld", m_v6_label_vld));
            archive(::cereal::make_nvp("v4_label_vld", m_v4_label_vld));
            archive(::cereal::make_nvp("label_encap", m.label_encap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vpl_label_and_valid_t& m) {
        uint64_t m_v6_label_vld;
        uint64_t m_v4_label_vld;
            archive(::cereal::make_nvp("v6_label_vld", m_v6_label_vld));
            archive(::cereal::make_nvp("v4_label_vld", m_v4_label_vld));
            archive(::cereal::make_nvp("label_encap", m.label_encap));
        m.v6_label_vld = m_v6_label_vld;
        m.v4_label_vld = m_v4_label_vld;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vpl_label_and_valid_t& m)
{
    serializer_class<npl_vpl_label_and_valid_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vpl_label_and_valid_t&);

template <class Archive>
void
load(Archive& archive, npl_vpl_label_and_valid_t& m)
{
    serializer_class<npl_vpl_label_and_valid_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vpl_label_and_valid_t&);



template<>
class serializer_class<npl_vxlan_dlp_specific_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vxlan_dlp_specific_t& m) {
        uint64_t m_stp_state_is_block = m.stp_state_is_block;
        uint64_t m_lp_profile = m.lp_profile;
        uint64_t m_disabled = m.disabled;
        uint64_t m_lp_set = m.lp_set;
        uint64_t m_sip_index = m.sip_index;
        uint64_t m_ttl = m.ttl;
            archive(::cereal::make_nvp("stp_state_is_block", m_stp_state_is_block));
            archive(::cereal::make_nvp("lp_profile", m_lp_profile));
            archive(::cereal::make_nvp("ttl_mode", m.ttl_mode));
            archive(::cereal::make_nvp("disabled", m_disabled));
            archive(::cereal::make_nvp("lp_set", m_lp_set));
            archive(::cereal::make_nvp("qos_info", m.qos_info));
            archive(::cereal::make_nvp("p_counter", m.p_counter));
            archive(::cereal::make_nvp("sip_index", m_sip_index));
            archive(::cereal::make_nvp("dip", m.dip));
            archive(::cereal::make_nvp("ttl", m_ttl));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vxlan_dlp_specific_t& m) {
        uint64_t m_stp_state_is_block;
        uint64_t m_lp_profile;
        uint64_t m_disabled;
        uint64_t m_lp_set;
        uint64_t m_sip_index;
        uint64_t m_ttl;
            archive(::cereal::make_nvp("stp_state_is_block", m_stp_state_is_block));
            archive(::cereal::make_nvp("lp_profile", m_lp_profile));
            archive(::cereal::make_nvp("ttl_mode", m.ttl_mode));
            archive(::cereal::make_nvp("disabled", m_disabled));
            archive(::cereal::make_nvp("lp_set", m_lp_set));
            archive(::cereal::make_nvp("qos_info", m.qos_info));
            archive(::cereal::make_nvp("p_counter", m.p_counter));
            archive(::cereal::make_nvp("sip_index", m_sip_index));
            archive(::cereal::make_nvp("dip", m.dip));
            archive(::cereal::make_nvp("ttl", m_ttl));
        m.stp_state_is_block = m_stp_state_is_block;
        m.lp_profile = m_lp_profile;
        m.disabled = m_disabled;
        m.lp_set = m_lp_set;
        m.sip_index = m_sip_index;
        m.ttl = m_ttl;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vxlan_dlp_specific_t& m)
{
    serializer_class<npl_vxlan_dlp_specific_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vxlan_dlp_specific_t&);

template <class Archive>
void
load(Archive& archive, npl_vxlan_dlp_specific_t& m)
{
    serializer_class<npl_vxlan_dlp_specific_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vxlan_dlp_specific_t&);



template<>
class serializer_class<npl_vxlan_encap_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vxlan_encap_data_t& m) {
        uint64_t m_vni = m.vni;
            archive(::cereal::make_nvp("vni", m_vni));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vxlan_encap_data_t& m) {
        uint64_t m_vni;
            archive(::cereal::make_nvp("vni", m_vni));
        m.vni = m_vni;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vxlan_encap_data_t& m)
{
    serializer_class<npl_vxlan_encap_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vxlan_encap_data_t&);

template <class Archive>
void
load(Archive& archive, npl_vxlan_encap_data_t& m)
{
    serializer_class<npl_vxlan_encap_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vxlan_encap_data_t&);



}

