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

template <class Archive> void save(Archive&, const npl_bd_attributes_t&);
template <class Archive> void load(Archive&, npl_bd_attributes_t&);

template <class Archive> void save(Archive&, const npl_bool_t&);
template <class Archive> void load(Archive&, npl_bool_t&);

template <class Archive> void save(Archive&, const npl_compound_termination_control_t&);
template <class Archive> void load(Archive&, npl_compound_termination_control_t&);

template <class Archive> void save(Archive&, const npl_counter_flag_t&);
template <class Archive> void load(Archive&, npl_counter_flag_t&);

template <class Archive> void save(Archive&, const npl_counter_ptr_t&);
template <class Archive> void load(Archive&, npl_counter_ptr_t&);

template <class Archive> void save(Archive&, const npl_destination_t&);
template <class Archive> void load(Archive&, npl_destination_t&);

template <class Archive> void save(Archive&, const npl_encap_mpls_exp_t&);
template <class Archive> void load(Archive&, npl_encap_mpls_exp_t&);

template <class Archive> void save(Archive&, const npl_ene_macro_id_t&);
template <class Archive> void load(Archive&, npl_ene_macro_id_t&);

template<>
class serializer_class<npl_event_queue_address_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_event_queue_address_t& m) {
        uint64_t m_address = m.address;
            archive(::cereal::make_nvp("address", m_address));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_event_queue_address_t& m) {
        uint64_t m_address;
            archive(::cereal::make_nvp("address", m_address));
        m.address = m_address;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_event_queue_address_t& m)
{
    serializer_class<npl_event_queue_address_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_event_queue_address_t&);

template <class Archive>
void
load(Archive& archive, npl_event_queue_address_t& m)
{
    serializer_class<npl_event_queue_address_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_event_queue_address_t&);



template<>
class serializer_class<npl_event_to_send_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_event_to_send_t& m) {
        uint64_t m_rmep_last_time = m.rmep_last_time;
        uint64_t m_rmep_id = m.rmep_id;
        uint64_t m_rmep_state_table_data = m.rmep_state_table_data;
            archive(::cereal::make_nvp("rmep_last_time", m_rmep_last_time));
            archive(::cereal::make_nvp("rmep_id", m_rmep_id));
            archive(::cereal::make_nvp("rmep_state_table_data", m_rmep_state_table_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_event_to_send_t& m) {
        uint64_t m_rmep_last_time;
        uint64_t m_rmep_id;
        uint64_t m_rmep_state_table_data;
            archive(::cereal::make_nvp("rmep_last_time", m_rmep_last_time));
            archive(::cereal::make_nvp("rmep_id", m_rmep_id));
            archive(::cereal::make_nvp("rmep_state_table_data", m_rmep_state_table_data));
        m.rmep_last_time = m_rmep_last_time;
        m.rmep_id = m_rmep_id;
        m.rmep_state_table_data = m_rmep_state_table_data;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_event_to_send_t& m)
{
    serializer_class<npl_event_to_send_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_event_to_send_t&);

template <class Archive>
void
load(Archive& archive, npl_event_to_send_t& m)
{
    serializer_class<npl_event_to_send_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_event_to_send_t&);



template<>
class serializer_class<npl_exact_bank_index_len_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_exact_bank_index_len_t& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_exact_bank_index_len_t& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_exact_bank_index_len_t& m)
{
    serializer_class<npl_exact_bank_index_len_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_exact_bank_index_len_t&);

template <class Archive>
void
load(Archive& archive, npl_exact_bank_index_len_t& m)
{
    serializer_class<npl_exact_bank_index_len_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_exact_bank_index_len_t&);



template<>
class serializer_class<npl_exact_meter_index_len_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_exact_meter_index_len_t& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_exact_meter_index_len_t& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_exact_meter_index_len_t& m)
{
    serializer_class<npl_exact_meter_index_len_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_exact_meter_index_len_t&);

template <class Archive>
void
load(Archive& archive, npl_exact_meter_index_len_t& m)
{
    serializer_class<npl_exact_meter_index_len_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_exact_meter_index_len_t&);



template<>
class serializer_class<npl_exp_and_bos_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_exp_and_bos_t& m) {
        uint64_t m_exp = m.exp;
        uint64_t m_bos = m.bos;
            archive(::cereal::make_nvp("exp", m_exp));
            archive(::cereal::make_nvp("bos", m_bos));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_exp_and_bos_t& m) {
        uint64_t m_exp;
        uint64_t m_bos;
            archive(::cereal::make_nvp("exp", m_exp));
            archive(::cereal::make_nvp("bos", m_bos));
        m.exp = m_exp;
        m.bos = m_bos;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_exp_and_bos_t& m)
{
    serializer_class<npl_exp_and_bos_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_exp_and_bos_t&);

template <class Archive>
void
load(Archive& archive, npl_exp_and_bos_t& m)
{
    serializer_class<npl_exp_and_bos_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_exp_and_bos_t&);



template<>
class serializer_class<npl_exp_bos_and_label_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_exp_bos_and_label_t& m) {
        uint64_t m_label = m.label;
            archive(::cereal::make_nvp("label_exp_bos", m.label_exp_bos));
            archive(::cereal::make_nvp("label", m_label));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_exp_bos_and_label_t& m) {
        uint64_t m_label;
            archive(::cereal::make_nvp("label_exp_bos", m.label_exp_bos));
            archive(::cereal::make_nvp("label", m_label));
        m.label = m_label;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_exp_bos_and_label_t& m)
{
    serializer_class<npl_exp_bos_and_label_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_exp_bos_and_label_t&);

template <class Archive>
void
load(Archive& archive, npl_exp_bos_and_label_t& m)
{
    serializer_class<npl_exp_bos_and_label_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_exp_bos_and_label_t&);



template<>
class serializer_class<npl_extended_encap_data2_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_extended_encap_data2_t& m) {
        uint64_t m_ene_ipv6_dip_lsb = m.ene_ipv6_dip_lsb;
            archive(::cereal::make_nvp("ene_ipv6_dip_lsb", m_ene_ipv6_dip_lsb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_extended_encap_data2_t& m) {
        uint64_t m_ene_ipv6_dip_lsb;
            archive(::cereal::make_nvp("ene_ipv6_dip_lsb", m_ene_ipv6_dip_lsb));
        m.ene_ipv6_dip_lsb = m_ene_ipv6_dip_lsb;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_extended_encap_data2_t& m)
{
    serializer_class<npl_extended_encap_data2_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_extended_encap_data2_t&);

template <class Archive>
void
load(Archive& archive, npl_extended_encap_data2_t& m)
{
    serializer_class<npl_extended_encap_data2_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_extended_encap_data2_t&);



template<>
class serializer_class<npl_extended_encap_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_extended_encap_data_t& m) {
            archive(::cereal::make_nvp("ene_ipv6_dip_msb", m.ene_ipv6_dip_msb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_extended_encap_data_t& m) {
            archive(::cereal::make_nvp("ene_ipv6_dip_msb", m.ene_ipv6_dip_msb));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_extended_encap_data_t& m)
{
    serializer_class<npl_extended_encap_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_extended_encap_data_t&);

template <class Archive>
void
load(Archive& archive, npl_extended_encap_data_t& m)
{
    serializer_class<npl_extended_encap_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_extended_encap_data_t&);



template<>
class serializer_class<npl_fabric_cfg_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_cfg_t& m) {
        uint64_t m_issu_codespace = m.issu_codespace;
        uint64_t m_device = m.device;
            archive(::cereal::make_nvp("issu_codespace", m_issu_codespace));
            archive(::cereal::make_nvp("plb_type", m.plb_type));
            archive(::cereal::make_nvp("device", m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_cfg_t& m) {
        uint64_t m_issu_codespace;
        uint64_t m_device;
            archive(::cereal::make_nvp("issu_codespace", m_issu_codespace));
            archive(::cereal::make_nvp("plb_type", m.plb_type));
            archive(::cereal::make_nvp("device", m_device));
        m.issu_codespace = m_issu_codespace;
        m.device = m_device;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_cfg_t& m)
{
    serializer_class<npl_fabric_cfg_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_cfg_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_cfg_t& m)
{
    serializer_class<npl_fabric_cfg_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_cfg_t&);



template<>
class serializer_class<npl_fabric_header_ctrl_sn_plb_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_header_ctrl_sn_plb_t& m) {
        uint64_t m_link_fc = m.link_fc;
        uint64_t m_fcn = m.fcn;
        uint64_t m_plb_ctxt = m.plb_ctxt;
            archive(::cereal::make_nvp("link_fc", m_link_fc));
            archive(::cereal::make_nvp("fcn", m_fcn));
            archive(::cereal::make_nvp("plb_ctxt", m_plb_ctxt));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_header_ctrl_sn_plb_t& m) {
        uint64_t m_link_fc;
        uint64_t m_fcn;
        uint64_t m_plb_ctxt;
            archive(::cereal::make_nvp("link_fc", m_link_fc));
            archive(::cereal::make_nvp("fcn", m_fcn));
            archive(::cereal::make_nvp("plb_ctxt", m_plb_ctxt));
        m.link_fc = m_link_fc;
        m.fcn = m_fcn;
        m.plb_ctxt = m_plb_ctxt;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_header_ctrl_sn_plb_t& m)
{
    serializer_class<npl_fabric_header_ctrl_sn_plb_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_header_ctrl_sn_plb_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_header_ctrl_sn_plb_t& m)
{
    serializer_class<npl_fabric_header_ctrl_sn_plb_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_header_ctrl_sn_plb_t&);



template<>
class serializer_class<npl_fabric_header_ctrl_ts_plb_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_header_ctrl_ts_plb_t& m) {
        uint64_t m_link_fc = m.link_fc;
        uint64_t m_fcn = m.fcn;
            archive(::cereal::make_nvp("link_fc", m_link_fc));
            archive(::cereal::make_nvp("fcn", m_fcn));
            archive(::cereal::make_nvp("plb_ctxt", m.plb_ctxt));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_header_ctrl_ts_plb_t& m) {
        uint64_t m_link_fc;
        uint64_t m_fcn;
            archive(::cereal::make_nvp("link_fc", m_link_fc));
            archive(::cereal::make_nvp("fcn", m_fcn));
            archive(::cereal::make_nvp("plb_ctxt", m.plb_ctxt));
        m.link_fc = m_link_fc;
        m.fcn = m_fcn;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_header_ctrl_ts_plb_t& m)
{
    serializer_class<npl_fabric_header_ctrl_ts_plb_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_header_ctrl_ts_plb_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_header_ctrl_ts_plb_t& m)
{
    serializer_class<npl_fabric_header_ctrl_ts_plb_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_header_ctrl_ts_plb_t&);



template<>
class serializer_class<npl_fabric_header_start_template_t_anonymous_union_ctrl_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_header_start_template_t_anonymous_union_ctrl_t& m) {
            archive(::cereal::make_nvp("ts_plb", m.ts_plb));
            archive(::cereal::make_nvp("sn_plb", m.sn_plb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_header_start_template_t_anonymous_union_ctrl_t& m) {
            archive(::cereal::make_nvp("ts_plb", m.ts_plb));
            archive(::cereal::make_nvp("sn_plb", m.sn_plb));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_header_start_template_t_anonymous_union_ctrl_t& m)
{
    serializer_class<npl_fabric_header_start_template_t_anonymous_union_ctrl_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_header_start_template_t_anonymous_union_ctrl_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_header_start_template_t_anonymous_union_ctrl_t& m)
{
    serializer_class<npl_fabric_header_start_template_t_anonymous_union_ctrl_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_header_start_template_t_anonymous_union_ctrl_t&);



template<>
class serializer_class<npl_fabric_ibm_cmd_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_ibm_cmd_t& m) {
        uint64_t m_ibm_cmd_padding = m.ibm_cmd_padding;
        uint64_t m_ibm_cmd = m.ibm_cmd;
            archive(::cereal::make_nvp("ibm_cmd_padding", m_ibm_cmd_padding));
            archive(::cereal::make_nvp("ibm_cmd", m_ibm_cmd));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_ibm_cmd_t& m) {
        uint64_t m_ibm_cmd_padding;
        uint64_t m_ibm_cmd;
            archive(::cereal::make_nvp("ibm_cmd_padding", m_ibm_cmd_padding));
            archive(::cereal::make_nvp("ibm_cmd", m_ibm_cmd));
        m.ibm_cmd_padding = m_ibm_cmd_padding;
        m.ibm_cmd = m_ibm_cmd;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_ibm_cmd_t& m)
{
    serializer_class<npl_fabric_ibm_cmd_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_ibm_cmd_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_ibm_cmd_t& m)
{
    serializer_class<npl_fabric_ibm_cmd_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_ibm_cmd_t&);



template<>
class serializer_class<npl_fabric_mc_ibm_cmd_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_mc_ibm_cmd_t& m) {
        uint64_t m_fabric_mc_ibm_cmd_padding = m.fabric_mc_ibm_cmd_padding;
        uint64_t m_fabric_mc_ibm_cmd = m.fabric_mc_ibm_cmd;
            archive(::cereal::make_nvp("fabric_mc_encapsulation_type", m.fabric_mc_encapsulation_type));
            archive(::cereal::make_nvp("fabric_mc_ibm_cmd_padding", m_fabric_mc_ibm_cmd_padding));
            archive(::cereal::make_nvp("fabric_mc_ibm_cmd", m_fabric_mc_ibm_cmd));
            archive(::cereal::make_nvp("fabric_mc_ibm_cmd_src", m.fabric_mc_ibm_cmd_src));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_mc_ibm_cmd_t& m) {
        uint64_t m_fabric_mc_ibm_cmd_padding;
        uint64_t m_fabric_mc_ibm_cmd;
            archive(::cereal::make_nvp("fabric_mc_encapsulation_type", m.fabric_mc_encapsulation_type));
            archive(::cereal::make_nvp("fabric_mc_ibm_cmd_padding", m_fabric_mc_ibm_cmd_padding));
            archive(::cereal::make_nvp("fabric_mc_ibm_cmd", m_fabric_mc_ibm_cmd));
            archive(::cereal::make_nvp("fabric_mc_ibm_cmd_src", m.fabric_mc_ibm_cmd_src));
        m.fabric_mc_ibm_cmd_padding = m_fabric_mc_ibm_cmd_padding;
        m.fabric_mc_ibm_cmd = m_fabric_mc_ibm_cmd;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_mc_ibm_cmd_t& m)
{
    serializer_class<npl_fabric_mc_ibm_cmd_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_mc_ibm_cmd_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_mc_ibm_cmd_t& m)
{
    serializer_class<npl_fabric_mc_ibm_cmd_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_mc_ibm_cmd_t&);



template<>
class serializer_class<npl_fb_link_2_link_bundle_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fb_link_2_link_bundle_table_result_t& m) {
        uint64_t m_bundle_num = m.bundle_num;
            archive(::cereal::make_nvp("bundle_num", m_bundle_num));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fb_link_2_link_bundle_table_result_t& m) {
        uint64_t m_bundle_num;
            archive(::cereal::make_nvp("bundle_num", m_bundle_num));
        m.bundle_num = m_bundle_num;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fb_link_2_link_bundle_table_result_t& m)
{
    serializer_class<npl_fb_link_2_link_bundle_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fb_link_2_link_bundle_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_fb_link_2_link_bundle_table_result_t& m)
{
    serializer_class<npl_fb_link_2_link_bundle_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fb_link_2_link_bundle_table_result_t&);



template<>
class serializer_class<npl_fe_broadcast_bmp_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fe_broadcast_bmp_table_result_t& m) {
            archive(::cereal::make_nvp("links_bmp", m.links_bmp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fe_broadcast_bmp_table_result_t& m) {
            archive(::cereal::make_nvp("links_bmp", m.links_bmp));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fe_broadcast_bmp_table_result_t& m)
{
    serializer_class<npl_fe_broadcast_bmp_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fe_broadcast_bmp_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_fe_broadcast_bmp_table_result_t& m)
{
    serializer_class<npl_fe_broadcast_bmp_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fe_broadcast_bmp_table_result_t&);



template<>
class serializer_class<npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_result_t& m) {
        uint64_t m_base_oq = m.base_oq;
            archive(::cereal::make_nvp("base_oq", m_base_oq));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_result_t& m) {
        uint64_t m_base_oq;
            archive(::cereal::make_nvp("base_oq", m_base_oq));
        m.base_oq = m_base_oq;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_result_t& m)
{
    serializer_class<npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_result_t& m)
{
    serializer_class<npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_result_t&);



template<>
class serializer_class<npl_fe_uc_bundle_selected_link_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fe_uc_bundle_selected_link_t& m) {
        uint64_t m_bundle_link = m.bundle_link;
            archive(::cereal::make_nvp("bundle_link", m_bundle_link));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fe_uc_bundle_selected_link_t& m) {
        uint64_t m_bundle_link;
            archive(::cereal::make_nvp("bundle_link", m_bundle_link));
        m.bundle_link = m_bundle_link;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fe_uc_bundle_selected_link_t& m)
{
    serializer_class<npl_fe_uc_bundle_selected_link_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fe_uc_bundle_selected_link_t&);

template <class Archive>
void
load(Archive& archive, npl_fe_uc_bundle_selected_link_t& m)
{
    serializer_class<npl_fe_uc_bundle_selected_link_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fe_uc_bundle_selected_link_t&);



template<>
class serializer_class<npl_fe_uc_link_bundle_desc_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fe_uc_link_bundle_desc_table_result_t& m) {
        uint64_t m_bundle_link_3_bc = m.bundle_link_3_bc;
        uint64_t m_bundle_link_3 = m.bundle_link_3;
        uint64_t m_bundle_link_2_bc = m.bundle_link_2_bc;
        uint64_t m_bundle_link_2 = m.bundle_link_2;
        uint64_t m_bundle_link_1_bc = m.bundle_link_1_bc;
        uint64_t m_bundle_link_1 = m.bundle_link_1;
        uint64_t m_bundle_link_0_bc = m.bundle_link_0_bc;
        uint64_t m_bundle_link_0 = m.bundle_link_0;
            archive(::cereal::make_nvp("bundle_link_3_bc", m_bundle_link_3_bc));
            archive(::cereal::make_nvp("bundle_link_3", m_bundle_link_3));
            archive(::cereal::make_nvp("bundle_link_2_bc", m_bundle_link_2_bc));
            archive(::cereal::make_nvp("bundle_link_2", m_bundle_link_2));
            archive(::cereal::make_nvp("bundle_link_1_bc", m_bundle_link_1_bc));
            archive(::cereal::make_nvp("bundle_link_1", m_bundle_link_1));
            archive(::cereal::make_nvp("bundle_link_0_bc", m_bundle_link_0_bc));
            archive(::cereal::make_nvp("bundle_link_0", m_bundle_link_0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fe_uc_link_bundle_desc_table_result_t& m) {
        uint64_t m_bundle_link_3_bc;
        uint64_t m_bundle_link_3;
        uint64_t m_bundle_link_2_bc;
        uint64_t m_bundle_link_2;
        uint64_t m_bundle_link_1_bc;
        uint64_t m_bundle_link_1;
        uint64_t m_bundle_link_0_bc;
        uint64_t m_bundle_link_0;
            archive(::cereal::make_nvp("bundle_link_3_bc", m_bundle_link_3_bc));
            archive(::cereal::make_nvp("bundle_link_3", m_bundle_link_3));
            archive(::cereal::make_nvp("bundle_link_2_bc", m_bundle_link_2_bc));
            archive(::cereal::make_nvp("bundle_link_2", m_bundle_link_2));
            archive(::cereal::make_nvp("bundle_link_1_bc", m_bundle_link_1_bc));
            archive(::cereal::make_nvp("bundle_link_1", m_bundle_link_1));
            archive(::cereal::make_nvp("bundle_link_0_bc", m_bundle_link_0_bc));
            archive(::cereal::make_nvp("bundle_link_0", m_bundle_link_0));
        m.bundle_link_3_bc = m_bundle_link_3_bc;
        m.bundle_link_3 = m_bundle_link_3;
        m.bundle_link_2_bc = m_bundle_link_2_bc;
        m.bundle_link_2 = m_bundle_link_2;
        m.bundle_link_1_bc = m_bundle_link_1_bc;
        m.bundle_link_1 = m_bundle_link_1;
        m.bundle_link_0_bc = m_bundle_link_0_bc;
        m.bundle_link_0 = m_bundle_link_0;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fe_uc_link_bundle_desc_table_result_t& m)
{
    serializer_class<npl_fe_uc_link_bundle_desc_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fe_uc_link_bundle_desc_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_fe_uc_link_bundle_desc_table_result_t& m)
{
    serializer_class<npl_fe_uc_link_bundle_desc_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fe_uc_link_bundle_desc_table_result_t&);



template<>
class serializer_class<npl_fe_uc_random_fb_link_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fe_uc_random_fb_link_t& m) {
        uint64_t m_link_num = m.link_num;
            archive(::cereal::make_nvp("link_num", m_link_num));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fe_uc_random_fb_link_t& m) {
        uint64_t m_link_num;
            archive(::cereal::make_nvp("link_num", m_link_num));
        m.link_num = m_link_num;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fe_uc_random_fb_link_t& m)
{
    serializer_class<npl_fe_uc_random_fb_link_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fe_uc_random_fb_link_t&);

template <class Archive>
void
load(Archive& archive, npl_fe_uc_random_fb_link_t& m)
{
    serializer_class<npl_fe_uc_random_fb_link_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fe_uc_random_fb_link_t&);



template<>
class serializer_class<npl_fec_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fec_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fec_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fec_t& m)
{
    serializer_class<npl_fec_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fec_t&);

template <class Archive>
void
load(Archive& archive, npl_fec_t& m)
{
    serializer_class<npl_fec_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fec_t&);



template<>
class serializer_class<npl_fi_macro_config_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fi_macro_config_data_t& m) {
        uint64_t m_tcam_key_inst1_offset = m.tcam_key_inst1_offset;
        uint64_t m_tcam_key_inst1_width = m.tcam_key_inst1_width;
        uint64_t m_tcam_key_inst0_offset = m.tcam_key_inst0_offset;
        uint64_t m_tcam_key_inst0_width = m.tcam_key_inst0_width;
        uint64_t m_alu_shift2 = m.alu_shift2;
        uint64_t m_alu_shift1 = m.alu_shift1;
        uint64_t m_alu_mux2_select = m.alu_mux2_select;
        uint64_t m_alu_mux1_select = m.alu_mux1_select;
        uint64_t m_fs2_const = m.fs2_const;
        uint64_t m_fs1_const = m.fs1_const;
        uint64_t m_alu_fs2_valid_bits = m.alu_fs2_valid_bits;
        uint64_t m_alu_fs2_offset = m.alu_fs2_offset;
        uint64_t m_alu_fs1_valid_bits = m.alu_fs1_valid_bits;
        uint64_t m_alu_fs1_offset = m.alu_fs1_offset;
            archive(::cereal::make_nvp("tcam_key_inst1_offset", m_tcam_key_inst1_offset));
            archive(::cereal::make_nvp("tcam_key_inst1_width", m_tcam_key_inst1_width));
            archive(::cereal::make_nvp("tcam_key_inst0_offset", m_tcam_key_inst0_offset));
            archive(::cereal::make_nvp("tcam_key_inst0_width", m_tcam_key_inst0_width));
            archive(::cereal::make_nvp("alu_shift2", m_alu_shift2));
            archive(::cereal::make_nvp("alu_shift1", m_alu_shift1));
            archive(::cereal::make_nvp("hw_logic_select", m.hw_logic_select));
            archive(::cereal::make_nvp("alu_mux2_select", m_alu_mux2_select));
            archive(::cereal::make_nvp("alu_mux1_select", m_alu_mux1_select));
            archive(::cereal::make_nvp("fs2_const", m_fs2_const));
            archive(::cereal::make_nvp("fs1_const", m_fs1_const));
            archive(::cereal::make_nvp("alu_fs2_valid_bits", m_alu_fs2_valid_bits));
            archive(::cereal::make_nvp("alu_fs2_offset", m_alu_fs2_offset));
            archive(::cereal::make_nvp("alu_fs1_valid_bits", m_alu_fs1_valid_bits));
            archive(::cereal::make_nvp("alu_fs1_offset", m_alu_fs1_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fi_macro_config_data_t& m) {
        uint64_t m_tcam_key_inst1_offset;
        uint64_t m_tcam_key_inst1_width;
        uint64_t m_tcam_key_inst0_offset;
        uint64_t m_tcam_key_inst0_width;
        uint64_t m_alu_shift2;
        uint64_t m_alu_shift1;
        uint64_t m_alu_mux2_select;
        uint64_t m_alu_mux1_select;
        uint64_t m_fs2_const;
        uint64_t m_fs1_const;
        uint64_t m_alu_fs2_valid_bits;
        uint64_t m_alu_fs2_offset;
        uint64_t m_alu_fs1_valid_bits;
        uint64_t m_alu_fs1_offset;
            archive(::cereal::make_nvp("tcam_key_inst1_offset", m_tcam_key_inst1_offset));
            archive(::cereal::make_nvp("tcam_key_inst1_width", m_tcam_key_inst1_width));
            archive(::cereal::make_nvp("tcam_key_inst0_offset", m_tcam_key_inst0_offset));
            archive(::cereal::make_nvp("tcam_key_inst0_width", m_tcam_key_inst0_width));
            archive(::cereal::make_nvp("alu_shift2", m_alu_shift2));
            archive(::cereal::make_nvp("alu_shift1", m_alu_shift1));
            archive(::cereal::make_nvp("hw_logic_select", m.hw_logic_select));
            archive(::cereal::make_nvp("alu_mux2_select", m_alu_mux2_select));
            archive(::cereal::make_nvp("alu_mux1_select", m_alu_mux1_select));
            archive(::cereal::make_nvp("fs2_const", m_fs2_const));
            archive(::cereal::make_nvp("fs1_const", m_fs1_const));
            archive(::cereal::make_nvp("alu_fs2_valid_bits", m_alu_fs2_valid_bits));
            archive(::cereal::make_nvp("alu_fs2_offset", m_alu_fs2_offset));
            archive(::cereal::make_nvp("alu_fs1_valid_bits", m_alu_fs1_valid_bits));
            archive(::cereal::make_nvp("alu_fs1_offset", m_alu_fs1_offset));
        m.tcam_key_inst1_offset = m_tcam_key_inst1_offset;
        m.tcam_key_inst1_width = m_tcam_key_inst1_width;
        m.tcam_key_inst0_offset = m_tcam_key_inst0_offset;
        m.tcam_key_inst0_width = m_tcam_key_inst0_width;
        m.alu_shift2 = m_alu_shift2;
        m.alu_shift1 = m_alu_shift1;
        m.alu_mux2_select = m_alu_mux2_select;
        m.alu_mux1_select = m_alu_mux1_select;
        m.fs2_const = m_fs2_const;
        m.fs1_const = m_fs1_const;
        m.alu_fs2_valid_bits = m_alu_fs2_valid_bits;
        m.alu_fs2_offset = m_alu_fs2_offset;
        m.alu_fs1_valid_bits = m_alu_fs1_valid_bits;
        m.alu_fs1_offset = m_alu_fs1_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fi_macro_config_data_t& m)
{
    serializer_class<npl_fi_macro_config_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fi_macro_config_data_t&);

template <class Archive>
void
load(Archive& archive, npl_fi_macro_config_data_t& m)
{
    serializer_class<npl_fi_macro_config_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fi_macro_config_data_t&);



template<>
class serializer_class<npl_filb_voq_mapping_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_filb_voq_mapping_result_t& m) {
        uint64_t m_packing_eligible = m.packing_eligible;
        uint64_t m_snr_plb_ss2dd = m.snr_plb_ss2dd;
        uint64_t m_dest_oq = m.dest_oq;
        uint64_t m_dest_slice = m.dest_slice;
        uint64_t m_dest_dev = m.dest_dev;
            archive(::cereal::make_nvp("packing_eligible", m_packing_eligible));
            archive(::cereal::make_nvp("snr_plb_ss2dd", m_snr_plb_ss2dd));
            archive(::cereal::make_nvp("dest_oq", m_dest_oq));
            archive(::cereal::make_nvp("dest_slice", m_dest_slice));
            archive(::cereal::make_nvp("dest_dev", m_dest_dev));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_filb_voq_mapping_result_t& m) {
        uint64_t m_packing_eligible;
        uint64_t m_snr_plb_ss2dd;
        uint64_t m_dest_oq;
        uint64_t m_dest_slice;
        uint64_t m_dest_dev;
            archive(::cereal::make_nvp("packing_eligible", m_packing_eligible));
            archive(::cereal::make_nvp("snr_plb_ss2dd", m_snr_plb_ss2dd));
            archive(::cereal::make_nvp("dest_oq", m_dest_oq));
            archive(::cereal::make_nvp("dest_slice", m_dest_slice));
            archive(::cereal::make_nvp("dest_dev", m_dest_dev));
        m.packing_eligible = m_packing_eligible;
        m.snr_plb_ss2dd = m_snr_plb_ss2dd;
        m.dest_oq = m_dest_oq;
        m.dest_slice = m_dest_slice;
        m.dest_dev = m_dest_dev;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_filb_voq_mapping_result_t& m)
{
    serializer_class<npl_filb_voq_mapping_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_filb_voq_mapping_result_t&);

template <class Archive>
void
load(Archive& archive, npl_filb_voq_mapping_result_t& m)
{
    serializer_class<npl_filb_voq_mapping_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_filb_voq_mapping_result_t&);



template<>
class serializer_class<npl_frm_db_fabric_routing_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_frm_db_fabric_routing_table_result_t& m) {
            archive(::cereal::make_nvp("fabric_routing_table_data", m.fabric_routing_table_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_frm_db_fabric_routing_table_result_t& m) {
            archive(::cereal::make_nvp("fabric_routing_table_data", m.fabric_routing_table_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_frm_db_fabric_routing_table_result_t& m)
{
    serializer_class<npl_frm_db_fabric_routing_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_frm_db_fabric_routing_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_frm_db_fabric_routing_table_result_t& m)
{
    serializer_class<npl_frm_db_fabric_routing_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_frm_db_fabric_routing_table_result_t&);



template<>
class serializer_class<npl_frr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_frr_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_frr_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_frr_t& m)
{
    serializer_class<npl_frr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_frr_t&);

template <class Archive>
void
load(Archive& archive, npl_frr_t& m)
{
    serializer_class<npl_frr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_frr_t&);



template<>
class serializer_class<npl_fwd_class_qos_group_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_class_qos_group_t& m) {
        uint64_t m_fwd_class = m.fwd_class;
        uint64_t m_qos_group = m.qos_group;
            archive(::cereal::make_nvp("fwd_class", m_fwd_class));
            archive(::cereal::make_nvp("qos_group", m_qos_group));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_class_qos_group_t& m) {
        uint64_t m_fwd_class;
        uint64_t m_qos_group;
            archive(::cereal::make_nvp("fwd_class", m_fwd_class));
            archive(::cereal::make_nvp("qos_group", m_qos_group));
        m.fwd_class = m_fwd_class;
        m.qos_group = m_qos_group;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_class_qos_group_t& m)
{
    serializer_class<npl_fwd_class_qos_group_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_class_qos_group_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_class_qos_group_t& m)
{
    serializer_class<npl_fwd_class_qos_group_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_class_qos_group_t&);



template<>
class serializer_class<npl_fwd_layer_and_rtf_stage_compressed_fields_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_layer_and_rtf_stage_compressed_fields_t& m) {
            archive(::cereal::make_nvp("fwd_layer", m.fwd_layer));
            archive(::cereal::make_nvp("rtf_stage", m.rtf_stage));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_layer_and_rtf_stage_compressed_fields_t& m) {
            archive(::cereal::make_nvp("fwd_layer", m.fwd_layer));
            archive(::cereal::make_nvp("rtf_stage", m.rtf_stage));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_layer_and_rtf_stage_compressed_fields_t& m)
{
    serializer_class<npl_fwd_layer_and_rtf_stage_compressed_fields_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_layer_and_rtf_stage_compressed_fields_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_layer_and_rtf_stage_compressed_fields_t& m)
{
    serializer_class<npl_fwd_layer_and_rtf_stage_compressed_fields_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_layer_and_rtf_stage_compressed_fields_t&);



template<>
class serializer_class<npl_fwd_qos_tag_dscp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_qos_tag_dscp_t& m) {
        uint64_t m_dscp = m.dscp;
            archive(::cereal::make_nvp("dscp", m_dscp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_qos_tag_dscp_t& m) {
        uint64_t m_dscp;
            archive(::cereal::make_nvp("dscp", m_dscp));
        m.dscp = m_dscp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_qos_tag_dscp_t& m)
{
    serializer_class<npl_fwd_qos_tag_dscp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_qos_tag_dscp_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_qos_tag_dscp_t& m)
{
    serializer_class<npl_fwd_qos_tag_dscp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_qos_tag_dscp_t&);



template<>
class serializer_class<npl_fwd_qos_tag_exp_or_qosgroup_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_qos_tag_exp_or_qosgroup_t& m) {
        uint64_t m_exp_or_qos_group = m.exp_or_qos_group;
            archive(::cereal::make_nvp("exp_or_qos_group", m_exp_or_qos_group));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_qos_tag_exp_or_qosgroup_t& m) {
        uint64_t m_exp_or_qos_group;
            archive(::cereal::make_nvp("exp_or_qos_group", m_exp_or_qos_group));
        m.exp_or_qos_group = m_exp_or_qos_group;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_qos_tag_exp_or_qosgroup_t& m)
{
    serializer_class<npl_fwd_qos_tag_exp_or_qosgroup_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_qos_tag_exp_or_qosgroup_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_qos_tag_exp_or_qosgroup_t& m)
{
    serializer_class<npl_fwd_qos_tag_exp_or_qosgroup_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_qos_tag_exp_or_qosgroup_t&);



template<>
class serializer_class<npl_fwd_qos_tag_group_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_qos_tag_group_t& m) {
        uint64_t m_qos_group_id = m.qos_group_id;
            archive(::cereal::make_nvp("qos_group_id", m_qos_group_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_qos_tag_group_t& m) {
        uint64_t m_qos_group_id;
            archive(::cereal::make_nvp("qos_group_id", m_qos_group_id));
        m.qos_group_id = m_qos_group_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_qos_tag_group_t& m)
{
    serializer_class<npl_fwd_qos_tag_group_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_qos_tag_group_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_qos_tag_group_t& m)
{
    serializer_class<npl_fwd_qos_tag_group_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_qos_tag_group_t&);



template<>
class serializer_class<npl_fwd_qos_tag_pcpdei_or_qosgroup_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_qos_tag_pcpdei_or_qosgroup_t& m) {
        uint64_t m_pcp_dei_or_qos_group = m.pcp_dei_or_qos_group;
            archive(::cereal::make_nvp("pcp_dei_or_qos_group", m_pcp_dei_or_qos_group));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_qos_tag_pcpdei_or_qosgroup_t& m) {
        uint64_t m_pcp_dei_or_qos_group;
            archive(::cereal::make_nvp("pcp_dei_or_qos_group", m_pcp_dei_or_qos_group));
        m.pcp_dei_or_qos_group = m_pcp_dei_or_qos_group;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_qos_tag_pcpdei_or_qosgroup_t& m)
{
    serializer_class<npl_fwd_qos_tag_pcpdei_or_qosgroup_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_qos_tag_pcpdei_or_qosgroup_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_qos_tag_pcpdei_or_qosgroup_t& m)
{
    serializer_class<npl_fwd_qos_tag_pcpdei_or_qosgroup_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_qos_tag_pcpdei_or_qosgroup_t&);



template<>
class serializer_class<npl_fwd_qos_tag_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_qos_tag_t& m) {
            archive(::cereal::make_nvp("l2", m.l2));
            archive(::cereal::make_nvp("l3", m.l3));
            archive(::cereal::make_nvp("mpls", m.mpls));
            archive(::cereal::make_nvp("group", m.group));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_qos_tag_t& m) {
            archive(::cereal::make_nvp("l2", m.l2));
            archive(::cereal::make_nvp("l3", m.l3));
            archive(::cereal::make_nvp("mpls", m.mpls));
            archive(::cereal::make_nvp("group", m.group));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_qos_tag_t& m)
{
    serializer_class<npl_fwd_qos_tag_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_qos_tag_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_qos_tag_t& m)
{
    serializer_class<npl_fwd_qos_tag_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_qos_tag_t&);



template<>
class serializer_class<npl_g_ifg_len_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_g_ifg_len_t& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_g_ifg_len_t& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_g_ifg_len_t& m)
{
    serializer_class<npl_g_ifg_len_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_g_ifg_len_t&);

template <class Archive>
void
load(Archive& archive, npl_g_ifg_len_t& m)
{
    serializer_class<npl_g_ifg_len_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_g_ifg_len_t&);



template<>
class serializer_class<npl_gre_encap_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_gre_encap_data_t& m) {
        uint64_t m_flag_res_version = m.flag_res_version;
        uint64_t m_proto = m.proto;
            archive(::cereal::make_nvp("flag_res_version", m_flag_res_version));
            archive(::cereal::make_nvp("proto", m_proto));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_gre_encap_data_t& m) {
        uint64_t m_flag_res_version;
        uint64_t m_proto;
            archive(::cereal::make_nvp("flag_res_version", m_flag_res_version));
            archive(::cereal::make_nvp("proto", m_proto));
        m.flag_res_version = m_flag_res_version;
        m.proto = m_proto;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_gre_encap_data_t& m)
{
    serializer_class<npl_gre_encap_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_gre_encap_data_t&);

template <class Archive>
void
load(Archive& archive, npl_gre_encap_data_t& m)
{
    serializer_class<npl_gre_encap_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_gre_encap_data_t&);



template<>
class serializer_class<npl_hmc_cgm_cgm_lut_results_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_hmc_cgm_cgm_lut_results_t& m) {
        uint64_t m_dp1 = m.dp1;
        uint64_t m_dp0 = m.dp0;
        uint64_t m_mark = m.mark;
            archive(::cereal::make_nvp("dp1", m_dp1));
            archive(::cereal::make_nvp("dp0", m_dp0));
            archive(::cereal::make_nvp("mark", m_mark));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_hmc_cgm_cgm_lut_results_t& m) {
        uint64_t m_dp1;
        uint64_t m_dp0;
        uint64_t m_mark;
            archive(::cereal::make_nvp("dp1", m_dp1));
            archive(::cereal::make_nvp("dp0", m_dp0));
            archive(::cereal::make_nvp("mark", m_mark));
        m.dp1 = m_dp1;
        m.dp0 = m_dp0;
        m.mark = m_mark;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_hmc_cgm_cgm_lut_results_t& m)
{
    serializer_class<npl_hmc_cgm_cgm_lut_results_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_hmc_cgm_cgm_lut_results_t&);

template <class Archive>
void
load(Archive& archive, npl_hmc_cgm_cgm_lut_results_t& m)
{
    serializer_class<npl_hmc_cgm_cgm_lut_results_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_hmc_cgm_cgm_lut_results_t&);



template<>
class serializer_class<npl_hw_mp_table_app_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_hw_mp_table_app_t& m) {
        uint64_t m_lm_count_phase_lsb = m.lm_count_phase_lsb;
        uint64_t m_lm_period = m.lm_period;
        uint64_t m_ccm_count_phase_msb = m.ccm_count_phase_msb;
            archive(::cereal::make_nvp("lm_count_phase_lsb", m_lm_count_phase_lsb));
            archive(::cereal::make_nvp("lm_period", m_lm_period));
            archive(::cereal::make_nvp("ccm_count_phase_msb", m_ccm_count_phase_msb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_hw_mp_table_app_t& m) {
        uint64_t m_lm_count_phase_lsb;
        uint64_t m_lm_period;
        uint64_t m_ccm_count_phase_msb;
            archive(::cereal::make_nvp("lm_count_phase_lsb", m_lm_count_phase_lsb));
            archive(::cereal::make_nvp("lm_period", m_lm_period));
            archive(::cereal::make_nvp("ccm_count_phase_msb", m_ccm_count_phase_msb));
        m.lm_count_phase_lsb = m_lm_count_phase_lsb;
        m.lm_period = m_lm_period;
        m.ccm_count_phase_msb = m_ccm_count_phase_msb;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_hw_mp_table_app_t& m)
{
    serializer_class<npl_hw_mp_table_app_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_hw_mp_table_app_t&);

template <class Archive>
void
load(Archive& archive, npl_hw_mp_table_app_t& m)
{
    serializer_class<npl_hw_mp_table_app_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_hw_mp_table_app_t&);



template<>
class serializer_class<npl_ibm_cmd_table_result_t_anonymous_union_voq_or_bitmap_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ibm_cmd_table_result_t_anonymous_union_voq_or_bitmap_t& m) {
        uint64_t m_base_voq = m.base_voq;
        uint64_t m_mc_bitmap = m.mc_bitmap;
            archive(::cereal::make_nvp("base_voq", m_base_voq));
            archive(::cereal::make_nvp("mc_bitmap", m_mc_bitmap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ibm_cmd_table_result_t_anonymous_union_voq_or_bitmap_t& m) {
        uint64_t m_base_voq;
        uint64_t m_mc_bitmap;
            archive(::cereal::make_nvp("base_voq", m_base_voq));
            archive(::cereal::make_nvp("mc_bitmap", m_mc_bitmap));
        m.base_voq = m_base_voq;
        m.mc_bitmap = m_mc_bitmap;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ibm_cmd_table_result_t_anonymous_union_voq_or_bitmap_t& m)
{
    serializer_class<npl_ibm_cmd_table_result_t_anonymous_union_voq_or_bitmap_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ibm_cmd_table_result_t_anonymous_union_voq_or_bitmap_t&);

template <class Archive>
void
load(Archive& archive, npl_ibm_cmd_table_result_t_anonymous_union_voq_or_bitmap_t& m)
{
    serializer_class<npl_ibm_cmd_table_result_t_anonymous_union_voq_or_bitmap_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ibm_cmd_table_result_t_anonymous_union_voq_or_bitmap_t&);



template<>
class serializer_class<npl_ibm_enables_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ibm_enables_table_result_t& m) {
        uint64_t m_ibm_partial_mirror_packet_size = m.ibm_partial_mirror_packet_size;
        uint64_t m_ibm_partial_mirror_en = m.ibm_partial_mirror_en;
        uint64_t m_ibm_enable_ive = m.ibm_enable_ive;
        uint64_t m_ibm_enable_hw_termination = m.ibm_enable_hw_termination;
        uint64_t m_cud_ibm_offset = m.cud_ibm_offset;
        uint64_t m_cud_has_ibm = m.cud_has_ibm;
            archive(::cereal::make_nvp("ibm_partial_mirror_packet_size", m_ibm_partial_mirror_packet_size));
            archive(::cereal::make_nvp("ibm_partial_mirror_en", m_ibm_partial_mirror_en));
            archive(::cereal::make_nvp("ibm_enable_ive", m_ibm_enable_ive));
            archive(::cereal::make_nvp("ibm_enable_hw_termination", m_ibm_enable_hw_termination));
            archive(::cereal::make_nvp("cud_ibm_offset", m_cud_ibm_offset));
            archive(::cereal::make_nvp("cud_has_ibm", m_cud_has_ibm));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ibm_enables_table_result_t& m) {
        uint64_t m_ibm_partial_mirror_packet_size;
        uint64_t m_ibm_partial_mirror_en;
        uint64_t m_ibm_enable_ive;
        uint64_t m_ibm_enable_hw_termination;
        uint64_t m_cud_ibm_offset;
        uint64_t m_cud_has_ibm;
            archive(::cereal::make_nvp("ibm_partial_mirror_packet_size", m_ibm_partial_mirror_packet_size));
            archive(::cereal::make_nvp("ibm_partial_mirror_en", m_ibm_partial_mirror_en));
            archive(::cereal::make_nvp("ibm_enable_ive", m_ibm_enable_ive));
            archive(::cereal::make_nvp("ibm_enable_hw_termination", m_ibm_enable_hw_termination));
            archive(::cereal::make_nvp("cud_ibm_offset", m_cud_ibm_offset));
            archive(::cereal::make_nvp("cud_has_ibm", m_cud_has_ibm));
        m.ibm_partial_mirror_packet_size = m_ibm_partial_mirror_packet_size;
        m.ibm_partial_mirror_en = m_ibm_partial_mirror_en;
        m.ibm_enable_ive = m_ibm_enable_ive;
        m.ibm_enable_hw_termination = m_ibm_enable_hw_termination;
        m.cud_ibm_offset = m_cud_ibm_offset;
        m.cud_has_ibm = m_cud_has_ibm;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ibm_enables_table_result_t& m)
{
    serializer_class<npl_ibm_enables_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ibm_enables_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_ibm_enables_table_result_t& m)
{
    serializer_class<npl_ibm_enables_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ibm_enables_table_result_t&);



template<>
class serializer_class<npl_icmp_type_code_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_icmp_type_code_t& m) {
        uint64_t m_type = m.type;
        uint64_t m_code = m.code;
            archive(::cereal::make_nvp("type", m_type));
            archive(::cereal::make_nvp("code", m_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_icmp_type_code_t& m) {
        uint64_t m_type;
        uint64_t m_code;
            archive(::cereal::make_nvp("type", m_type));
            archive(::cereal::make_nvp("code", m_code));
        m.type = m_type;
        m.code = m_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_icmp_type_code_t& m)
{
    serializer_class<npl_icmp_type_code_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_icmp_type_code_t&);

template <class Archive>
void
load(Archive& archive, npl_icmp_type_code_t& m)
{
    serializer_class<npl_icmp_type_code_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_icmp_type_code_t&);



template<>
class serializer_class<npl_ifg_len_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ifg_len_t& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ifg_len_t& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ifg_len_t& m)
{
    serializer_class<npl_ifg_len_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ifg_len_t&);

template <class Archive>
void
load(Archive& archive, npl_ifg_len_t& m)
{
    serializer_class<npl_ifg_len_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ifg_len_t&);



template<>
class serializer_class<npl_ifg_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ifg_t& m) {
        uint64_t m_index = m.index;
            archive(::cereal::make_nvp("index", m_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ifg_t& m) {
        uint64_t m_index;
            archive(::cereal::make_nvp("index", m_index));
        m.index = m_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ifg_t& m)
{
    serializer_class<npl_ifg_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ifg_t&);

template <class Archive>
void
load(Archive& archive, npl_ifg_t& m)
{
    serializer_class<npl_ifg_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ifg_t&);



template<>
class serializer_class<npl_ifgb_tc_lut_results_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ifgb_tc_lut_results_t& m) {
        uint64_t m_use_lut = m.use_lut;
        uint64_t m_data = m.data;
            archive(::cereal::make_nvp("use_lut", m_use_lut));
            archive(::cereal::make_nvp("data", m_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ifgb_tc_lut_results_t& m) {
        uint64_t m_use_lut;
        uint64_t m_data;
            archive(::cereal::make_nvp("use_lut", m_use_lut));
            archive(::cereal::make_nvp("data", m_data));
        m.use_lut = m_use_lut;
        m.data = m_data;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ifgb_tc_lut_results_t& m)
{
    serializer_class<npl_ifgb_tc_lut_results_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ifgb_tc_lut_results_t&);

template <class Archive>
void
load(Archive& archive, npl_ifgb_tc_lut_results_t& m)
{
    serializer_class<npl_ifgb_tc_lut_results_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ifgb_tc_lut_results_t&);



template<>
class serializer_class<npl_ingress_lpts_og_app_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_lpts_og_app_data_t& m) {
        uint64_t m_lpts_og_app_id = m.lpts_og_app_id;
            archive(::cereal::make_nvp("lpts_og_app_id", m_lpts_og_app_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_lpts_og_app_data_t& m) {
        uint64_t m_lpts_og_app_id;
            archive(::cereal::make_nvp("lpts_og_app_id", m_lpts_og_app_id));
        m.lpts_og_app_id = m_lpts_og_app_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_lpts_og_app_data_t& m)
{
    serializer_class<npl_ingress_lpts_og_app_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_lpts_og_app_data_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_lpts_og_app_data_t& m)
{
    serializer_class<npl_ingress_lpts_og_app_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_lpts_og_app_data_t&);



template<>
class serializer_class<npl_ingress_ptp_info_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_ptp_info_t& m) {
        uint64_t m_is_ptp_trans_sup = m.is_ptp_trans_sup;
            archive(::cereal::make_nvp("ptp_transport_type", m.ptp_transport_type));
            archive(::cereal::make_nvp("is_ptp_trans_sup", m_is_ptp_trans_sup));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_ptp_info_t& m) {
        uint64_t m_is_ptp_trans_sup;
            archive(::cereal::make_nvp("ptp_transport_type", m.ptp_transport_type));
            archive(::cereal::make_nvp("is_ptp_trans_sup", m_is_ptp_trans_sup));
        m.is_ptp_trans_sup = m_is_ptp_trans_sup;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_ptp_info_t& m)
{
    serializer_class<npl_ingress_ptp_info_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_ptp_info_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_ptp_info_t& m)
{
    serializer_class<npl_ingress_ptp_info_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_ptp_info_t&);



template<>
class serializer_class<npl_ingress_qos_mapping_remark_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_qos_mapping_remark_t& m) {
        uint64_t m_qos_group = m.qos_group;
        uint64_t m_enable_ingress_remark = m.enable_ingress_remark;
        uint64_t m_fwd_qos_tag = m.fwd_qos_tag;
            archive(::cereal::make_nvp("qos_group", m_qos_group));
            archive(::cereal::make_nvp("encap_mpls_exp", m.encap_mpls_exp));
            archive(::cereal::make_nvp("enable_ingress_remark", m_enable_ingress_remark));
            archive(::cereal::make_nvp("fwd_qos_tag", m_fwd_qos_tag));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_qos_mapping_remark_t& m) {
        uint64_t m_qos_group;
        uint64_t m_enable_ingress_remark;
        uint64_t m_fwd_qos_tag;
            archive(::cereal::make_nvp("qos_group", m_qos_group));
            archive(::cereal::make_nvp("encap_mpls_exp", m.encap_mpls_exp));
            archive(::cereal::make_nvp("enable_ingress_remark", m_enable_ingress_remark));
            archive(::cereal::make_nvp("fwd_qos_tag", m_fwd_qos_tag));
        m.qos_group = m_qos_group;
        m.enable_ingress_remark = m_enable_ingress_remark;
        m.fwd_qos_tag = m_fwd_qos_tag;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_qos_mapping_remark_t& m)
{
    serializer_class<npl_ingress_qos_mapping_remark_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_qos_mapping_remark_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_qos_mapping_remark_t& m)
{
    serializer_class<npl_ingress_qos_mapping_remark_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_qos_mapping_remark_t&);



template<>
class serializer_class<npl_ingress_qos_result_t_anonymous_union_fwd_class_qos_group_u_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_qos_result_t_anonymous_union_fwd_class_qos_group_u_t& m) {
        uint64_t m_qos_group_pd = m.qos_group_pd;
            archive(::cereal::make_nvp("fwd_class_qos_group", m.fwd_class_qos_group));
            archive(::cereal::make_nvp("qos_group_pd", m_qos_group_pd));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_qos_result_t_anonymous_union_fwd_class_qos_group_u_t& m) {
        uint64_t m_qos_group_pd;
            archive(::cereal::make_nvp("fwd_class_qos_group", m.fwd_class_qos_group));
            archive(::cereal::make_nvp("qos_group_pd", m_qos_group_pd));
        m.qos_group_pd = m_qos_group_pd;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_qos_result_t_anonymous_union_fwd_class_qos_group_u_t& m)
{
    serializer_class<npl_ingress_qos_result_t_anonymous_union_fwd_class_qos_group_u_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_qos_result_t_anonymous_union_fwd_class_qos_group_u_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_qos_result_t_anonymous_union_fwd_class_qos_group_u_t& m)
{
    serializer_class<npl_ingress_qos_result_t_anonymous_union_fwd_class_qos_group_u_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_qos_result_t_anonymous_union_fwd_class_qos_group_u_t&);



template<>
class serializer_class<npl_initial_pd_nw_rx_data_t_anonymous_union_init_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_initial_pd_nw_rx_data_t_anonymous_union_init_data_t& m) {
        uint64_t m_initial_npp_attributes_index = m.initial_npp_attributes_index;
        uint64_t m_initial_slice_id = m.initial_slice_id;
            archive(::cereal::make_nvp("initial_npp_attributes_index", m_initial_npp_attributes_index));
            archive(::cereal::make_nvp("initial_slice_id", m_initial_slice_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_initial_pd_nw_rx_data_t_anonymous_union_init_data_t& m) {
        uint64_t m_initial_npp_attributes_index;
        uint64_t m_initial_slice_id;
            archive(::cereal::make_nvp("initial_npp_attributes_index", m_initial_npp_attributes_index));
            archive(::cereal::make_nvp("initial_slice_id", m_initial_slice_id));
        m.initial_npp_attributes_index = m_initial_npp_attributes_index;
        m.initial_slice_id = m_initial_slice_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_initial_pd_nw_rx_data_t_anonymous_union_init_data_t& m)
{
    serializer_class<npl_initial_pd_nw_rx_data_t_anonymous_union_init_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_initial_pd_nw_rx_data_t_anonymous_union_init_data_t&);

template <class Archive>
void
load(Archive& archive, npl_initial_pd_nw_rx_data_t_anonymous_union_init_data_t& m)
{
    serializer_class<npl_initial_pd_nw_rx_data_t_anonymous_union_init_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_initial_pd_nw_rx_data_t_anonymous_union_init_data_t&);



template<>
class serializer_class<npl_initial_recycle_pd_nw_rx_data_t_anonymous_union_init_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_initial_recycle_pd_nw_rx_data_t_anonymous_union_init_data_t& m) {
        uint64_t m_initial_npp_attributes_index = m.initial_npp_attributes_index;
        uint64_t m_initial_slice_id = m.initial_slice_id;
            archive(::cereal::make_nvp("initial_npp_attributes_index", m_initial_npp_attributes_index));
            archive(::cereal::make_nvp("initial_slice_id", m_initial_slice_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_initial_recycle_pd_nw_rx_data_t_anonymous_union_init_data_t& m) {
        uint64_t m_initial_npp_attributes_index;
        uint64_t m_initial_slice_id;
            archive(::cereal::make_nvp("initial_npp_attributes_index", m_initial_npp_attributes_index));
            archive(::cereal::make_nvp("initial_slice_id", m_initial_slice_id));
        m.initial_npp_attributes_index = m_initial_npp_attributes_index;
        m.initial_slice_id = m_initial_slice_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_initial_recycle_pd_nw_rx_data_t_anonymous_union_init_data_t& m)
{
    serializer_class<npl_initial_recycle_pd_nw_rx_data_t_anonymous_union_init_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_initial_recycle_pd_nw_rx_data_t_anonymous_union_init_data_t&);

template <class Archive>
void
load(Archive& archive, npl_initial_recycle_pd_nw_rx_data_t_anonymous_union_init_data_t& m)
{
    serializer_class<npl_initial_recycle_pd_nw_rx_data_t_anonymous_union_init_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_initial_recycle_pd_nw_rx_data_t_anonymous_union_init_data_t&);



template<>
class serializer_class<npl_inject_header_type_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_header_type_t& m) {
            archive(::cereal::make_nvp("inject_type", m.inject_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_header_type_t& m) {
            archive(::cereal::make_nvp("inject_type", m.inject_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_header_type_t& m)
{
    serializer_class<npl_inject_header_type_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_header_type_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_header_type_t& m)
{
    serializer_class<npl_inject_header_type_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_header_type_t&);



template<>
class serializer_class<npl_inject_source_if_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_source_if_t& m) {
        uint64_t m_inject_ifg = m.inject_ifg;
        uint64_t m_inject_pif = m.inject_pif;
            archive(::cereal::make_nvp("inject_ifg", m_inject_ifg));
            archive(::cereal::make_nvp("inject_pif", m_inject_pif));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_source_if_t& m) {
        uint64_t m_inject_ifg;
        uint64_t m_inject_pif;
            archive(::cereal::make_nvp("inject_ifg", m_inject_ifg));
            archive(::cereal::make_nvp("inject_pif", m_inject_pif));
        m.inject_ifg = m_inject_ifg;
        m.inject_pif = m_inject_pif;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_source_if_t& m)
{
    serializer_class<npl_inject_source_if_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_source_if_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_source_if_t& m)
{
    serializer_class<npl_inject_source_if_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_source_if_t&);



template<>
class serializer_class<npl_inject_up_destination_override_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_up_destination_override_t& m) {
            archive(::cereal::make_nvp("dest_override", m.dest_override));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_up_destination_override_t& m) {
            archive(::cereal::make_nvp("dest_override", m.dest_override));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_up_destination_override_t& m)
{
    serializer_class<npl_inject_up_destination_override_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_up_destination_override_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_up_destination_override_t& m)
{
    serializer_class<npl_inject_up_destination_override_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_up_destination_override_t&);



template<>
class serializer_class<npl_inject_up_eth_header_t_anonymous_union_from_port_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_up_eth_header_t_anonymous_union_from_port_t& m) {
        uint64_t m_up_ssp = m.up_ssp;
            archive(::cereal::make_nvp("up_ssp", m_up_ssp));
            archive(::cereal::make_nvp("up_source_if", m.up_source_if));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_up_eth_header_t_anonymous_union_from_port_t& m) {
        uint64_t m_up_ssp;
            archive(::cereal::make_nvp("up_ssp", m_up_ssp));
            archive(::cereal::make_nvp("up_source_if", m.up_source_if));
        m.up_ssp = m_up_ssp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_up_eth_header_t_anonymous_union_from_port_t& m)
{
    serializer_class<npl_inject_up_eth_header_t_anonymous_union_from_port_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_up_eth_header_t_anonymous_union_from_port_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_up_eth_header_t_anonymous_union_from_port_t& m)
{
    serializer_class<npl_inject_up_eth_header_t_anonymous_union_from_port_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_up_eth_header_t_anonymous_union_from_port_t&);



template<>
class serializer_class<npl_inject_up_none_routable_mc_lpts_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_up_none_routable_mc_lpts_t& m) {
        uint64_t m_placeholder = m.placeholder;
            archive(::cereal::make_nvp("placeholder", m_placeholder));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_up_none_routable_mc_lpts_t& m) {
        uint64_t m_placeholder;
            archive(::cereal::make_nvp("placeholder", m_placeholder));
        m.placeholder = m_placeholder;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_up_none_routable_mc_lpts_t& m)
{
    serializer_class<npl_inject_up_none_routable_mc_lpts_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_up_none_routable_mc_lpts_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_up_none_routable_mc_lpts_t& m)
{
    serializer_class<npl_inject_up_none_routable_mc_lpts_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_up_none_routable_mc_lpts_t&);



template<>
class serializer_class<npl_inject_up_vxlan_mc_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_up_vxlan_mc_t& m) {
        uint64_t m_placeholder = m.placeholder;
            archive(::cereal::make_nvp("placeholder", m_placeholder));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_up_vxlan_mc_t& m) {
        uint64_t m_placeholder;
            archive(::cereal::make_nvp("placeholder", m_placeholder));
        m.placeholder = m_placeholder;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_up_vxlan_mc_t& m)
{
    serializer_class<npl_inject_up_vxlan_mc_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_up_vxlan_mc_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_up_vxlan_mc_t& m)
{
    serializer_class<npl_inject_up_vxlan_mc_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_up_vxlan_mc_t&);



template<>
class serializer_class<npl_internal_traps_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_internal_traps_t& m) {
        uint64_t m_l3_lpm_lpts = m.l3_lpm_lpts;
        uint64_t m_ipv4_non_routable_mc_routing = m.ipv4_non_routable_mc_routing;
        uint64_t m_ipv4_non_routable_mc_bridging = m.ipv4_non_routable_mc_bridging;
        uint64_t m_ipv6_non_routable_mc_routing = m.ipv6_non_routable_mc_routing;
        uint64_t m_ipv6_non_routable_mc_bridging = m.ipv6_non_routable_mc_bridging;
            archive(::cereal::make_nvp("l3_lpm_lpts", m_l3_lpm_lpts));
            archive(::cereal::make_nvp("ipv4_non_routable_mc_routing", m_ipv4_non_routable_mc_routing));
            archive(::cereal::make_nvp("ipv4_non_routable_mc_bridging", m_ipv4_non_routable_mc_bridging));
            archive(::cereal::make_nvp("ipv6_non_routable_mc_routing", m_ipv6_non_routable_mc_routing));
            archive(::cereal::make_nvp("ipv6_non_routable_mc_bridging", m_ipv6_non_routable_mc_bridging));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_internal_traps_t& m) {
        uint64_t m_l3_lpm_lpts;
        uint64_t m_ipv4_non_routable_mc_routing;
        uint64_t m_ipv4_non_routable_mc_bridging;
        uint64_t m_ipv6_non_routable_mc_routing;
        uint64_t m_ipv6_non_routable_mc_bridging;
            archive(::cereal::make_nvp("l3_lpm_lpts", m_l3_lpm_lpts));
            archive(::cereal::make_nvp("ipv4_non_routable_mc_routing", m_ipv4_non_routable_mc_routing));
            archive(::cereal::make_nvp("ipv4_non_routable_mc_bridging", m_ipv4_non_routable_mc_bridging));
            archive(::cereal::make_nvp("ipv6_non_routable_mc_routing", m_ipv6_non_routable_mc_routing));
            archive(::cereal::make_nvp("ipv6_non_routable_mc_bridging", m_ipv6_non_routable_mc_bridging));
        m.l3_lpm_lpts = m_l3_lpm_lpts;
        m.ipv4_non_routable_mc_routing = m_ipv4_non_routable_mc_routing;
        m.ipv4_non_routable_mc_bridging = m_ipv4_non_routable_mc_bridging;
        m.ipv6_non_routable_mc_routing = m_ipv6_non_routable_mc_routing;
        m.ipv6_non_routable_mc_bridging = m_ipv6_non_routable_mc_bridging;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_internal_traps_t& m)
{
    serializer_class<npl_internal_traps_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_internal_traps_t&);

template <class Archive>
void
load(Archive& archive, npl_internal_traps_t& m)
{
    serializer_class<npl_internal_traps_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_internal_traps_t&);



template<>
class serializer_class<npl_invert_crc_and_context_id_local_var_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_invert_crc_and_context_id_local_var_t& m) {
        uint64_t m_inver_crc = m.inver_crc;
        uint64_t m_context_id_bit_8 = m.context_id_bit_8;
            archive(::cereal::make_nvp("inver_crc", m_inver_crc));
            archive(::cereal::make_nvp("context_id_bit_8", m_context_id_bit_8));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_invert_crc_and_context_id_local_var_t& m) {
        uint64_t m_inver_crc;
        uint64_t m_context_id_bit_8;
            archive(::cereal::make_nvp("inver_crc", m_inver_crc));
            archive(::cereal::make_nvp("context_id_bit_8", m_context_id_bit_8));
        m.inver_crc = m_inver_crc;
        m.context_id_bit_8 = m_context_id_bit_8;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_invert_crc_and_context_id_local_var_t& m)
{
    serializer_class<npl_invert_crc_and_context_id_local_var_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_invert_crc_and_context_id_local_var_t&);

template <class Archive>
void
load(Archive& archive, npl_invert_crc_and_context_id_local_var_t& m)
{
    serializer_class<npl_invert_crc_and_context_id_local_var_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_invert_crc_and_context_id_local_var_t&);



template<>
class serializer_class<npl_ip_lpm_result_t_anonymous_union_destination_or_default_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_lpm_result_t_anonymous_union_destination_or_default_t& m) {
        uint64_t m_is_default = m.is_default;
            archive(::cereal::make_nvp("destination", m.destination));
            archive(::cereal::make_nvp("is_default", m_is_default));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_lpm_result_t_anonymous_union_destination_or_default_t& m) {
        uint64_t m_is_default;
            archive(::cereal::make_nvp("destination", m.destination));
            archive(::cereal::make_nvp("is_default", m_is_default));
        m.is_default = m_is_default;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_lpm_result_t_anonymous_union_destination_or_default_t& m)
{
    serializer_class<npl_ip_lpm_result_t_anonymous_union_destination_or_default_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_lpm_result_t_anonymous_union_destination_or_default_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_lpm_result_t_anonymous_union_destination_or_default_t& m)
{
    serializer_class<npl_ip_lpm_result_t_anonymous_union_destination_or_default_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_lpm_result_t_anonymous_union_destination_or_default_t&);



template<>
class serializer_class<npl_ip_lpm_result_t_anonymous_union_rtype_or_is_fec_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_lpm_result_t_anonymous_union_rtype_or_is_fec_t& m) {
        uint64_t m_rtype = m.rtype;
        uint64_t m_is_fec = m.is_fec;
            archive(::cereal::make_nvp("rtype", m_rtype));
            archive(::cereal::make_nvp("is_fec", m_is_fec));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_lpm_result_t_anonymous_union_rtype_or_is_fec_t& m) {
        uint64_t m_rtype;
        uint64_t m_is_fec;
            archive(::cereal::make_nvp("rtype", m_rtype));
            archive(::cereal::make_nvp("is_fec", m_is_fec));
        m.rtype = m_rtype;
        m.is_fec = m_is_fec;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_lpm_result_t_anonymous_union_rtype_or_is_fec_t& m)
{
    serializer_class<npl_ip_lpm_result_t_anonymous_union_rtype_or_is_fec_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_lpm_result_t_anonymous_union_rtype_or_is_fec_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_lpm_result_t_anonymous_union_rtype_or_is_fec_t& m)
{
    serializer_class<npl_ip_lpm_result_t_anonymous_union_rtype_or_is_fec_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_lpm_result_t_anonymous_union_rtype_or_is_fec_t&);



template<>
class serializer_class<npl_ip_prefix_destination_compound_results_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_prefix_destination_compound_results_t& m) {
            archive(::cereal::make_nvp("ip_prefix_destination", m.ip_prefix_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_prefix_destination_compound_results_t& m) {
            archive(::cereal::make_nvp("ip_prefix_destination", m.ip_prefix_destination));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_prefix_destination_compound_results_t& m)
{
    serializer_class<npl_ip_prefix_destination_compound_results_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_prefix_destination_compound_results_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_prefix_destination_compound_results_t& m)
{
    serializer_class<npl_ip_prefix_destination_compound_results_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_prefix_destination_compound_results_t&);



template<>
class serializer_class<npl_ip_relay_egress_qos_key_pack_table_load_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_relay_egress_qos_key_pack_table_load_t& m) {
        uint64_t m_zero_counter_ptr = m.zero_counter_ptr;
            archive(::cereal::make_nvp("muxed_qos_group", m.muxed_qos_group));
            archive(::cereal::make_nvp("mapping_qos_fwd_qos_tag", m.mapping_qos_fwd_qos_tag));
            archive(::cereal::make_nvp("mapping_qos_pd_tag", m.mapping_qos_pd_tag));
            archive(::cereal::make_nvp("zero_counter_ptr", m_zero_counter_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_relay_egress_qos_key_pack_table_load_t& m) {
        uint64_t m_zero_counter_ptr;
            archive(::cereal::make_nvp("muxed_qos_group", m.muxed_qos_group));
            archive(::cereal::make_nvp("mapping_qos_fwd_qos_tag", m.mapping_qos_fwd_qos_tag));
            archive(::cereal::make_nvp("mapping_qos_pd_tag", m.mapping_qos_pd_tag));
            archive(::cereal::make_nvp("zero_counter_ptr", m_zero_counter_ptr));
        m.zero_counter_ptr = m_zero_counter_ptr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_relay_egress_qos_key_pack_table_load_t& m)
{
    serializer_class<npl_ip_relay_egress_qos_key_pack_table_load_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_relay_egress_qos_key_pack_table_load_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_relay_egress_qos_key_pack_table_load_t& m)
{
    serializer_class<npl_ip_relay_egress_qos_key_pack_table_load_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_relay_egress_qos_key_pack_table_load_t&);



template<>
class serializer_class<npl_ip_rtf_iter_prop_over_fwd0_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_rtf_iter_prop_over_fwd0_t& m) {
        uint64_t m_acl_id = m.acl_id;
            archive(::cereal::make_nvp("table_index", m.table_index));
            archive(::cereal::make_nvp("acl_id", m_acl_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_rtf_iter_prop_over_fwd0_t& m) {
        uint64_t m_acl_id;
            archive(::cereal::make_nvp("table_index", m.table_index));
            archive(::cereal::make_nvp("acl_id", m_acl_id));
        m.acl_id = m_acl_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_rtf_iter_prop_over_fwd0_t& m)
{
    serializer_class<npl_ip_rtf_iter_prop_over_fwd0_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_rtf_iter_prop_over_fwd0_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_rtf_iter_prop_over_fwd0_t& m)
{
    serializer_class<npl_ip_rtf_iter_prop_over_fwd0_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_rtf_iter_prop_over_fwd0_t&);



template<>
class serializer_class<npl_ip_rtf_iter_prop_over_fwd1_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_rtf_iter_prop_over_fwd1_t& m) {
        uint64_t m_acl_id = m.acl_id;
            archive(::cereal::make_nvp("table_index", m.table_index));
            archive(::cereal::make_nvp("acl_id", m_acl_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_rtf_iter_prop_over_fwd1_t& m) {
        uint64_t m_acl_id;
            archive(::cereal::make_nvp("table_index", m.table_index));
            archive(::cereal::make_nvp("acl_id", m_acl_id));
        m.acl_id = m_acl_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_rtf_iter_prop_over_fwd1_t& m)
{
    serializer_class<npl_ip_rtf_iter_prop_over_fwd1_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_rtf_iter_prop_over_fwd1_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_rtf_iter_prop_over_fwd1_t& m)
{
    serializer_class<npl_ip_rtf_iter_prop_over_fwd1_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_rtf_iter_prop_over_fwd1_t&);



template<>
class serializer_class<npl_ip_rx_global_counter_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_rx_global_counter_t& m) {
            archive(::cereal::make_nvp("tunnel_transit_counter_p", m.tunnel_transit_counter_p));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_rx_global_counter_t& m) {
            archive(::cereal::make_nvp("tunnel_transit_counter_p", m.tunnel_transit_counter_p));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_rx_global_counter_t& m)
{
    serializer_class<npl_ip_rx_global_counter_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_rx_global_counter_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_rx_global_counter_t& m)
{
    serializer_class<npl_ip_rx_global_counter_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_rx_global_counter_t&);



template<>
class serializer_class<npl_ip_tunnel_dip_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_tunnel_dip_t& m) {
        uint64_t m_ipv6_dip_index = m.ipv6_dip_index;
        uint64_t m_ipv4_dip = m.ipv4_dip;
            archive(::cereal::make_nvp("ipv6_dip_index", m_ipv6_dip_index));
            archive(::cereal::make_nvp("ipv4_dip", m_ipv4_dip));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_tunnel_dip_t& m) {
        uint64_t m_ipv6_dip_index;
        uint64_t m_ipv4_dip;
            archive(::cereal::make_nvp("ipv6_dip_index", m_ipv6_dip_index));
            archive(::cereal::make_nvp("ipv4_dip", m_ipv4_dip));
        m.ipv6_dip_index = m_ipv6_dip_index;
        m.ipv4_dip = m_ipv4_dip;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_tunnel_dip_t& m)
{
    serializer_class<npl_ip_tunnel_dip_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_tunnel_dip_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_tunnel_dip_t& m)
{
    serializer_class<npl_ip_tunnel_dip_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_tunnel_dip_t&);



template<>
class serializer_class<npl_ip_ver_and_post_fwd_stage_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_ver_and_post_fwd_stage_t& m) {
            archive(::cereal::make_nvp("ip_ver", m.ip_ver));
            archive(::cereal::make_nvp("post_fwd_rtf_stage", m.post_fwd_rtf_stage));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_ver_and_post_fwd_stage_t& m) {
            archive(::cereal::make_nvp("ip_ver", m.ip_ver));
            archive(::cereal::make_nvp("post_fwd_rtf_stage", m.post_fwd_rtf_stage));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_ver_and_post_fwd_stage_t& m)
{
    serializer_class<npl_ip_ver_and_post_fwd_stage_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_ver_and_post_fwd_stage_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_ver_and_post_fwd_stage_t& m)
{
    serializer_class<npl_ip_ver_and_post_fwd_stage_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_ver_and_post_fwd_stage_t&);



template<>
class serializer_class<npl_ip_ver_mc_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_ver_mc_t& m) {
            archive(::cereal::make_nvp("ip_version", m.ip_version));
            archive(::cereal::make_nvp("is_mc", m.is_mc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_ver_mc_t& m) {
            archive(::cereal::make_nvp("ip_version", m.ip_version));
            archive(::cereal::make_nvp("is_mc", m.is_mc));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_ver_mc_t& m)
{
    serializer_class<npl_ip_ver_mc_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_ver_mc_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_ver_mc_t& m)
{
    serializer_class<npl_ip_ver_mc_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_ver_mc_t&);



template<>
class serializer_class<npl_ipv4_header_flags_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_header_flags_t& m) {
        uint64_t m_header_error = m.header_error;
        uint64_t m_fragmented = m.fragmented;
        uint64_t m_checksum_error = m.checksum_error;
            archive(::cereal::make_nvp("header_error", m_header_error));
            archive(::cereal::make_nvp("fragmented", m_fragmented));
            archive(::cereal::make_nvp("checksum_error", m_checksum_error));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_header_flags_t& m) {
        uint64_t m_header_error;
        uint64_t m_fragmented;
        uint64_t m_checksum_error;
            archive(::cereal::make_nvp("header_error", m_header_error));
            archive(::cereal::make_nvp("fragmented", m_fragmented));
            archive(::cereal::make_nvp("checksum_error", m_checksum_error));
        m.header_error = m_header_error;
        m.fragmented = m_fragmented;
        m.checksum_error = m_checksum_error;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_header_flags_t& m)
{
    serializer_class<npl_ipv4_header_flags_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_header_flags_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_header_flags_t& m)
{
    serializer_class<npl_ipv4_header_flags_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_header_flags_t&);



template<>
class serializer_class<npl_ipv4_ipv6_init_rtf_stage_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_ipv6_init_rtf_stage_t& m) {
            archive(::cereal::make_nvp("ipv4_init_rtf_stage", m.ipv4_init_rtf_stage));
            archive(::cereal::make_nvp("ipv6_init_rtf_stage", m.ipv6_init_rtf_stage));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_ipv6_init_rtf_stage_t& m) {
            archive(::cereal::make_nvp("ipv4_init_rtf_stage", m.ipv4_init_rtf_stage));
            archive(::cereal::make_nvp("ipv6_init_rtf_stage", m.ipv6_init_rtf_stage));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_ipv6_init_rtf_stage_t& m)
{
    serializer_class<npl_ipv4_ipv6_init_rtf_stage_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_ipv6_init_rtf_stage_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_ipv6_init_rtf_stage_t& m)
{
    serializer_class<npl_ipv4_ipv6_init_rtf_stage_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_ipv6_init_rtf_stage_t&);



template<>
class serializer_class<npl_ipv4_sip_dip_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_sip_dip_t& m) {
        uint64_t m_sip = m.sip;
        uint64_t m_dip = m.dip;
            archive(::cereal::make_nvp("sip", m_sip));
            archive(::cereal::make_nvp("dip", m_dip));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_sip_dip_t& m) {
        uint64_t m_sip;
        uint64_t m_dip;
            archive(::cereal::make_nvp("sip", m_sip));
            archive(::cereal::make_nvp("dip", m_dip));
        m.sip = m_sip;
        m.dip = m_dip;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_sip_dip_t& m)
{
    serializer_class<npl_ipv4_sip_dip_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_sip_dip_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_sip_dip_t& m)
{
    serializer_class<npl_ipv4_sip_dip_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_sip_dip_t&);



template<>
class serializer_class<npl_ipv4_traps_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_traps_t& m) {
        uint64_t m_mc_forwarding_disabled = m.mc_forwarding_disabled;
        uint64_t m_uc_forwarding_disabled = m.uc_forwarding_disabled;
        uint64_t m_checksum = m.checksum;
        uint64_t m_header_error = m.header_error;
        uint64_t m_unknown_protocol = m.unknown_protocol;
        uint64_t m_options_exist = m.options_exist;
        uint64_t m_non_comp_mc = m.non_comp_mc;
            archive(::cereal::make_nvp("mc_forwarding_disabled", m_mc_forwarding_disabled));
            archive(::cereal::make_nvp("uc_forwarding_disabled", m_uc_forwarding_disabled));
            archive(::cereal::make_nvp("checksum", m_checksum));
            archive(::cereal::make_nvp("header_error", m_header_error));
            archive(::cereal::make_nvp("unknown_protocol", m_unknown_protocol));
            archive(::cereal::make_nvp("options_exist", m_options_exist));
            archive(::cereal::make_nvp("non_comp_mc", m_non_comp_mc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_traps_t& m) {
        uint64_t m_mc_forwarding_disabled;
        uint64_t m_uc_forwarding_disabled;
        uint64_t m_checksum;
        uint64_t m_header_error;
        uint64_t m_unknown_protocol;
        uint64_t m_options_exist;
        uint64_t m_non_comp_mc;
            archive(::cereal::make_nvp("mc_forwarding_disabled", m_mc_forwarding_disabled));
            archive(::cereal::make_nvp("uc_forwarding_disabled", m_uc_forwarding_disabled));
            archive(::cereal::make_nvp("checksum", m_checksum));
            archive(::cereal::make_nvp("header_error", m_header_error));
            archive(::cereal::make_nvp("unknown_protocol", m_unknown_protocol));
            archive(::cereal::make_nvp("options_exist", m_options_exist));
            archive(::cereal::make_nvp("non_comp_mc", m_non_comp_mc));
        m.mc_forwarding_disabled = m_mc_forwarding_disabled;
        m.uc_forwarding_disabled = m_uc_forwarding_disabled;
        m.checksum = m_checksum;
        m.header_error = m_header_error;
        m.unknown_protocol = m_unknown_protocol;
        m.options_exist = m_options_exist;
        m.non_comp_mc = m_non_comp_mc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_traps_t& m)
{
    serializer_class<npl_ipv4_traps_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_traps_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_traps_t& m)
{
    serializer_class<npl_ipv4_traps_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_traps_t&);



template<>
class serializer_class<npl_ipv4_ttl_and_protocol_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_ttl_and_protocol_t& m) {
        uint64_t m_ttl = m.ttl;
        uint64_t m_protocol = m.protocol;
            archive(::cereal::make_nvp("ttl", m_ttl));
            archive(::cereal::make_nvp("protocol", m_protocol));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_ttl_and_protocol_t& m) {
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
save(Archive& archive, const npl_ipv4_ttl_and_protocol_t& m)
{
    serializer_class<npl_ipv4_ttl_and_protocol_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_ttl_and_protocol_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_ttl_and_protocol_t& m)
{
    serializer_class<npl_ipv4_ttl_and_protocol_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_ttl_and_protocol_t&);



template<>
class serializer_class<npl_ipv6_header_flags_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_header_flags_t& m) {
        uint64_t m_header_error = m.header_error;
        uint64_t m_not_first_fragment = m.not_first_fragment;
            archive(::cereal::make_nvp("header_error", m_header_error));
            archive(::cereal::make_nvp("not_first_fragment", m_not_first_fragment));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_header_flags_t& m) {
        uint64_t m_header_error;
        uint64_t m_not_first_fragment;
            archive(::cereal::make_nvp("header_error", m_header_error));
            archive(::cereal::make_nvp("not_first_fragment", m_not_first_fragment));
        m.header_error = m_header_error;
        m.not_first_fragment = m_not_first_fragment;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_header_flags_t& m)
{
    serializer_class<npl_ipv6_header_flags_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_header_flags_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_header_flags_t& m)
{
    serializer_class<npl_ipv6_header_flags_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_header_flags_t&);



template<>
class serializer_class<npl_ipv6_next_header_and_hop_limit_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_next_header_and_hop_limit_t& m) {
        uint64_t m_next_header = m.next_header;
        uint64_t m_hop_limit = m.hop_limit;
            archive(::cereal::make_nvp("next_header", m_next_header));
            archive(::cereal::make_nvp("hop_limit", m_hop_limit));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_next_header_and_hop_limit_t& m) {
        uint64_t m_next_header;
        uint64_t m_hop_limit;
            archive(::cereal::make_nvp("next_header", m_next_header));
            archive(::cereal::make_nvp("hop_limit", m_hop_limit));
        m.next_header = m_next_header;
        m.hop_limit = m_hop_limit;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_next_header_and_hop_limit_t& m)
{
    serializer_class<npl_ipv6_next_header_and_hop_limit_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_next_header_and_hop_limit_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_next_header_and_hop_limit_t& m)
{
    serializer_class<npl_ipv6_next_header_and_hop_limit_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_next_header_and_hop_limit_t&);



template<>
class serializer_class<npl_ipv6_traps_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_traps_t& m) {
        uint64_t m_mc_forwarding_disabled = m.mc_forwarding_disabled;
        uint64_t m_uc_forwarding_disabled = m.uc_forwarding_disabled;
        uint64_t m_hop_by_hop = m.hop_by_hop;
        uint64_t m_header_error = m.header_error;
        uint64_t m_illegal_sip = m.illegal_sip;
        uint64_t m_illegal_dip = m.illegal_dip;
        uint64_t m_zero_payload = m.zero_payload;
        uint64_t m_next_header_check = m.next_header_check;
        uint64_t m_non_comp_mc = m.non_comp_mc;
            archive(::cereal::make_nvp("mc_forwarding_disabled", m_mc_forwarding_disabled));
            archive(::cereal::make_nvp("uc_forwarding_disabled", m_uc_forwarding_disabled));
            archive(::cereal::make_nvp("hop_by_hop", m_hop_by_hop));
            archive(::cereal::make_nvp("header_error", m_header_error));
            archive(::cereal::make_nvp("illegal_sip", m_illegal_sip));
            archive(::cereal::make_nvp("illegal_dip", m_illegal_dip));
            archive(::cereal::make_nvp("zero_payload", m_zero_payload));
            archive(::cereal::make_nvp("next_header_check", m_next_header_check));
            archive(::cereal::make_nvp("non_comp_mc", m_non_comp_mc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_traps_t& m) {
        uint64_t m_mc_forwarding_disabled;
        uint64_t m_uc_forwarding_disabled;
        uint64_t m_hop_by_hop;
        uint64_t m_header_error;
        uint64_t m_illegal_sip;
        uint64_t m_illegal_dip;
        uint64_t m_zero_payload;
        uint64_t m_next_header_check;
        uint64_t m_non_comp_mc;
            archive(::cereal::make_nvp("mc_forwarding_disabled", m_mc_forwarding_disabled));
            archive(::cereal::make_nvp("uc_forwarding_disabled", m_uc_forwarding_disabled));
            archive(::cereal::make_nvp("hop_by_hop", m_hop_by_hop));
            archive(::cereal::make_nvp("header_error", m_header_error));
            archive(::cereal::make_nvp("illegal_sip", m_illegal_sip));
            archive(::cereal::make_nvp("illegal_dip", m_illegal_dip));
            archive(::cereal::make_nvp("zero_payload", m_zero_payload));
            archive(::cereal::make_nvp("next_header_check", m_next_header_check));
            archive(::cereal::make_nvp("non_comp_mc", m_non_comp_mc));
        m.mc_forwarding_disabled = m_mc_forwarding_disabled;
        m.uc_forwarding_disabled = m_uc_forwarding_disabled;
        m.hop_by_hop = m_hop_by_hop;
        m.header_error = m_header_error;
        m.illegal_sip = m_illegal_sip;
        m.illegal_dip = m_illegal_dip;
        m.zero_payload = m_zero_payload;
        m.next_header_check = m_next_header_check;
        m.non_comp_mc = m_non_comp_mc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_traps_t& m)
{
    serializer_class<npl_ipv6_traps_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_traps_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_traps_t& m)
{
    serializer_class<npl_ipv6_traps_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_traps_t&);



template<>
class serializer_class<npl_is_inject_up_and_ip_first_fragment_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_is_inject_up_and_ip_first_fragment_t& m) {
            archive(::cereal::make_nvp("is_inject_up_dest_override", m.is_inject_up_dest_override));
            archive(::cereal::make_nvp("is_inject_up", m.is_inject_up));
            archive(::cereal::make_nvp("ip_first_fragment", m.ip_first_fragment));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_is_inject_up_and_ip_first_fragment_t& m) {
            archive(::cereal::make_nvp("is_inject_up_dest_override", m.is_inject_up_dest_override));
            archive(::cereal::make_nvp("is_inject_up", m.is_inject_up));
            archive(::cereal::make_nvp("ip_first_fragment", m.ip_first_fragment));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_is_inject_up_and_ip_first_fragment_t& m)
{
    serializer_class<npl_is_inject_up_and_ip_first_fragment_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_is_inject_up_and_ip_first_fragment_t&);

template <class Archive>
void
load(Archive& archive, npl_is_inject_up_and_ip_first_fragment_t& m)
{
    serializer_class<npl_is_inject_up_and_ip_first_fragment_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_is_inject_up_and_ip_first_fragment_t&);



template<>
class serializer_class<npl_is_pbts_prefix_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_is_pbts_prefix_t& m) {
            archive(::cereal::make_nvp("val", m.val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_is_pbts_prefix_t& m) {
            archive(::cereal::make_nvp("val", m.val));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_is_pbts_prefix_t& m)
{
    serializer_class<npl_is_pbts_prefix_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_is_pbts_prefix_t&);

template <class Archive>
void
load(Archive& archive, npl_is_pbts_prefix_t& m)
{
    serializer_class<npl_is_pbts_prefix_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_is_pbts_prefix_t&);



template<>
class serializer_class<npl_ive_enable_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ive_enable_t& m) {
        uint64_t m_enable = m.enable;
            archive(::cereal::make_nvp("enable", m_enable));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ive_enable_t& m) {
        uint64_t m_enable;
            archive(::cereal::make_nvp("enable", m_enable));
        m.enable = m_enable;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ive_enable_t& m)
{
    serializer_class<npl_ive_enable_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ive_enable_t&);

template <class Archive>
void
load(Archive& archive, npl_ive_enable_t& m)
{
    serializer_class<npl_ive_enable_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ive_enable_t&);



template<>
class serializer_class<npl_l2_dlp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_dlp_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_dlp_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_dlp_t& m)
{
    serializer_class<npl_l2_dlp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_dlp_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_dlp_t& m)
{
    serializer_class<npl_l2_dlp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_dlp_t&);



template<>
class serializer_class<npl_l2_global_slp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_global_slp_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_global_slp_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_global_slp_t& m)
{
    serializer_class<npl_l2_global_slp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_global_slp_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_global_slp_t& m)
{
    serializer_class<npl_l2_global_slp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_global_slp_t&);



template<>
class serializer_class<npl_l2_lpts_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_attributes_t& m) {
        uint64_t m_mac_terminated = m.mac_terminated;
            archive(::cereal::make_nvp("mac_terminated", m_mac_terminated));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_attributes_t& m) {
        uint64_t m_mac_terminated;
            archive(::cereal::make_nvp("mac_terminated", m_mac_terminated));
        m.mac_terminated = m_mac_terminated;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_attributes_t& m)
{
    serializer_class<npl_l2_lpts_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_attributes_t& m)
{
    serializer_class<npl_l2_lpts_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_attributes_t&);



template<>
class serializer_class<npl_l2_lpts_ip_fragment_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_ip_fragment_t& m) {
        uint64_t m_v6_not_first_fragment = m.v6_not_first_fragment;
        uint64_t m_v4_not_first_fragment = m.v4_not_first_fragment;
            archive(::cereal::make_nvp("v6_not_first_fragment", m_v6_not_first_fragment));
            archive(::cereal::make_nvp("v4_not_first_fragment", m_v4_not_first_fragment));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_ip_fragment_t& m) {
        uint64_t m_v6_not_first_fragment;
        uint64_t m_v4_not_first_fragment;
            archive(::cereal::make_nvp("v6_not_first_fragment", m_v6_not_first_fragment));
            archive(::cereal::make_nvp("v4_not_first_fragment", m_v4_not_first_fragment));
        m.v6_not_first_fragment = m_v6_not_first_fragment;
        m.v4_not_first_fragment = m_v4_not_first_fragment;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_ip_fragment_t& m)
{
    serializer_class<npl_l2_lpts_ip_fragment_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_ip_fragment_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_ip_fragment_t& m)
{
    serializer_class<npl_l2_lpts_ip_fragment_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_ip_fragment_t&);



template<>
class serializer_class<npl_l2_lpts_next_macro_pack_fields_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_next_macro_pack_fields_t& m) {
        uint64_t m_l2_lpts = m.l2_lpts;
            archive(::cereal::make_nvp("l2_lpts", m_l2_lpts));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_next_macro_pack_fields_t& m) {
        uint64_t m_l2_lpts;
            archive(::cereal::make_nvp("l2_lpts", m_l2_lpts));
        m.l2_lpts = m_l2_lpts;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_next_macro_pack_fields_t& m)
{
    serializer_class<npl_l2_lpts_next_macro_pack_fields_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_next_macro_pack_fields_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_next_macro_pack_fields_t& m)
{
    serializer_class<npl_l2_lpts_next_macro_pack_fields_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_next_macro_pack_fields_t&);



template<>
class serializer_class<npl_l2_lpts_traps_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_traps_t& m) {
        uint64_t m_trap0 = m.trap0;
        uint64_t m_trap1 = m.trap1;
        uint64_t m_trap2 = m.trap2;
        uint64_t m_trap3 = m.trap3;
        uint64_t m_trap4 = m.trap4;
        uint64_t m_trap5 = m.trap5;
        uint64_t m_trap6 = m.trap6;
        uint64_t m_trap7 = m.trap7;
        uint64_t m_trap8 = m.trap8;
        uint64_t m_trap9 = m.trap9;
        uint64_t m_trap10 = m.trap10;
        uint64_t m_trap11 = m.trap11;
            archive(::cereal::make_nvp("trap0", m_trap0));
            archive(::cereal::make_nvp("trap1", m_trap1));
            archive(::cereal::make_nvp("trap2", m_trap2));
            archive(::cereal::make_nvp("trap3", m_trap3));
            archive(::cereal::make_nvp("trap4", m_trap4));
            archive(::cereal::make_nvp("trap5", m_trap5));
            archive(::cereal::make_nvp("trap6", m_trap6));
            archive(::cereal::make_nvp("trap7", m_trap7));
            archive(::cereal::make_nvp("trap8", m_trap8));
            archive(::cereal::make_nvp("trap9", m_trap9));
            archive(::cereal::make_nvp("trap10", m_trap10));
            archive(::cereal::make_nvp("trap11", m_trap11));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_traps_t& m) {
        uint64_t m_trap0;
        uint64_t m_trap1;
        uint64_t m_trap2;
        uint64_t m_trap3;
        uint64_t m_trap4;
        uint64_t m_trap5;
        uint64_t m_trap6;
        uint64_t m_trap7;
        uint64_t m_trap8;
        uint64_t m_trap9;
        uint64_t m_trap10;
        uint64_t m_trap11;
            archive(::cereal::make_nvp("trap0", m_trap0));
            archive(::cereal::make_nvp("trap1", m_trap1));
            archive(::cereal::make_nvp("trap2", m_trap2));
            archive(::cereal::make_nvp("trap3", m_trap3));
            archive(::cereal::make_nvp("trap4", m_trap4));
            archive(::cereal::make_nvp("trap5", m_trap5));
            archive(::cereal::make_nvp("trap6", m_trap6));
            archive(::cereal::make_nvp("trap7", m_trap7));
            archive(::cereal::make_nvp("trap8", m_trap8));
            archive(::cereal::make_nvp("trap9", m_trap9));
            archive(::cereal::make_nvp("trap10", m_trap10));
            archive(::cereal::make_nvp("trap11", m_trap11));
        m.trap0 = m_trap0;
        m.trap1 = m_trap1;
        m.trap2 = m_trap2;
        m.trap3 = m_trap3;
        m.trap4 = m_trap4;
        m.trap5 = m_trap5;
        m.trap6 = m_trap6;
        m.trap7 = m_trap7;
        m.trap8 = m_trap8;
        m.trap9 = m_trap9;
        m.trap10 = m_trap10;
        m.trap11 = m_trap11;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_traps_t& m)
{
    serializer_class<npl_l2_lpts_traps_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_traps_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_traps_t& m)
{
    serializer_class<npl_l2_lpts_traps_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_traps_t&);



template<>
class serializer_class<npl_l2_relay_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_relay_id_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_relay_id_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_relay_id_t& m)
{
    serializer_class<npl_l2_relay_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_relay_id_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_relay_id_t& m)
{
    serializer_class<npl_l2_relay_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_relay_id_t&);



template<>
class serializer_class<npl_l2vpn_control_bits_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2vpn_control_bits_t& m) {
        uint64_t m_enable_pwe_cntr = m.enable_pwe_cntr;
        uint64_t m_no_fat = m.no_fat;
            archive(::cereal::make_nvp("enable_pwe_cntr", m_enable_pwe_cntr));
            archive(::cereal::make_nvp("no_fat", m_no_fat));
            archive(::cereal::make_nvp("cw_fat_exists", m.cw_fat_exists));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2vpn_control_bits_t& m) {
        uint64_t m_enable_pwe_cntr;
        uint64_t m_no_fat;
            archive(::cereal::make_nvp("enable_pwe_cntr", m_enable_pwe_cntr));
            archive(::cereal::make_nvp("no_fat", m_no_fat));
            archive(::cereal::make_nvp("cw_fat_exists", m.cw_fat_exists));
        m.enable_pwe_cntr = m_enable_pwe_cntr;
        m.no_fat = m_no_fat;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2vpn_control_bits_t& m)
{
    serializer_class<npl_l2vpn_control_bits_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2vpn_control_bits_t&);

template <class Archive>
void
load(Archive& archive, npl_l2vpn_control_bits_t& m)
{
    serializer_class<npl_l2vpn_control_bits_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2vpn_control_bits_t&);



template<>
class serializer_class<npl_l2vpn_label_encap_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2vpn_label_encap_data_t& m) {
        uint64_t m_lp_profile = m.lp_profile;
        uint64_t m_pwe_l2_dlp_id = m.pwe_l2_dlp_id;
        uint64_t m_label = m.label;
            archive(::cereal::make_nvp("pwe_encap_cntr", m.pwe_encap_cntr));
            archive(::cereal::make_nvp("lp_profile", m_lp_profile));
            archive(::cereal::make_nvp("first_ene_macro", m.first_ene_macro));
            archive(::cereal::make_nvp("pwe_l2_dlp_id", m_pwe_l2_dlp_id));
            archive(::cereal::make_nvp("l2vpn_control_bits", m.l2vpn_control_bits));
            archive(::cereal::make_nvp("label", m_label));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2vpn_label_encap_data_t& m) {
        uint64_t m_lp_profile;
        uint64_t m_pwe_l2_dlp_id;
        uint64_t m_label;
            archive(::cereal::make_nvp("pwe_encap_cntr", m.pwe_encap_cntr));
            archive(::cereal::make_nvp("lp_profile", m_lp_profile));
            archive(::cereal::make_nvp("first_ene_macro", m.first_ene_macro));
            archive(::cereal::make_nvp("pwe_l2_dlp_id", m_pwe_l2_dlp_id));
            archive(::cereal::make_nvp("l2vpn_control_bits", m.l2vpn_control_bits));
            archive(::cereal::make_nvp("label", m_label));
        m.lp_profile = m_lp_profile;
        m.pwe_l2_dlp_id = m_pwe_l2_dlp_id;
        m.label = m_label;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2vpn_label_encap_data_t& m)
{
    serializer_class<npl_l2vpn_label_encap_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2vpn_label_encap_data_t&);

template <class Archive>
void
load(Archive& archive, npl_l2vpn_label_encap_data_t& m)
{
    serializer_class<npl_l2vpn_label_encap_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2vpn_label_encap_data_t&);



template<>
class serializer_class<npl_l3_dlp_lsbs_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_dlp_lsbs_t& m) {
        uint64_t m_l3_dlp_lsbs = m.l3_dlp_lsbs;
            archive(::cereal::make_nvp("l3_dlp_lsbs", m_l3_dlp_lsbs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_dlp_lsbs_t& m) {
        uint64_t m_l3_dlp_lsbs;
            archive(::cereal::make_nvp("l3_dlp_lsbs", m_l3_dlp_lsbs));
        m.l3_dlp_lsbs = m_l3_dlp_lsbs;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_dlp_lsbs_t& m)
{
    serializer_class<npl_l3_dlp_lsbs_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_dlp_lsbs_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_dlp_lsbs_t& m)
{
    serializer_class<npl_l3_dlp_lsbs_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_dlp_lsbs_t&);



template<>
class serializer_class<npl_l3_ecn_ctrl_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_ecn_ctrl_t& m) {
        uint64_t m_count_cong_pkt = m.count_cong_pkt;
        uint64_t m_disable_ecn = m.disable_ecn;
            archive(::cereal::make_nvp("count_cong_pkt", m_count_cong_pkt));
            archive(::cereal::make_nvp("disable_ecn", m_disable_ecn));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_ecn_ctrl_t& m) {
        uint64_t m_count_cong_pkt;
        uint64_t m_disable_ecn;
            archive(::cereal::make_nvp("count_cong_pkt", m_count_cong_pkt));
            archive(::cereal::make_nvp("disable_ecn", m_disable_ecn));
        m.count_cong_pkt = m_count_cong_pkt;
        m.disable_ecn = m_disable_ecn;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_ecn_ctrl_t& m)
{
    serializer_class<npl_l3_ecn_ctrl_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_ecn_ctrl_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_ecn_ctrl_t& m)
{
    serializer_class<npl_l3_ecn_ctrl_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_ecn_ctrl_t&);



template<>
class serializer_class<npl_l3_pfc_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_pfc_data_t& m) {
        uint64_t m_tc = m.tc;
        uint64_t m_dsp = m.dsp;
            archive(::cereal::make_nvp("tc", m_tc));
            archive(::cereal::make_nvp("dsp", m_dsp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_pfc_data_t& m) {
        uint64_t m_tc;
        uint64_t m_dsp;
            archive(::cereal::make_nvp("tc", m_tc));
            archive(::cereal::make_nvp("dsp", m_dsp));
        m.tc = m_tc;
        m.dsp = m_dsp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_pfc_data_t& m)
{
    serializer_class<npl_l3_pfc_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_pfc_data_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_pfc_data_t& m)
{
    serializer_class<npl_l3_pfc_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_pfc_data_t&);



template<>
class serializer_class<npl_l3_relay_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_relay_id_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_relay_id_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_relay_id_t& m)
{
    serializer_class<npl_l3_relay_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_relay_id_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_relay_id_t& m)
{
    serializer_class<npl_l3_relay_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_relay_id_t&);



template<>
class serializer_class<npl_l3_slp_lsbs_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_slp_lsbs_t& m) {
        uint64_t m_l3_slp_lsbs = m.l3_slp_lsbs;
            archive(::cereal::make_nvp("l3_slp_lsbs", m_l3_slp_lsbs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_slp_lsbs_t& m) {
        uint64_t m_l3_slp_lsbs;
            archive(::cereal::make_nvp("l3_slp_lsbs", m_l3_slp_lsbs));
        m.l3_slp_lsbs = m_l3_slp_lsbs;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_slp_lsbs_t& m)
{
    serializer_class<npl_l3_slp_lsbs_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_slp_lsbs_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_slp_lsbs_t& m)
{
    serializer_class<npl_l3_slp_lsbs_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_slp_lsbs_t&);



template<>
class serializer_class<npl_l3_traps_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_traps_t& m) {
        uint64_t m_ip_unicast_rpf = m.ip_unicast_rpf;
        uint64_t m_ip_multicast_rpf = m.ip_multicast_rpf;
        uint64_t m_ip_mc_drop = m.ip_mc_drop;
        uint64_t m_ip_mc_punt_dc_pass = m.ip_mc_punt_dc_pass;
        uint64_t m_ip_mc_snoop_dc_pass = m.ip_mc_snoop_dc_pass;
        uint64_t m_ip_mc_snoop_rpf_fail = m.ip_mc_snoop_rpf_fail;
        uint64_t m_ip_mc_punt_rpf_fail = m.ip_mc_punt_rpf_fail;
        uint64_t m_ip_mc_snoop_lookup_miss = m.ip_mc_snoop_lookup_miss;
        uint64_t m_ip_multicast_not_found = m.ip_multicast_not_found;
        uint64_t m_ip_mc_s_g_punt_member = m.ip_mc_s_g_punt_member;
        uint64_t m_ip_mc_g_punt_member = m.ip_mc_g_punt_member;
        uint64_t m_ip_mc_egress_punt = m.ip_mc_egress_punt;
        uint64_t m_isis_over_l3 = m.isis_over_l3;
        uint64_t m_isis_drain = m.isis_drain;
        uint64_t m_no_hbm_access_dip = m.no_hbm_access_dip;
        uint64_t m_no_hbm_access_sip = m.no_hbm_access_sip;
        uint64_t m_lpm_error = m.lpm_error;
        uint64_t m_lpm_drop = m.lpm_drop;
        uint64_t m_local_subnet = m.local_subnet;
        uint64_t m_icmp_redirect = m.icmp_redirect;
        uint64_t m_no_lp_over_lag_mapping = m.no_lp_over_lag_mapping;
        uint64_t m_ingress_monitor = m.ingress_monitor;
        uint64_t m_egress_monitor = m.egress_monitor;
        uint64_t m_acl_drop = m.acl_drop;
        uint64_t m_acl_force_punt = m.acl_force_punt;
        uint64_t m_acl_force_punt1 = m.acl_force_punt1;
        uint64_t m_acl_force_punt2 = m.acl_force_punt2;
        uint64_t m_acl_force_punt3 = m.acl_force_punt3;
        uint64_t m_acl_force_punt4 = m.acl_force_punt4;
        uint64_t m_acl_force_punt5 = m.acl_force_punt5;
        uint64_t m_acl_force_punt6 = m.acl_force_punt6;
        uint64_t m_acl_force_punt7 = m.acl_force_punt7;
        uint64_t m_glean_adj = m.glean_adj;
        uint64_t m_drop_adj = m.drop_adj;
        uint64_t m_drop_adj_non_inject = m.drop_adj_non_inject;
        uint64_t m_null_adj = m.null_adj;
        uint64_t m_user_trap1 = m.user_trap1;
        uint64_t m_user_trap2 = m.user_trap2;
        uint64_t m_lpm_default_drop = m.lpm_default_drop;
        uint64_t m_lpm_incomplete0 = m.lpm_incomplete0;
        uint64_t m_lpm_incomplete2 = m.lpm_incomplete2;
        uint64_t m_bfd_micro_ip_disabled = m.bfd_micro_ip_disabled;
        uint64_t m_no_vni_mapping = m.no_vni_mapping;
        uint64_t m_no_hbm_access_og_sip = m.no_hbm_access_og_sip;
        uint64_t m_no_hbm_access_og_dip = m.no_hbm_access_og_dip;
        uint64_t m_no_l3_dlp_mapping = m.no_l3_dlp_mapping;
        uint64_t m_l3_dlp_disabled = m.l3_dlp_disabled;
        uint64_t m_split_horizon = m.split_horizon;
        uint64_t m_mc_same_interface = m.mc_same_interface;
        uint64_t m_no_vpn_label_found = m.no_vpn_label_found;
        uint64_t m_ttl_or_hop_limit_is_one = m.ttl_or_hop_limit_is_one;
        uint64_t m_tx_mtu_failure = m.tx_mtu_failure;
        uint64_t m_tx_frr_drop = m.tx_frr_drop;
            archive(::cereal::make_nvp("ip_unicast_rpf", m_ip_unicast_rpf));
            archive(::cereal::make_nvp("ip_multicast_rpf", m_ip_multicast_rpf));
            archive(::cereal::make_nvp("ip_mc_drop", m_ip_mc_drop));
            archive(::cereal::make_nvp("ip_mc_punt_dc_pass", m_ip_mc_punt_dc_pass));
            archive(::cereal::make_nvp("ip_mc_snoop_dc_pass", m_ip_mc_snoop_dc_pass));
            archive(::cereal::make_nvp("ip_mc_snoop_rpf_fail", m_ip_mc_snoop_rpf_fail));
            archive(::cereal::make_nvp("ip_mc_punt_rpf_fail", m_ip_mc_punt_rpf_fail));
            archive(::cereal::make_nvp("ip_mc_snoop_lookup_miss", m_ip_mc_snoop_lookup_miss));
            archive(::cereal::make_nvp("ip_multicast_not_found", m_ip_multicast_not_found));
            archive(::cereal::make_nvp("ip_mc_s_g_punt_member", m_ip_mc_s_g_punt_member));
            archive(::cereal::make_nvp("ip_mc_g_punt_member", m_ip_mc_g_punt_member));
            archive(::cereal::make_nvp("ip_mc_egress_punt", m_ip_mc_egress_punt));
            archive(::cereal::make_nvp("isis_over_l3", m_isis_over_l3));
            archive(::cereal::make_nvp("isis_drain", m_isis_drain));
            archive(::cereal::make_nvp("no_hbm_access_dip", m_no_hbm_access_dip));
            archive(::cereal::make_nvp("no_hbm_access_sip", m_no_hbm_access_sip));
            archive(::cereal::make_nvp("lpm_error", m_lpm_error));
            archive(::cereal::make_nvp("lpm_drop", m_lpm_drop));
            archive(::cereal::make_nvp("local_subnet", m_local_subnet));
            archive(::cereal::make_nvp("icmp_redirect", m_icmp_redirect));
            archive(::cereal::make_nvp("no_lp_over_lag_mapping", m_no_lp_over_lag_mapping));
            archive(::cereal::make_nvp("ingress_monitor", m_ingress_monitor));
            archive(::cereal::make_nvp("egress_monitor", m_egress_monitor));
            archive(::cereal::make_nvp("acl_drop", m_acl_drop));
            archive(::cereal::make_nvp("acl_force_punt", m_acl_force_punt));
            archive(::cereal::make_nvp("acl_force_punt1", m_acl_force_punt1));
            archive(::cereal::make_nvp("acl_force_punt2", m_acl_force_punt2));
            archive(::cereal::make_nvp("acl_force_punt3", m_acl_force_punt3));
            archive(::cereal::make_nvp("acl_force_punt4", m_acl_force_punt4));
            archive(::cereal::make_nvp("acl_force_punt5", m_acl_force_punt5));
            archive(::cereal::make_nvp("acl_force_punt6", m_acl_force_punt6));
            archive(::cereal::make_nvp("acl_force_punt7", m_acl_force_punt7));
            archive(::cereal::make_nvp("glean_adj", m_glean_adj));
            archive(::cereal::make_nvp("drop_adj", m_drop_adj));
            archive(::cereal::make_nvp("drop_adj_non_inject", m_drop_adj_non_inject));
            archive(::cereal::make_nvp("null_adj", m_null_adj));
            archive(::cereal::make_nvp("user_trap1", m_user_trap1));
            archive(::cereal::make_nvp("user_trap2", m_user_trap2));
            archive(::cereal::make_nvp("lpm_default_drop", m_lpm_default_drop));
            archive(::cereal::make_nvp("lpm_incomplete0", m_lpm_incomplete0));
            archive(::cereal::make_nvp("lpm_incomplete2", m_lpm_incomplete2));
            archive(::cereal::make_nvp("bfd_micro_ip_disabled", m_bfd_micro_ip_disabled));
            archive(::cereal::make_nvp("no_vni_mapping", m_no_vni_mapping));
            archive(::cereal::make_nvp("no_hbm_access_og_sip", m_no_hbm_access_og_sip));
            archive(::cereal::make_nvp("no_hbm_access_og_dip", m_no_hbm_access_og_dip));
            archive(::cereal::make_nvp("no_l3_dlp_mapping", m_no_l3_dlp_mapping));
            archive(::cereal::make_nvp("l3_dlp_disabled", m_l3_dlp_disabled));
            archive(::cereal::make_nvp("split_horizon", m_split_horizon));
            archive(::cereal::make_nvp("mc_same_interface", m_mc_same_interface));
            archive(::cereal::make_nvp("no_vpn_label_found", m_no_vpn_label_found));
            archive(::cereal::make_nvp("ttl_or_hop_limit_is_one", m_ttl_or_hop_limit_is_one));
            archive(::cereal::make_nvp("tx_mtu_failure", m_tx_mtu_failure));
            archive(::cereal::make_nvp("tx_frr_drop", m_tx_frr_drop));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_traps_t& m) {
        uint64_t m_ip_unicast_rpf;
        uint64_t m_ip_multicast_rpf;
        uint64_t m_ip_mc_drop;
        uint64_t m_ip_mc_punt_dc_pass;
        uint64_t m_ip_mc_snoop_dc_pass;
        uint64_t m_ip_mc_snoop_rpf_fail;
        uint64_t m_ip_mc_punt_rpf_fail;
        uint64_t m_ip_mc_snoop_lookup_miss;
        uint64_t m_ip_multicast_not_found;
        uint64_t m_ip_mc_s_g_punt_member;
        uint64_t m_ip_mc_g_punt_member;
        uint64_t m_ip_mc_egress_punt;
        uint64_t m_isis_over_l3;
        uint64_t m_isis_drain;
        uint64_t m_no_hbm_access_dip;
        uint64_t m_no_hbm_access_sip;
        uint64_t m_lpm_error;
        uint64_t m_lpm_drop;
        uint64_t m_local_subnet;
        uint64_t m_icmp_redirect;
        uint64_t m_no_lp_over_lag_mapping;
        uint64_t m_ingress_monitor;
        uint64_t m_egress_monitor;
        uint64_t m_acl_drop;
        uint64_t m_acl_force_punt;
        uint64_t m_acl_force_punt1;
        uint64_t m_acl_force_punt2;
        uint64_t m_acl_force_punt3;
        uint64_t m_acl_force_punt4;
        uint64_t m_acl_force_punt5;
        uint64_t m_acl_force_punt6;
        uint64_t m_acl_force_punt7;
        uint64_t m_glean_adj;
        uint64_t m_drop_adj;
        uint64_t m_drop_adj_non_inject;
        uint64_t m_null_adj;
        uint64_t m_user_trap1;
        uint64_t m_user_trap2;
        uint64_t m_lpm_default_drop;
        uint64_t m_lpm_incomplete0;
        uint64_t m_lpm_incomplete2;
        uint64_t m_bfd_micro_ip_disabled;
        uint64_t m_no_vni_mapping;
        uint64_t m_no_hbm_access_og_sip;
        uint64_t m_no_hbm_access_og_dip;
        uint64_t m_no_l3_dlp_mapping;
        uint64_t m_l3_dlp_disabled;
        uint64_t m_split_horizon;
        uint64_t m_mc_same_interface;
        uint64_t m_no_vpn_label_found;
        uint64_t m_ttl_or_hop_limit_is_one;
        uint64_t m_tx_mtu_failure;
        uint64_t m_tx_frr_drop;
            archive(::cereal::make_nvp("ip_unicast_rpf", m_ip_unicast_rpf));
            archive(::cereal::make_nvp("ip_multicast_rpf", m_ip_multicast_rpf));
            archive(::cereal::make_nvp("ip_mc_drop", m_ip_mc_drop));
            archive(::cereal::make_nvp("ip_mc_punt_dc_pass", m_ip_mc_punt_dc_pass));
            archive(::cereal::make_nvp("ip_mc_snoop_dc_pass", m_ip_mc_snoop_dc_pass));
            archive(::cereal::make_nvp("ip_mc_snoop_rpf_fail", m_ip_mc_snoop_rpf_fail));
            archive(::cereal::make_nvp("ip_mc_punt_rpf_fail", m_ip_mc_punt_rpf_fail));
            archive(::cereal::make_nvp("ip_mc_snoop_lookup_miss", m_ip_mc_snoop_lookup_miss));
            archive(::cereal::make_nvp("ip_multicast_not_found", m_ip_multicast_not_found));
            archive(::cereal::make_nvp("ip_mc_s_g_punt_member", m_ip_mc_s_g_punt_member));
            archive(::cereal::make_nvp("ip_mc_g_punt_member", m_ip_mc_g_punt_member));
            archive(::cereal::make_nvp("ip_mc_egress_punt", m_ip_mc_egress_punt));
            archive(::cereal::make_nvp("isis_over_l3", m_isis_over_l3));
            archive(::cereal::make_nvp("isis_drain", m_isis_drain));
            archive(::cereal::make_nvp("no_hbm_access_dip", m_no_hbm_access_dip));
            archive(::cereal::make_nvp("no_hbm_access_sip", m_no_hbm_access_sip));
            archive(::cereal::make_nvp("lpm_error", m_lpm_error));
            archive(::cereal::make_nvp("lpm_drop", m_lpm_drop));
            archive(::cereal::make_nvp("local_subnet", m_local_subnet));
            archive(::cereal::make_nvp("icmp_redirect", m_icmp_redirect));
            archive(::cereal::make_nvp("no_lp_over_lag_mapping", m_no_lp_over_lag_mapping));
            archive(::cereal::make_nvp("ingress_monitor", m_ingress_monitor));
            archive(::cereal::make_nvp("egress_monitor", m_egress_monitor));
            archive(::cereal::make_nvp("acl_drop", m_acl_drop));
            archive(::cereal::make_nvp("acl_force_punt", m_acl_force_punt));
            archive(::cereal::make_nvp("acl_force_punt1", m_acl_force_punt1));
            archive(::cereal::make_nvp("acl_force_punt2", m_acl_force_punt2));
            archive(::cereal::make_nvp("acl_force_punt3", m_acl_force_punt3));
            archive(::cereal::make_nvp("acl_force_punt4", m_acl_force_punt4));
            archive(::cereal::make_nvp("acl_force_punt5", m_acl_force_punt5));
            archive(::cereal::make_nvp("acl_force_punt6", m_acl_force_punt6));
            archive(::cereal::make_nvp("acl_force_punt7", m_acl_force_punt7));
            archive(::cereal::make_nvp("glean_adj", m_glean_adj));
            archive(::cereal::make_nvp("drop_adj", m_drop_adj));
            archive(::cereal::make_nvp("drop_adj_non_inject", m_drop_adj_non_inject));
            archive(::cereal::make_nvp("null_adj", m_null_adj));
            archive(::cereal::make_nvp("user_trap1", m_user_trap1));
            archive(::cereal::make_nvp("user_trap2", m_user_trap2));
            archive(::cereal::make_nvp("lpm_default_drop", m_lpm_default_drop));
            archive(::cereal::make_nvp("lpm_incomplete0", m_lpm_incomplete0));
            archive(::cereal::make_nvp("lpm_incomplete2", m_lpm_incomplete2));
            archive(::cereal::make_nvp("bfd_micro_ip_disabled", m_bfd_micro_ip_disabled));
            archive(::cereal::make_nvp("no_vni_mapping", m_no_vni_mapping));
            archive(::cereal::make_nvp("no_hbm_access_og_sip", m_no_hbm_access_og_sip));
            archive(::cereal::make_nvp("no_hbm_access_og_dip", m_no_hbm_access_og_dip));
            archive(::cereal::make_nvp("no_l3_dlp_mapping", m_no_l3_dlp_mapping));
            archive(::cereal::make_nvp("l3_dlp_disabled", m_l3_dlp_disabled));
            archive(::cereal::make_nvp("split_horizon", m_split_horizon));
            archive(::cereal::make_nvp("mc_same_interface", m_mc_same_interface));
            archive(::cereal::make_nvp("no_vpn_label_found", m_no_vpn_label_found));
            archive(::cereal::make_nvp("ttl_or_hop_limit_is_one", m_ttl_or_hop_limit_is_one));
            archive(::cereal::make_nvp("tx_mtu_failure", m_tx_mtu_failure));
            archive(::cereal::make_nvp("tx_frr_drop", m_tx_frr_drop));
        m.ip_unicast_rpf = m_ip_unicast_rpf;
        m.ip_multicast_rpf = m_ip_multicast_rpf;
        m.ip_mc_drop = m_ip_mc_drop;
        m.ip_mc_punt_dc_pass = m_ip_mc_punt_dc_pass;
        m.ip_mc_snoop_dc_pass = m_ip_mc_snoop_dc_pass;
        m.ip_mc_snoop_rpf_fail = m_ip_mc_snoop_rpf_fail;
        m.ip_mc_punt_rpf_fail = m_ip_mc_punt_rpf_fail;
        m.ip_mc_snoop_lookup_miss = m_ip_mc_snoop_lookup_miss;
        m.ip_multicast_not_found = m_ip_multicast_not_found;
        m.ip_mc_s_g_punt_member = m_ip_mc_s_g_punt_member;
        m.ip_mc_g_punt_member = m_ip_mc_g_punt_member;
        m.ip_mc_egress_punt = m_ip_mc_egress_punt;
        m.isis_over_l3 = m_isis_over_l3;
        m.isis_drain = m_isis_drain;
        m.no_hbm_access_dip = m_no_hbm_access_dip;
        m.no_hbm_access_sip = m_no_hbm_access_sip;
        m.lpm_error = m_lpm_error;
        m.lpm_drop = m_lpm_drop;
        m.local_subnet = m_local_subnet;
        m.icmp_redirect = m_icmp_redirect;
        m.no_lp_over_lag_mapping = m_no_lp_over_lag_mapping;
        m.ingress_monitor = m_ingress_monitor;
        m.egress_monitor = m_egress_monitor;
        m.acl_drop = m_acl_drop;
        m.acl_force_punt = m_acl_force_punt;
        m.acl_force_punt1 = m_acl_force_punt1;
        m.acl_force_punt2 = m_acl_force_punt2;
        m.acl_force_punt3 = m_acl_force_punt3;
        m.acl_force_punt4 = m_acl_force_punt4;
        m.acl_force_punt5 = m_acl_force_punt5;
        m.acl_force_punt6 = m_acl_force_punt6;
        m.acl_force_punt7 = m_acl_force_punt7;
        m.glean_adj = m_glean_adj;
        m.drop_adj = m_drop_adj;
        m.drop_adj_non_inject = m_drop_adj_non_inject;
        m.null_adj = m_null_adj;
        m.user_trap1 = m_user_trap1;
        m.user_trap2 = m_user_trap2;
        m.lpm_default_drop = m_lpm_default_drop;
        m.lpm_incomplete0 = m_lpm_incomplete0;
        m.lpm_incomplete2 = m_lpm_incomplete2;
        m.bfd_micro_ip_disabled = m_bfd_micro_ip_disabled;
        m.no_vni_mapping = m_no_vni_mapping;
        m.no_hbm_access_og_sip = m_no_hbm_access_og_sip;
        m.no_hbm_access_og_dip = m_no_hbm_access_og_dip;
        m.no_l3_dlp_mapping = m_no_l3_dlp_mapping;
        m.l3_dlp_disabled = m_l3_dlp_disabled;
        m.split_horizon = m_split_horizon;
        m.mc_same_interface = m_mc_same_interface;
        m.no_vpn_label_found = m_no_vpn_label_found;
        m.ttl_or_hop_limit_is_one = m_ttl_or_hop_limit_is_one;
        m.tx_mtu_failure = m_tx_mtu_failure;
        m.tx_frr_drop = m_tx_frr_drop;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_traps_t& m)
{
    serializer_class<npl_l3_traps_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_traps_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_traps_t& m)
{
    serializer_class<npl_l3_traps_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_traps_t&);



template<>
class serializer_class<npl_l4_ports_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l4_ports_header_t& m) {
        uint64_t m_src_port = m.src_port;
        uint64_t m_dst_port = m.dst_port;
            archive(::cereal::make_nvp("src_port", m_src_port));
            archive(::cereal::make_nvp("dst_port", m_dst_port));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l4_ports_header_t& m) {
        uint64_t m_src_port;
        uint64_t m_dst_port;
            archive(::cereal::make_nvp("src_port", m_src_port));
            archive(::cereal::make_nvp("dst_port", m_dst_port));
        m.src_port = m_src_port;
        m.dst_port = m_dst_port;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l4_ports_header_t& m)
{
    serializer_class<npl_l4_ports_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l4_ports_header_t&);

template <class Archive>
void
load(Archive& archive, npl_l4_ports_header_t& m)
{
    serializer_class<npl_l4_ports_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l4_ports_header_t&);



template<>
class serializer_class<npl_large_em_label_encap_data_and_counter_ptr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_large_em_label_encap_data_and_counter_ptr_t& m) {
        uint64_t m_num_labels = m.num_labels;
            archive(::cereal::make_nvp("num_labels", m_num_labels));
            archive(::cereal::make_nvp("label_encap", m.label_encap));
            archive(::cereal::make_nvp("counter_ptr", m.counter_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_large_em_label_encap_data_and_counter_ptr_t& m) {
        uint64_t m_num_labels;
            archive(::cereal::make_nvp("num_labels", m_num_labels));
            archive(::cereal::make_nvp("label_encap", m.label_encap));
            archive(::cereal::make_nvp("counter_ptr", m.counter_ptr));
        m.num_labels = m_num_labels;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_large_em_label_encap_data_and_counter_ptr_t& m)
{
    serializer_class<npl_large_em_label_encap_data_and_counter_ptr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_large_em_label_encap_data_and_counter_ptr_t&);

template <class Archive>
void
load(Archive& archive, npl_large_em_label_encap_data_and_counter_ptr_t& m)
{
    serializer_class<npl_large_em_label_encap_data_and_counter_ptr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_large_em_label_encap_data_and_counter_ptr_t&);



template<>
class serializer_class<npl_lb_group_size_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lb_group_size_table_result_t& m) {
        uint64_t m_curr_group_size = m.curr_group_size;
            archive(::cereal::make_nvp("curr_group_size", m_curr_group_size));
            archive(::cereal::make_nvp("consistency_mode", m.consistency_mode));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lb_group_size_table_result_t& m) {
        uint64_t m_curr_group_size;
            archive(::cereal::make_nvp("curr_group_size", m_curr_group_size));
            archive(::cereal::make_nvp("consistency_mode", m.consistency_mode));
        m.curr_group_size = m_curr_group_size;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lb_group_size_table_result_t& m)
{
    serializer_class<npl_lb_group_size_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lb_group_size_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_lb_group_size_table_result_t& m)
{
    serializer_class<npl_lb_group_size_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lb_group_size_table_result_t&);



template<>
class serializer_class<npl_lb_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lb_key_t& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lb_key_t& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lb_key_t& m)
{
    serializer_class<npl_lb_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lb_key_t&);

template <class Archive>
void
load(Archive& archive, npl_lb_key_t& m)
{
    serializer_class<npl_lb_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lb_key_t&);



template<>
class serializer_class<npl_learn_manager_cfg_max_learn_type_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_learn_manager_cfg_max_learn_type_t& m) {
            archive(::cereal::make_nvp("lr_type", m.lr_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_learn_manager_cfg_max_learn_type_t& m) {
            archive(::cereal::make_nvp("lr_type", m.lr_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_learn_manager_cfg_max_learn_type_t& m)
{
    serializer_class<npl_learn_manager_cfg_max_learn_type_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_learn_manager_cfg_max_learn_type_t&);

template <class Archive>
void
load(Archive& archive, npl_learn_manager_cfg_max_learn_type_t& m)
{
    serializer_class<npl_learn_manager_cfg_max_learn_type_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_learn_manager_cfg_max_learn_type_t&);



template<>
class serializer_class<npl_light_fi_stage_cfg_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_light_fi_stage_cfg_t& m) {
        uint64_t m_update_current_header_info = m.update_current_header_info;
        uint64_t m_size_width = m.size_width;
        uint64_t m_size_offset = m.size_offset;
        uint64_t m_next_protocol_or_type_width = m.next_protocol_or_type_width;
        uint64_t m_next_protocol_or_type_offset = m.next_protocol_or_type_offset;
            archive(::cereal::make_nvp("update_current_header_info", m_update_current_header_info));
            archive(::cereal::make_nvp("size_width", m_size_width));
            archive(::cereal::make_nvp("size_offset", m_size_offset));
            archive(::cereal::make_nvp("next_protocol_or_type_width", m_next_protocol_or_type_width));
            archive(::cereal::make_nvp("next_protocol_or_type_offset", m_next_protocol_or_type_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_stage_cfg_t& m) {
        uint64_t m_update_current_header_info;
        uint64_t m_size_width;
        uint64_t m_size_offset;
        uint64_t m_next_protocol_or_type_width;
        uint64_t m_next_protocol_or_type_offset;
            archive(::cereal::make_nvp("update_current_header_info", m_update_current_header_info));
            archive(::cereal::make_nvp("size_width", m_size_width));
            archive(::cereal::make_nvp("size_offset", m_size_offset));
            archive(::cereal::make_nvp("next_protocol_or_type_width", m_next_protocol_or_type_width));
            archive(::cereal::make_nvp("next_protocol_or_type_offset", m_next_protocol_or_type_offset));
        m.update_current_header_info = m_update_current_header_info;
        m.size_width = m_size_width;
        m.size_offset = m_size_offset;
        m.next_protocol_or_type_width = m_next_protocol_or_type_width;
        m.next_protocol_or_type_offset = m_next_protocol_or_type_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_light_fi_stage_cfg_t& m)
{
    serializer_class<npl_light_fi_stage_cfg_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_light_fi_stage_cfg_t&);

template <class Archive>
void
load(Archive& archive, npl_light_fi_stage_cfg_t& m)
{
    serializer_class<npl_light_fi_stage_cfg_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_light_fi_stage_cfg_t&);



template<>
class serializer_class<npl_link_up_vector_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_link_up_vector_result_t& m) {
            archive(::cereal::make_nvp("link_up", m.link_up));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_link_up_vector_result_t& m) {
            archive(::cereal::make_nvp("link_up", m.link_up));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_link_up_vector_result_t& m)
{
    serializer_class<npl_link_up_vector_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_link_up_vector_result_t&);

template <class Archive>
void
load(Archive& archive, npl_link_up_vector_result_t& m)
{
    serializer_class<npl_link_up_vector_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_link_up_vector_result_t&);



template<>
class serializer_class<npl_lm_command_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lm_command_t& m) {
        uint64_t m_op = m.op;
        uint64_t m_offset = m.offset;
            archive(::cereal::make_nvp("op", m_op));
            archive(::cereal::make_nvp("offset", m_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lm_command_t& m) {
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
save(Archive& archive, const npl_lm_command_t& m)
{
    serializer_class<npl_lm_command_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lm_command_t&);

template <class Archive>
void
load(Archive& archive, npl_lm_command_t& m)
{
    serializer_class<npl_lm_command_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lm_command_t&);



template<>
class serializer_class<npl_local_tx_ip_mapping_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_local_tx_ip_mapping_t& m) {
        uint64_t m_is_mpls_fwd = m.is_mpls_fwd;
        uint64_t m_is_underlying_ip_proto = m.is_underlying_ip_proto;
        uint64_t m_is_mapped_v4 = m.is_mapped_v4;
            archive(::cereal::make_nvp("is_mpls_fwd", m_is_mpls_fwd));
            archive(::cereal::make_nvp("is_underlying_ip_proto", m_is_underlying_ip_proto));
            archive(::cereal::make_nvp("is_mapped_v4", m_is_mapped_v4));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_local_tx_ip_mapping_t& m) {
        uint64_t m_is_mpls_fwd;
        uint64_t m_is_underlying_ip_proto;
        uint64_t m_is_mapped_v4;
            archive(::cereal::make_nvp("is_mpls_fwd", m_is_mpls_fwd));
            archive(::cereal::make_nvp("is_underlying_ip_proto", m_is_underlying_ip_proto));
            archive(::cereal::make_nvp("is_mapped_v4", m_is_mapped_v4));
        m.is_mpls_fwd = m_is_mpls_fwd;
        m.is_underlying_ip_proto = m_is_underlying_ip_proto;
        m.is_mapped_v4 = m_is_mapped_v4;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_local_tx_ip_mapping_t& m)
{
    serializer_class<npl_local_tx_ip_mapping_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_local_tx_ip_mapping_t&);

template <class Archive>
void
load(Archive& archive, npl_local_tx_ip_mapping_t& m)
{
    serializer_class<npl_local_tx_ip_mapping_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_local_tx_ip_mapping_t&);



template<>
class serializer_class<npl_lp_attr_update_raw_bits_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lp_attr_update_raw_bits_t& m) {
        uint64_t m_update_12_bits = m.update_12_bits;
        uint64_t m_update_3_bits = m.update_3_bits;
        uint64_t m_update_q_m_counters = m.update_q_m_counters;
            archive(::cereal::make_nvp("update_12_bits", m_update_12_bits));
            archive(::cereal::make_nvp("update_3_bits", m_update_3_bits));
            archive(::cereal::make_nvp("update_65_bits", m.update_65_bits));
            archive(::cereal::make_nvp("update_q_m_counters", m_update_q_m_counters));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lp_attr_update_raw_bits_t& m) {
        uint64_t m_update_12_bits;
        uint64_t m_update_3_bits;
        uint64_t m_update_q_m_counters;
            archive(::cereal::make_nvp("update_12_bits", m_update_12_bits));
            archive(::cereal::make_nvp("update_3_bits", m_update_3_bits));
            archive(::cereal::make_nvp("update_65_bits", m.update_65_bits));
            archive(::cereal::make_nvp("update_q_m_counters", m_update_q_m_counters));
        m.update_12_bits = m_update_12_bits;
        m.update_3_bits = m_update_3_bits;
        m.update_q_m_counters = m_update_q_m_counters;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lp_attr_update_raw_bits_t& m)
{
    serializer_class<npl_lp_attr_update_raw_bits_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lp_attr_update_raw_bits_t&);

template <class Archive>
void
load(Archive& archive, npl_lp_attr_update_raw_bits_t& m)
{
    serializer_class<npl_lp_attr_update_raw_bits_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lp_attr_update_raw_bits_t&);



template<>
class serializer_class<npl_lp_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lp_id_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lp_id_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lp_id_t& m)
{
    serializer_class<npl_lp_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lp_id_t&);

template <class Archive>
void
load(Archive& archive, npl_lp_id_t& m)
{
    serializer_class<npl_lp_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lp_id_t&);



template<>
class serializer_class<npl_lp_rtf_conf_set_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lp_rtf_conf_set_t& m) {
        uint64_t m_val = m.val;
            archive(::cereal::make_nvp("val", m_val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lp_rtf_conf_set_t& m) {
        uint64_t m_val;
            archive(::cereal::make_nvp("val", m_val));
        m.val = m_val;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lp_rtf_conf_set_t& m)
{
    serializer_class<npl_lp_rtf_conf_set_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lp_rtf_conf_set_t&);

template <class Archive>
void
load(Archive& archive, npl_lp_rtf_conf_set_t& m)
{
    serializer_class<npl_lp_rtf_conf_set_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lp_rtf_conf_set_t&);



template<>
class serializer_class<npl_lpm_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lpm_payload_t& m) {
            archive(::cereal::make_nvp("destination", m.destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lpm_payload_t& m) {
            archive(::cereal::make_nvp("destination", m.destination));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lpm_payload_t& m)
{
    serializer_class<npl_lpm_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lpm_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_lpm_payload_t& m)
{
    serializer_class<npl_lpm_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lpm_payload_t&);



template<>
class serializer_class<npl_lpm_prefix_fec_access_map_output_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lpm_prefix_fec_access_map_output_t& m) {
        uint64_t m_access_fec_table = m.access_fec_table;
            archive(::cereal::make_nvp("access_fec_table", m_access_fec_table));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lpm_prefix_fec_access_map_output_t& m) {
        uint64_t m_access_fec_table;
            archive(::cereal::make_nvp("access_fec_table", m_access_fec_table));
        m.access_fec_table = m_access_fec_table;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lpm_prefix_fec_access_map_output_t& m)
{
    serializer_class<npl_lpm_prefix_fec_access_map_output_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lpm_prefix_fec_access_map_output_t&);

template <class Archive>
void
load(Archive& archive, npl_lpm_prefix_fec_access_map_output_t& m)
{
    serializer_class<npl_lpm_prefix_fec_access_map_output_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lpm_prefix_fec_access_map_output_t&);



template<>
class serializer_class<npl_lpm_prefix_map_output_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lpm_prefix_map_output_t& m) {
        uint64_t m_prefix = m.prefix;
        uint64_t m_is_default = m.is_default;
            archive(::cereal::make_nvp("prefix", m_prefix));
            archive(::cereal::make_nvp("is_default", m_is_default));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lpm_prefix_map_output_t& m) {
        uint64_t m_prefix;
        uint64_t m_is_default;
            archive(::cereal::make_nvp("prefix", m_prefix));
            archive(::cereal::make_nvp("is_default", m_is_default));
        m.prefix = m_prefix;
        m.is_default = m_is_default;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lpm_prefix_map_output_t& m)
{
    serializer_class<npl_lpm_prefix_map_output_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lpm_prefix_map_output_t&);

template <class Archive>
void
load(Archive& archive, npl_lpm_prefix_map_output_t& m)
{
    serializer_class<npl_lpm_prefix_map_output_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lpm_prefix_map_output_t&);



template<>
class serializer_class<npl_lpts_cntr_and_lookup_index_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lpts_cntr_and_lookup_index_t& m) {
        uint64_t m_meter_index_lsb = m.meter_index_lsb;
        uint64_t m_lpts_second_lookup_index = m.lpts_second_lookup_index;
            archive(::cereal::make_nvp("meter_index_lsb", m_meter_index_lsb));
            archive(::cereal::make_nvp("lpts_second_lookup_index", m_lpts_second_lookup_index));
            archive(::cereal::make_nvp("lpts_counter_ptr", m.lpts_counter_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lpts_cntr_and_lookup_index_t& m) {
        uint64_t m_meter_index_lsb;
        uint64_t m_lpts_second_lookup_index;
            archive(::cereal::make_nvp("meter_index_lsb", m_meter_index_lsb));
            archive(::cereal::make_nvp("lpts_second_lookup_index", m_lpts_second_lookup_index));
            archive(::cereal::make_nvp("lpts_counter_ptr", m.lpts_counter_ptr));
        m.meter_index_lsb = m_meter_index_lsb;
        m.lpts_second_lookup_index = m_lpts_second_lookup_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lpts_cntr_and_lookup_index_t& m)
{
    serializer_class<npl_lpts_cntr_and_lookup_index_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lpts_cntr_and_lookup_index_t&);

template <class Archive>
void
load(Archive& archive, npl_lpts_cntr_and_lookup_index_t& m)
{
    serializer_class<npl_lpts_cntr_and_lookup_index_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lpts_cntr_and_lookup_index_t&);



template<>
class serializer_class<npl_lpts_flow_type_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lpts_flow_type_t& m) {
        uint64_t m_lpts_flow = m.lpts_flow;
            archive(::cereal::make_nvp("lpts_flow", m_lpts_flow));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lpts_flow_type_t& m) {
        uint64_t m_lpts_flow;
            archive(::cereal::make_nvp("lpts_flow", m_lpts_flow));
        m.lpts_flow = m_lpts_flow;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lpts_flow_type_t& m)
{
    serializer_class<npl_lpts_flow_type_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lpts_flow_type_t&);

template <class Archive>
void
load(Archive& archive, npl_lpts_flow_type_t& m)
{
    serializer_class<npl_lpts_flow_type_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lpts_flow_type_t&);



template<>
class serializer_class<npl_lpts_packet_flags_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lpts_packet_flags_t& m) {
        uint64_t m_established = m.established;
        uint64_t m_skip_bfd_or_ttl_255 = m.skip_bfd_or_ttl_255;
            archive(::cereal::make_nvp("established", m_established));
            archive(::cereal::make_nvp("skip_bfd_or_ttl_255", m_skip_bfd_or_ttl_255));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lpts_packet_flags_t& m) {
        uint64_t m_established;
        uint64_t m_skip_bfd_or_ttl_255;
            archive(::cereal::make_nvp("established", m_established));
            archive(::cereal::make_nvp("skip_bfd_or_ttl_255", m_skip_bfd_or_ttl_255));
        m.established = m_established;
        m.skip_bfd_or_ttl_255 = m_skip_bfd_or_ttl_255;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lpts_packet_flags_t& m)
{
    serializer_class<npl_lpts_packet_flags_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lpts_packet_flags_t&);

template <class Archive>
void
load(Archive& archive, npl_lpts_packet_flags_t& m)
{
    serializer_class<npl_lpts_packet_flags_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lpts_packet_flags_t&);



template<>
class serializer_class<npl_lpts_tcam_first_result_encap_data_msb_t_anonymous_union_encap_punt_code_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lpts_tcam_first_result_encap_data_msb_t_anonymous_union_encap_punt_code_t& m) {
        uint64_t m_mirror_or_redirect_code = m.mirror_or_redirect_code;
            archive(::cereal::make_nvp("mirror_or_redirect_code", m_mirror_or_redirect_code));
            archive(::cereal::make_nvp("fabric_ibm_cmd", m.fabric_ibm_cmd));
            archive(::cereal::make_nvp("lpts_reason", m.lpts_reason));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lpts_tcam_first_result_encap_data_msb_t_anonymous_union_encap_punt_code_t& m) {
        uint64_t m_mirror_or_redirect_code;
            archive(::cereal::make_nvp("mirror_or_redirect_code", m_mirror_or_redirect_code));
            archive(::cereal::make_nvp("fabric_ibm_cmd", m.fabric_ibm_cmd));
            archive(::cereal::make_nvp("lpts_reason", m.lpts_reason));
        m.mirror_or_redirect_code = m_mirror_or_redirect_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lpts_tcam_first_result_encap_data_msb_t_anonymous_union_encap_punt_code_t& m)
{
    serializer_class<npl_lpts_tcam_first_result_encap_data_msb_t_anonymous_union_encap_punt_code_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lpts_tcam_first_result_encap_data_msb_t_anonymous_union_encap_punt_code_t&);

template <class Archive>
void
load(Archive& archive, npl_lpts_tcam_first_result_encap_data_msb_t_anonymous_union_encap_punt_code_t& m)
{
    serializer_class<npl_lpts_tcam_first_result_encap_data_msb_t_anonymous_union_encap_punt_code_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lpts_tcam_first_result_encap_data_msb_t_anonymous_union_encap_punt_code_t&);



template<>
class serializer_class<npl_lr_fifo_register_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lr_fifo_register_t& m) {
        uint64_t m_address = m.address;
            archive(::cereal::make_nvp("address", m_address));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lr_fifo_register_t& m) {
        uint64_t m_address;
            archive(::cereal::make_nvp("address", m_address));
        m.address = m_address;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lr_fifo_register_t& m)
{
    serializer_class<npl_lr_fifo_register_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lr_fifo_register_t&);

template <class Archive>
void
load(Archive& archive, npl_lr_fifo_register_t& m)
{
    serializer_class<npl_lr_fifo_register_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lr_fifo_register_t&);



template<>
class serializer_class<npl_lr_filter_fifo_register_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lr_filter_fifo_register_t& m) {
        uint64_t m_address = m.address;
            archive(::cereal::make_nvp("address", m_address));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lr_filter_fifo_register_t& m) {
        uint64_t m_address;
            archive(::cereal::make_nvp("address", m_address));
        m.address = m_address;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lr_filter_fifo_register_t& m)
{
    serializer_class<npl_lr_filter_fifo_register_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lr_filter_fifo_register_t&);

template <class Archive>
void
load(Archive& archive, npl_lr_filter_fifo_register_t& m)
{
    serializer_class<npl_lr_filter_fifo_register_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lr_filter_fifo_register_t&);



template<>
class serializer_class<npl_lsp_encap_mapping_data_payload_t_anonymous_union_counter_and_flag_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lsp_encap_mapping_data_payload_t_anonymous_union_counter_and_flag_t& m) {
            archive(::cereal::make_nvp("counter_flag", m.counter_flag));
            archive(::cereal::make_nvp("lsp_counter", m.lsp_counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lsp_encap_mapping_data_payload_t_anonymous_union_counter_and_flag_t& m) {
            archive(::cereal::make_nvp("counter_flag", m.counter_flag));
            archive(::cereal::make_nvp("lsp_counter", m.lsp_counter));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lsp_encap_mapping_data_payload_t_anonymous_union_counter_and_flag_t& m)
{
    serializer_class<npl_lsp_encap_mapping_data_payload_t_anonymous_union_counter_and_flag_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lsp_encap_mapping_data_payload_t_anonymous_union_counter_and_flag_t&);

template <class Archive>
void
load(Archive& archive, npl_lsp_encap_mapping_data_payload_t_anonymous_union_counter_and_flag_t& m)
{
    serializer_class<npl_lsp_encap_mapping_data_payload_t_anonymous_union_counter_and_flag_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lsp_encap_mapping_data_payload_t_anonymous_union_counter_and_flag_t&);



template<>
class serializer_class<npl_lsp_impose_2_mpls_labels_ene_offset_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lsp_impose_2_mpls_labels_ene_offset_t& m) {
            archive(::cereal::make_nvp("lsp_two_labels_ene_jump_offset", m.lsp_two_labels_ene_jump_offset));
            archive(::cereal::make_nvp("lsp_one_label_ene_jump_offset", m.lsp_one_label_ene_jump_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lsp_impose_2_mpls_labels_ene_offset_t& m) {
            archive(::cereal::make_nvp("lsp_two_labels_ene_jump_offset", m.lsp_two_labels_ene_jump_offset));
            archive(::cereal::make_nvp("lsp_one_label_ene_jump_offset", m.lsp_one_label_ene_jump_offset));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lsp_impose_2_mpls_labels_ene_offset_t& m)
{
    serializer_class<npl_lsp_impose_2_mpls_labels_ene_offset_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lsp_impose_2_mpls_labels_ene_offset_t&);

template <class Archive>
void
load(Archive& archive, npl_lsp_impose_2_mpls_labels_ene_offset_t& m)
{
    serializer_class<npl_lsp_impose_2_mpls_labels_ene_offset_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lsp_impose_2_mpls_labels_ene_offset_t&);



template<>
class serializer_class<npl_lsp_impose_mpls_labels_ene_offset_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lsp_impose_mpls_labels_ene_offset_t& m) {
            archive(::cereal::make_nvp("lsp_impose_2_mpls_labels_ene_offset", m.lsp_impose_2_mpls_labels_ene_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lsp_impose_mpls_labels_ene_offset_t& m) {
            archive(::cereal::make_nvp("lsp_impose_2_mpls_labels_ene_offset", m.lsp_impose_2_mpls_labels_ene_offset));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lsp_impose_mpls_labels_ene_offset_t& m)
{
    serializer_class<npl_lsp_impose_mpls_labels_ene_offset_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lsp_impose_mpls_labels_ene_offset_t&);

template <class Archive>
void
load(Archive& archive, npl_lsp_impose_mpls_labels_ene_offset_t& m)
{
    serializer_class<npl_lsp_impose_mpls_labels_ene_offset_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lsp_impose_mpls_labels_ene_offset_t&);



template<>
class serializer_class<npl_lsp_labels_opt3_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lsp_labels_opt3_t& m) {
        uint64_t m_label_0 = m.label_0;
        uint64_t m_label_1 = m.label_1;
        uint64_t m_label_2 = m.label_2;
            archive(::cereal::make_nvp("label_0", m_label_0));
            archive(::cereal::make_nvp("label_1", m_label_1));
            archive(::cereal::make_nvp("label_2", m_label_2));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lsp_labels_opt3_t& m) {
        uint64_t m_label_0;
        uint64_t m_label_1;
        uint64_t m_label_2;
            archive(::cereal::make_nvp("label_0", m_label_0));
            archive(::cereal::make_nvp("label_1", m_label_1));
            archive(::cereal::make_nvp("label_2", m_label_2));
        m.label_0 = m_label_0;
        m.label_1 = m_label_1;
        m.label_2 = m_label_2;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lsp_labels_opt3_t& m)
{
    serializer_class<npl_lsp_labels_opt3_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lsp_labels_opt3_t&);

template <class Archive>
void
load(Archive& archive, npl_lsp_labels_opt3_t& m)
{
    serializer_class<npl_lsp_labels_opt3_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lsp_labels_opt3_t&);



template<>
class serializer_class<npl_lsp_labels_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lsp_labels_t& m) {
        uint64_t m_label_0 = m.label_0;
        uint64_t m_label_1 = m.label_1;
            archive(::cereal::make_nvp("label_0", m_label_0));
            archive(::cereal::make_nvp("label_1", m_label_1));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lsp_labels_t& m) {
        uint64_t m_label_0;
        uint64_t m_label_1;
            archive(::cereal::make_nvp("label_0", m_label_0));
            archive(::cereal::make_nvp("label_1", m_label_1));
        m.label_0 = m_label_0;
        m.label_1 = m_label_1;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lsp_labels_t& m)
{
    serializer_class<npl_lsp_labels_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lsp_labels_t&);

template <class Archive>
void
load(Archive& archive, npl_lsp_labels_t& m)
{
    serializer_class<npl_lsp_labels_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lsp_labels_t&);



template<>
class serializer_class<npl_lsp_type_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lsp_type_t& m) {
        uint64_t m_destination_encoding = m.destination_encoding;
        uint64_t m_vpn = m.vpn;
        uint64_t m_inter_as = m.inter_as;
            archive(::cereal::make_nvp("destination_encoding", m_destination_encoding));
            archive(::cereal::make_nvp("vpn", m_vpn));
            archive(::cereal::make_nvp("inter_as", m_inter_as));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lsp_type_t& m) {
        uint64_t m_destination_encoding;
        uint64_t m_vpn;
        uint64_t m_inter_as;
            archive(::cereal::make_nvp("destination_encoding", m_destination_encoding));
            archive(::cereal::make_nvp("vpn", m_vpn));
            archive(::cereal::make_nvp("inter_as", m_inter_as));
        m.destination_encoding = m_destination_encoding;
        m.vpn = m_vpn;
        m.inter_as = m_inter_as;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lsp_type_t& m)
{
    serializer_class<npl_lsp_type_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lsp_type_t&);

template <class Archive>
void
load(Archive& archive, npl_lsp_type_t& m)
{
    serializer_class<npl_lsp_type_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lsp_type_t&);



template<>
class serializer_class<npl_lsr_encap_t_anonymous_union_lsp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lsr_encap_t_anonymous_union_lsp_t& m) {
        uint64_t m_swap_label = m.swap_label;
        uint64_t m_lsp_id = m.lsp_id;
            archive(::cereal::make_nvp("swap_label", m_swap_label));
            archive(::cereal::make_nvp("lsp_id", m_lsp_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lsr_encap_t_anonymous_union_lsp_t& m) {
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
save(Archive& archive, const npl_lsr_encap_t_anonymous_union_lsp_t& m)
{
    serializer_class<npl_lsr_encap_t_anonymous_union_lsp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lsr_encap_t_anonymous_union_lsp_t&);

template <class Archive>
void
load(Archive& archive, npl_lsr_encap_t_anonymous_union_lsp_t& m)
{
    serializer_class<npl_lsr_encap_t_anonymous_union_lsp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lsr_encap_t_anonymous_union_lsp_t&);



template<>
class serializer_class<npl_mac_addr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_addr_t& m) {
        uint64_t m_mac_address = m.mac_address;
            archive(::cereal::make_nvp("mac_address", m_mac_address));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_addr_t& m) {
        uint64_t m_mac_address;
            archive(::cereal::make_nvp("mac_address", m_mac_address));
        m.mac_address = m_mac_address;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_addr_t& m)
{
    serializer_class<npl_mac_addr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_addr_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_addr_t& m)
{
    serializer_class<npl_mac_addr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_addr_t&);



template<>
class serializer_class<npl_mac_da_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_da_t& m) {
        uint64_t m_is_vrrp = m.is_vrrp;
        uint64_t m_mac_l2_lpts_lkup = m.mac_l2_lpts_lkup;
        uint64_t m_use_l2_lpts = m.use_l2_lpts;
        uint64_t m_prefix = m.prefix;
        uint64_t m_is_ipv4_mc = m.is_ipv4_mc;
        uint64_t m_is_ipv6_mc = m.is_ipv6_mc;
            archive(::cereal::make_nvp("is_vrrp", m_is_vrrp));
            archive(::cereal::make_nvp("mac_l2_lpts_lkup", m_mac_l2_lpts_lkup));
            archive(::cereal::make_nvp("use_l2_lpts", m_use_l2_lpts));
            archive(::cereal::make_nvp("prefix", m_prefix));
            archive(::cereal::make_nvp("compound_termination_control", m.compound_termination_control));
            archive(::cereal::make_nvp("is_ipv4_mc", m_is_ipv4_mc));
            archive(::cereal::make_nvp("is_ipv6_mc", m_is_ipv6_mc));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_da_t& m) {
        uint64_t m_is_vrrp;
        uint64_t m_mac_l2_lpts_lkup;
        uint64_t m_use_l2_lpts;
        uint64_t m_prefix;
        uint64_t m_is_ipv4_mc;
        uint64_t m_is_ipv6_mc;
            archive(::cereal::make_nvp("is_vrrp", m_is_vrrp));
            archive(::cereal::make_nvp("mac_l2_lpts_lkup", m_mac_l2_lpts_lkup));
            archive(::cereal::make_nvp("use_l2_lpts", m_use_l2_lpts));
            archive(::cereal::make_nvp("prefix", m_prefix));
            archive(::cereal::make_nvp("compound_termination_control", m.compound_termination_control));
            archive(::cereal::make_nvp("is_ipv4_mc", m_is_ipv4_mc));
            archive(::cereal::make_nvp("is_ipv6_mc", m_is_ipv6_mc));
            archive(::cereal::make_nvp("type", m.type));
        m.is_vrrp = m_is_vrrp;
        m.mac_l2_lpts_lkup = m_mac_l2_lpts_lkup;
        m.use_l2_lpts = m_use_l2_lpts;
        m.prefix = m_prefix;
        m.is_ipv4_mc = m_is_ipv4_mc;
        m.is_ipv6_mc = m_is_ipv6_mc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_da_t& m)
{
    serializer_class<npl_mac_da_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_da_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_da_t& m)
{
    serializer_class<npl_mac_da_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_da_t&);



template<>
class serializer_class<npl_mac_da_tos_pack_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_da_tos_pack_payload_t& m) {
        uint64_t m_dscp = m.dscp;
        uint64_t m_v4_ttl = m.v4_ttl;
        uint64_t m_v6_ttl = m.v6_ttl;
        uint64_t m_hln = m.hln;
        uint64_t m_tos = m.tos;
            archive(::cereal::make_nvp("dscp", m_dscp));
            archive(::cereal::make_nvp("v4_ttl", m_v4_ttl));
            archive(::cereal::make_nvp("v6_ttl", m_v6_ttl));
            archive(::cereal::make_nvp("hln", m_hln));
            archive(::cereal::make_nvp("tos", m_tos));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_da_tos_pack_payload_t& m) {
        uint64_t m_dscp;
        uint64_t m_v4_ttl;
        uint64_t m_v6_ttl;
        uint64_t m_hln;
        uint64_t m_tos;
            archive(::cereal::make_nvp("dscp", m_dscp));
            archive(::cereal::make_nvp("v4_ttl", m_v4_ttl));
            archive(::cereal::make_nvp("v6_ttl", m_v6_ttl));
            archive(::cereal::make_nvp("hln", m_hln));
            archive(::cereal::make_nvp("tos", m_tos));
        m.dscp = m_dscp;
        m.v4_ttl = m_v4_ttl;
        m.v6_ttl = m_v6_ttl;
        m.hln = m_hln;
        m.tos = m_tos;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_da_tos_pack_payload_t& m)
{
    serializer_class<npl_mac_da_tos_pack_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_da_tos_pack_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_da_tos_pack_payload_t& m)
{
    serializer_class<npl_mac_da_tos_pack_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_da_tos_pack_payload_t&);



template<>
class serializer_class<npl_mac_l2_relay_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_l2_relay_attributes_t& m) {
        uint64_t m_drop_unknown_bc = m.drop_unknown_bc;
        uint64_t m_drop_unknown_mc = m.drop_unknown_mc;
        uint64_t m_drop_unknown_uc = m.drop_unknown_uc;
        uint64_t m_mld_snooping = m.mld_snooping;
        uint64_t m_igmp_snooping = m.igmp_snooping;
        uint64_t m_is_svi = m.is_svi;
            archive(::cereal::make_nvp("bd_attributes", m.bd_attributes));
            archive(::cereal::make_nvp("flood_destination", m.flood_destination));
            archive(::cereal::make_nvp("drop_unknown_bc", m_drop_unknown_bc));
            archive(::cereal::make_nvp("drop_unknown_mc", m_drop_unknown_mc));
            archive(::cereal::make_nvp("drop_unknown_uc", m_drop_unknown_uc));
            archive(::cereal::make_nvp("mld_snooping", m_mld_snooping));
            archive(::cereal::make_nvp("igmp_snooping", m_igmp_snooping));
            archive(::cereal::make_nvp("is_svi", m_is_svi));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_l2_relay_attributes_t& m) {
        uint64_t m_drop_unknown_bc;
        uint64_t m_drop_unknown_mc;
        uint64_t m_drop_unknown_uc;
        uint64_t m_mld_snooping;
        uint64_t m_igmp_snooping;
        uint64_t m_is_svi;
            archive(::cereal::make_nvp("bd_attributes", m.bd_attributes));
            archive(::cereal::make_nvp("flood_destination", m.flood_destination));
            archive(::cereal::make_nvp("drop_unknown_bc", m_drop_unknown_bc));
            archive(::cereal::make_nvp("drop_unknown_mc", m_drop_unknown_mc));
            archive(::cereal::make_nvp("drop_unknown_uc", m_drop_unknown_uc));
            archive(::cereal::make_nvp("mld_snooping", m_mld_snooping));
            archive(::cereal::make_nvp("igmp_snooping", m_igmp_snooping));
            archive(::cereal::make_nvp("is_svi", m_is_svi));
        m.drop_unknown_bc = m_drop_unknown_bc;
        m.drop_unknown_mc = m_drop_unknown_mc;
        m.drop_unknown_uc = m_drop_unknown_uc;
        m.mld_snooping = m_mld_snooping;
        m.igmp_snooping = m_igmp_snooping;
        m.is_svi = m_is_svi;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_l2_relay_attributes_t& m)
{
    serializer_class<npl_mac_l2_relay_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_l2_relay_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_l2_relay_attributes_t& m)
{
    serializer_class<npl_mac_l2_relay_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_l2_relay_attributes_t&);



template<>
class serializer_class<npl_mac_l3_remark_pack_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_l3_remark_pack_payload_t& m) {
        uint64_t m_ipv6_tos = m.ipv6_tos;
        uint64_t m_ipv4_tos = m.ipv4_tos;
        uint64_t m_mpls_exp_bos = m.mpls_exp_bos;
            archive(::cereal::make_nvp("ipv6_tos", m_ipv6_tos));
            archive(::cereal::make_nvp("ipv4_tos", m_ipv4_tos));
            archive(::cereal::make_nvp("mpls_exp_bos", m_mpls_exp_bos));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_l3_remark_pack_payload_t& m) {
        uint64_t m_ipv6_tos;
        uint64_t m_ipv4_tos;
        uint64_t m_mpls_exp_bos;
            archive(::cereal::make_nvp("ipv6_tos", m_ipv6_tos));
            archive(::cereal::make_nvp("ipv4_tos", m_ipv4_tos));
            archive(::cereal::make_nvp("mpls_exp_bos", m_mpls_exp_bos));
        m.ipv6_tos = m_ipv6_tos;
        m.ipv4_tos = m_ipv4_tos;
        m.mpls_exp_bos = m_mpls_exp_bos;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_l3_remark_pack_payload_t& m)
{
    serializer_class<npl_mac_l3_remark_pack_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_l3_remark_pack_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_l3_remark_pack_payload_t& m)
{
    serializer_class<npl_mac_l3_remark_pack_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_l3_remark_pack_payload_t&);



template<>
class serializer_class<npl_mac_relay_g_destination_pad_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_relay_g_destination_pad_t& m) {
            archive(::cereal::make_nvp("dest", m.dest));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_relay_g_destination_pad_t& m) {
            archive(::cereal::make_nvp("dest", m.dest));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_relay_g_destination_pad_t& m)
{
    serializer_class<npl_mac_relay_g_destination_pad_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_relay_g_destination_pad_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_relay_g_destination_pad_t& m)
{
    serializer_class<npl_mac_relay_g_destination_pad_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_relay_g_destination_pad_t&);



template<>
class serializer_class<npl_mac_relay_g_destination_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_relay_g_destination_t& m) {
            archive(::cereal::make_nvp("destination", m.destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_relay_g_destination_t& m) {
            archive(::cereal::make_nvp("destination", m.destination));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_relay_g_destination_t& m)
{
    serializer_class<npl_mac_relay_g_destination_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_relay_g_destination_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_relay_g_destination_t& m)
{
    serializer_class<npl_mac_relay_g_destination_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_relay_g_destination_t&);



}

