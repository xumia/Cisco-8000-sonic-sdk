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

template <class Archive> void save(Archive&, const npl_bfd_mp_table_transmit_b_payload_t&);
template <class Archive> void load(Archive&, npl_bfd_mp_table_transmit_b_payload_t&);

template <class Archive> void save(Archive&, const npl_bool_t&);
template <class Archive> void load(Archive&, npl_bool_t&);

template <class Archive> void save(Archive&, const npl_compound_termination_control_t&);
template <class Archive> void load(Archive&, npl_compound_termination_control_t&);

template <class Archive> void save(Archive&, const npl_counter_flag_t&);
template <class Archive> void load(Archive&, npl_counter_flag_t&);

template <class Archive> void save(Archive&, const npl_counter_ptr_t&);
template <class Archive> void load(Archive&, npl_counter_ptr_t&);

template <class Archive> void save(Archive&, const npl_dest_class_id_t&);
template <class Archive> void load(Archive&, npl_dest_class_id_t&);

template <class Archive> void save(Archive&, const npl_destination_t&);
template <class Archive> void load(Archive&, npl_destination_t&);

template <class Archive> void save(Archive&, const npl_ene_macro_id_t&);
template <class Archive> void load(Archive&, npl_ene_macro_id_t&);

template <class Archive> void save(Archive&, const npl_ene_no_bos_t&);
template <class Archive> void load(Archive&, npl_ene_no_bos_t&);

template <class Archive> void save(Archive&, const npl_eth_mp_table_transmit_b_payload_t&);
template <class Archive> void load(Archive&, npl_eth_mp_table_transmit_b_payload_t&);

template <class Archive> void save(Archive&, const npl_exp_bos_and_label_t&);
template <class Archive> void load(Archive&, npl_exp_bos_and_label_t&);

template <class Archive> void save(Archive&, const npl_fabric_ibm_cmd_t&);
template <class Archive> void load(Archive&, npl_fabric_ibm_cmd_t&);

template <class Archive> void save(Archive&, const npl_hw_mp_table_app_t&);
template <class Archive> void load(Archive&, npl_hw_mp_table_app_t&);

template <class Archive> void save(Archive&, const npl_is_inject_up_and_ip_first_fragment_t&);
template <class Archive> void load(Archive&, npl_is_inject_up_and_ip_first_fragment_t&);

template <class Archive> void save(Archive&, const npl_l2_dlp_t&);
template <class Archive> void load(Archive&, npl_l2_dlp_t&);

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
class serializer_class<npl_l3_dlp_msbs_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_dlp_msbs_t& m) {
        uint64_t m_l3_dlp_msbs = m.l3_dlp_msbs;
            archive(::cereal::make_nvp("l3_dlp_msbs", m_l3_dlp_msbs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_dlp_msbs_t& m) {
        uint64_t m_l3_dlp_msbs;
            archive(::cereal::make_nvp("l3_dlp_msbs", m_l3_dlp_msbs));
        m.l3_dlp_msbs = m_l3_dlp_msbs;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_dlp_msbs_t& m)
{
    serializer_class<npl_l3_dlp_msbs_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_dlp_msbs_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_dlp_msbs_t& m)
{
    serializer_class<npl_l3_dlp_msbs_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_dlp_msbs_t&);



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
class serializer_class<npl_l3_slp_msbs_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_slp_msbs_t& m) {
        uint64_t m_l3_slp_msbs = m.l3_slp_msbs;
            archive(::cereal::make_nvp("l3_slp_msbs", m_l3_slp_msbs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_slp_msbs_t& m) {
        uint64_t m_l3_slp_msbs;
            archive(::cereal::make_nvp("l3_slp_msbs", m_l3_slp_msbs));
        m.l3_slp_msbs = m_l3_slp_msbs;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_slp_msbs_t& m)
{
    serializer_class<npl_l3_slp_msbs_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_slp_msbs_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_slp_msbs_t& m)
{
    serializer_class<npl_l3_slp_msbs_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_slp_msbs_t&);



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
        uint64_t m_update_protocol_is_layer = m.update_protocol_is_layer;
        uint64_t m_update_current_header_info = m.update_current_header_info;
        uint64_t m_size_width = m.size_width;
        uint64_t m_size_offset = m.size_offset;
        uint64_t m_next_protocol_or_type_width = m.next_protocol_or_type_width;
        uint64_t m_next_protocol_or_type_offset = m.next_protocol_or_type_offset;
            archive(::cereal::make_nvp("update_protocol_is_layer", m_update_protocol_is_layer));
            archive(::cereal::make_nvp("update_current_header_info", m_update_current_header_info));
            archive(::cereal::make_nvp("size_width", m_size_width));
            archive(::cereal::make_nvp("size_offset", m_size_offset));
            archive(::cereal::make_nvp("next_protocol_or_type_width", m_next_protocol_or_type_width));
            archive(::cereal::make_nvp("next_protocol_or_type_offset", m_next_protocol_or_type_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_light_fi_stage_cfg_t& m) {
        uint64_t m_update_protocol_is_layer;
        uint64_t m_update_current_header_info;
        uint64_t m_size_width;
        uint64_t m_size_offset;
        uint64_t m_next_protocol_or_type_width;
        uint64_t m_next_protocol_or_type_offset;
            archive(::cereal::make_nvp("update_protocol_is_layer", m_update_protocol_is_layer));
            archive(::cereal::make_nvp("update_current_header_info", m_update_current_header_info));
            archive(::cereal::make_nvp("size_width", m_size_width));
            archive(::cereal::make_nvp("size_offset", m_size_offset));
            archive(::cereal::make_nvp("next_protocol_or_type_width", m_next_protocol_or_type_width));
            archive(::cereal::make_nvp("next_protocol_or_type_offset", m_next_protocol_or_type_offset));
        m.update_protocol_is_layer = m_update_protocol_is_layer;
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
            archive(::cereal::make_nvp("class_id", m.class_id));
            archive(::cereal::make_nvp("destination", m.destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lpm_payload_t& m) {
            archive(::cereal::make_nvp("class_id", m.class_id));
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
class serializer_class<npl_lpm_std_ip_em_lpm_result_destination_t_anonymous_union_union_for_padding_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lpm_std_ip_em_lpm_result_destination_t_anonymous_union_union_for_padding_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lpm_std_ip_em_lpm_result_destination_t_anonymous_union_union_for_padding_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lpm_std_ip_em_lpm_result_destination_t_anonymous_union_union_for_padding_t& m)
{
    serializer_class<npl_lpm_std_ip_em_lpm_result_destination_t_anonymous_union_union_for_padding_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lpm_std_ip_em_lpm_result_destination_t_anonymous_union_union_for_padding_t&);

template <class Archive>
void
load(Archive& archive, npl_lpm_std_ip_em_lpm_result_destination_t_anonymous_union_union_for_padding_t& m)
{
    serializer_class<npl_lpm_std_ip_em_lpm_result_destination_t_anonymous_union_union_for_padding_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lpm_std_ip_em_lpm_result_destination_t_anonymous_union_union_for_padding_t&);



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
        uint64_t m_is_mc = m.is_mc;
        uint64_t m_is_ipv4_mc = m.is_ipv4_mc;
        uint64_t m_is_ipv6_mc = m.is_ipv6_mc;
            archive(::cereal::make_nvp("is_vrrp", m_is_vrrp));
            archive(::cereal::make_nvp("mac_l2_lpts_lkup", m_mac_l2_lpts_lkup));
            archive(::cereal::make_nvp("use_l2_lpts", m_use_l2_lpts));
            archive(::cereal::make_nvp("prefix", m_prefix));
            archive(::cereal::make_nvp("compound_termination_control", m.compound_termination_control));
            archive(::cereal::make_nvp("is_mc", m_is_mc));
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
        uint64_t m_is_mc;
        uint64_t m_is_ipv4_mc;
        uint64_t m_is_ipv6_mc;
            archive(::cereal::make_nvp("is_vrrp", m_is_vrrp));
            archive(::cereal::make_nvp("mac_l2_lpts_lkup", m_mac_l2_lpts_lkup));
            archive(::cereal::make_nvp("use_l2_lpts", m_use_l2_lpts));
            archive(::cereal::make_nvp("prefix", m_prefix));
            archive(::cereal::make_nvp("compound_termination_control", m.compound_termination_control));
            archive(::cereal::make_nvp("is_mc", m_is_mc));
            archive(::cereal::make_nvp("is_ipv4_mc", m_is_ipv4_mc));
            archive(::cereal::make_nvp("is_ipv6_mc", m_is_ipv6_mc));
            archive(::cereal::make_nvp("type", m.type));
        m.is_vrrp = m_is_vrrp;
        m.mac_l2_lpts_lkup = m_mac_l2_lpts_lkup;
        m.use_l2_lpts = m_use_l2_lpts;
        m.prefix = m_prefix;
        m.is_mc = m_is_mc;
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
        uint64_t m_eth_type = m.eth_type;
        uint64_t m_mac_da = m.mac_da;
        uint64_t m_v4_ttl = m.v4_ttl;
        uint64_t m_v6_ttl = m.v6_ttl;
        uint64_t m_hln = m.hln;
        uint64_t m_tos = m.tos;
            archive(::cereal::make_nvp("eth_type", m_eth_type));
            archive(::cereal::make_nvp("mac_da", m_mac_da));
            archive(::cereal::make_nvp("v4_ttl", m_v4_ttl));
            archive(::cereal::make_nvp("v6_ttl", m_v6_ttl));
            archive(::cereal::make_nvp("hln", m_hln));
            archive(::cereal::make_nvp("tos", m_tos));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_da_tos_pack_payload_t& m) {
        uint64_t m_eth_type;
        uint64_t m_mac_da;
        uint64_t m_v4_ttl;
        uint64_t m_v6_ttl;
        uint64_t m_hln;
        uint64_t m_tos;
            archive(::cereal::make_nvp("eth_type", m_eth_type));
            archive(::cereal::make_nvp("mac_da", m_mac_da));
            archive(::cereal::make_nvp("v4_ttl", m_v4_ttl));
            archive(::cereal::make_nvp("v6_ttl", m_v6_ttl));
            archive(::cereal::make_nvp("hln", m_hln));
            archive(::cereal::make_nvp("tos", m_tos));
        m.eth_type = m_eth_type;
        m.mac_da = m_mac_da;
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
class serializer_class<npl_mac_metadata_em_pad_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_metadata_em_pad_t& m) {
        uint64_t m_pad = m.pad;
            archive(::cereal::make_nvp("pad", m_pad));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_metadata_em_pad_t& m) {
        uint64_t m_pad;
            archive(::cereal::make_nvp("pad", m_pad));
        m.pad = m_pad;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_metadata_em_pad_t& m)
{
    serializer_class<npl_mac_metadata_em_pad_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_metadata_em_pad_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_metadata_em_pad_t& m)
{
    serializer_class<npl_mac_metadata_em_pad_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_metadata_em_pad_t&);



template<>
class serializer_class<npl_mac_metadata_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_metadata_t& m) {
            archive(::cereal::make_nvp("class_id", m.class_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_metadata_t& m) {
            archive(::cereal::make_nvp("class_id", m.class_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_metadata_t& m)
{
    serializer_class<npl_mac_metadata_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_metadata_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_metadata_t& m)
{
    serializer_class<npl_mac_metadata_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_metadata_t&);



template<>
class serializer_class<npl_mac_relay_g_destination_pad_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_relay_g_destination_pad_t& m) {
        uint64_t m_pad = m.pad;
            archive(::cereal::make_nvp("dest", m.dest));
            archive(::cereal::make_nvp("pad", m_pad));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_relay_g_destination_pad_t& m) {
        uint64_t m_pad;
            archive(::cereal::make_nvp("dest", m.dest));
            archive(::cereal::make_nvp("pad", m_pad));
        m.pad = m_pad;
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



template<>
class serializer_class<npl_mact_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mact_result_t& m) {
        uint64_t m_application_specific_fields = m.application_specific_fields;
            archive(::cereal::make_nvp("application_specific_fields", m_application_specific_fields));
            archive(::cereal::make_nvp("destination", m.destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mact_result_t& m) {
        uint64_t m_application_specific_fields;
            archive(::cereal::make_nvp("application_specific_fields", m_application_specific_fields));
            archive(::cereal::make_nvp("destination", m.destination));
        m.application_specific_fields = m_application_specific_fields;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mact_result_t& m)
{
    serializer_class<npl_mact_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mact_result_t&);

template <class Archive>
void
load(Archive& archive, npl_mact_result_t& m)
{
    serializer_class<npl_mact_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mact_result_t&);



template<>
class serializer_class<npl_mapping_qos_tag_packed_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mapping_qos_tag_packed_result_t& m) {
        uint64_t m_fwd_hdr_type_v6 = m.fwd_hdr_type_v6;
        uint64_t m_mapping_qos_tag = m.mapping_qos_tag;
        uint64_t m_el_label_exp_bos_inner_label_bos_1 = m.el_label_exp_bos_inner_label_bos_1;
        uint64_t m_el_label_exp_bos_inner_label_bos_0 = m.el_label_exp_bos_inner_label_bos_0;
            archive(::cereal::make_nvp("fwd_hdr_type_v6", m_fwd_hdr_type_v6));
            archive(::cereal::make_nvp("mapping_qos_tag", m_mapping_qos_tag));
            archive(::cereal::make_nvp("eth_ene_macro_id", m.eth_ene_macro_id));
            archive(::cereal::make_nvp("el_label_exp_bos_inner_label_bos_1", m_el_label_exp_bos_inner_label_bos_1));
            archive(::cereal::make_nvp("el_label_exp_bos_inner_label_bos_0", m_el_label_exp_bos_inner_label_bos_0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mapping_qos_tag_packed_result_t& m) {
        uint64_t m_fwd_hdr_type_v6;
        uint64_t m_mapping_qos_tag;
        uint64_t m_el_label_exp_bos_inner_label_bos_1;
        uint64_t m_el_label_exp_bos_inner_label_bos_0;
            archive(::cereal::make_nvp("fwd_hdr_type_v6", m_fwd_hdr_type_v6));
            archive(::cereal::make_nvp("mapping_qos_tag", m_mapping_qos_tag));
            archive(::cereal::make_nvp("eth_ene_macro_id", m.eth_ene_macro_id));
            archive(::cereal::make_nvp("el_label_exp_bos_inner_label_bos_1", m_el_label_exp_bos_inner_label_bos_1));
            archive(::cereal::make_nvp("el_label_exp_bos_inner_label_bos_0", m_el_label_exp_bos_inner_label_bos_0));
        m.fwd_hdr_type_v6 = m_fwd_hdr_type_v6;
        m.mapping_qos_tag = m_mapping_qos_tag;
        m.el_label_exp_bos_inner_label_bos_1 = m_el_label_exp_bos_inner_label_bos_1;
        m.el_label_exp_bos_inner_label_bos_0 = m_el_label_exp_bos_inner_label_bos_0;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mapping_qos_tag_packed_result_t& m)
{
    serializer_class<npl_mapping_qos_tag_packed_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mapping_qos_tag_packed_result_t&);

template <class Archive>
void
load(Archive& archive, npl_mapping_qos_tag_packed_result_t& m)
{
    serializer_class<npl_mapping_qos_tag_packed_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mapping_qos_tag_packed_result_t&);



template<>
class serializer_class<npl_mc_bitmap_base_voq_lookup_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_bitmap_base_voq_lookup_table_result_t& m) {
        uint64_t m_tc_map_profile = m.tc_map_profile;
        uint64_t m_base_voq = m.base_voq;
            archive(::cereal::make_nvp("tc_map_profile", m_tc_map_profile));
            archive(::cereal::make_nvp("base_voq", m_base_voq));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_bitmap_base_voq_lookup_table_result_t& m) {
        uint64_t m_tc_map_profile;
        uint64_t m_base_voq;
            archive(::cereal::make_nvp("tc_map_profile", m_tc_map_profile));
            archive(::cereal::make_nvp("base_voq", m_base_voq));
        m.tc_map_profile = m_tc_map_profile;
        m.base_voq = m_base_voq;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_bitmap_base_voq_lookup_table_result_t& m)
{
    serializer_class<npl_mc_bitmap_base_voq_lookup_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_bitmap_base_voq_lookup_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_bitmap_base_voq_lookup_table_result_t& m)
{
    serializer_class<npl_mc_bitmap_base_voq_lookup_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_bitmap_base_voq_lookup_table_result_t&);



template<>
class serializer_class<npl_mc_bitmap_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_bitmap_t& m) {
        uint64_t m_bitmap_indicator = m.bitmap_indicator;
        uint64_t m_bitmap = m.bitmap;
            archive(::cereal::make_nvp("bitmap_indicator", m_bitmap_indicator));
            archive(::cereal::make_nvp("bitmap", m_bitmap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_bitmap_t& m) {
        uint64_t m_bitmap_indicator;
        uint64_t m_bitmap;
            archive(::cereal::make_nvp("bitmap_indicator", m_bitmap_indicator));
            archive(::cereal::make_nvp("bitmap", m_bitmap));
        m.bitmap_indicator = m_bitmap_indicator;
        m.bitmap = m_bitmap;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_bitmap_t& m)
{
    serializer_class<npl_mc_bitmap_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_bitmap_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_bitmap_t& m)
{
    serializer_class<npl_mc_bitmap_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_bitmap_t&);



template<>
class serializer_class<npl_mc_copy_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_copy_id_t& m) {
        uint64_t m_val = m.val;
            archive(::cereal::make_nvp("val", m_val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_copy_id_t& m) {
        uint64_t m_val;
            archive(::cereal::make_nvp("val", m_val));
        m.val = m_val;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_copy_id_t& m)
{
    serializer_class<npl_mc_copy_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_copy_id_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_copy_id_t& m)
{
    serializer_class<npl_mc_copy_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_copy_id_t&);



template<>
class serializer_class<npl_mc_em_db__key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_em_db__key_t& m) {
        uint64_t m_is_tx = m.is_tx;
        uint64_t m_slice_or_is_fabric = m.slice_or_is_fabric;
        uint64_t m_is_rcy = m.is_rcy;
        uint64_t m_mcid = m.mcid;
        uint64_t m_entry_index = m.entry_index;
            archive(::cereal::make_nvp("is_tx", m_is_tx));
            archive(::cereal::make_nvp("slice_or_is_fabric", m_slice_or_is_fabric));
            archive(::cereal::make_nvp("is_rcy", m_is_rcy));
            archive(::cereal::make_nvp("mcid", m_mcid));
            archive(::cereal::make_nvp("entry_index", m_entry_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_em_db__key_t& m) {
        uint64_t m_is_tx;
        uint64_t m_slice_or_is_fabric;
        uint64_t m_is_rcy;
        uint64_t m_mcid;
        uint64_t m_entry_index;
            archive(::cereal::make_nvp("is_tx", m_is_tx));
            archive(::cereal::make_nvp("slice_or_is_fabric", m_slice_or_is_fabric));
            archive(::cereal::make_nvp("is_rcy", m_is_rcy));
            archive(::cereal::make_nvp("mcid", m_mcid));
            archive(::cereal::make_nvp("entry_index", m_entry_index));
        m.is_tx = m_is_tx;
        m.slice_or_is_fabric = m_slice_or_is_fabric;
        m.is_rcy = m_is_rcy;
        m.mcid = m_mcid;
        m.entry_index = m_entry_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_em_db__key_t& m)
{
    serializer_class<npl_mc_em_db__key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_em_db__key_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_em_db__key_t& m)
{
    serializer_class<npl_mc_em_db__key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_em_db__key_t&);



template<>
class serializer_class<npl_mc_em_db_result_tx_format_1_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_em_db_result_tx_format_1_t& m) {
        uint64_t m_copy_bitmap = m.copy_bitmap;
        uint64_t m_bmp_map_profile = m.bmp_map_profile;
        uint64_t m_tc_map_profile = m.tc_map_profile;
        uint64_t m_mc_copy_id = m.mc_copy_id;
            archive(::cereal::make_nvp("copy_bitmap", m_copy_bitmap));
            archive(::cereal::make_nvp("bmp_map_profile", m_bmp_map_profile));
            archive(::cereal::make_nvp("tc_map_profile", m_tc_map_profile));
            archive(::cereal::make_nvp("mc_copy_id", m_mc_copy_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_em_db_result_tx_format_1_t& m) {
        uint64_t m_copy_bitmap;
        uint64_t m_bmp_map_profile;
        uint64_t m_tc_map_profile;
        uint64_t m_mc_copy_id;
            archive(::cereal::make_nvp("copy_bitmap", m_copy_bitmap));
            archive(::cereal::make_nvp("bmp_map_profile", m_bmp_map_profile));
            archive(::cereal::make_nvp("tc_map_profile", m_tc_map_profile));
            archive(::cereal::make_nvp("mc_copy_id", m_mc_copy_id));
        m.copy_bitmap = m_copy_bitmap;
        m.bmp_map_profile = m_bmp_map_profile;
        m.tc_map_profile = m_tc_map_profile;
        m.mc_copy_id = m_mc_copy_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_em_db_result_tx_format_1_t& m)
{
    serializer_class<npl_mc_em_db_result_tx_format_1_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_em_db_result_tx_format_1_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_em_db_result_tx_format_1_t& m)
{
    serializer_class<npl_mc_em_db_result_tx_format_1_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_em_db_result_tx_format_1_t&);



template<>
class serializer_class<npl_mc_fe_links_bmp_db_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_fe_links_bmp_db_result_t& m) {
        uint64_t m_use_bitmap_directly = m.use_bitmap_directly;
            archive(::cereal::make_nvp("use_bitmap_directly", m_use_bitmap_directly));
            archive(::cereal::make_nvp("fe_links_bmp", m.fe_links_bmp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_fe_links_bmp_db_result_t& m) {
        uint64_t m_use_bitmap_directly;
            archive(::cereal::make_nvp("use_bitmap_directly", m_use_bitmap_directly));
            archive(::cereal::make_nvp("fe_links_bmp", m.fe_links_bmp));
        m.use_bitmap_directly = m_use_bitmap_directly;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_fe_links_bmp_db_result_t& m)
{
    serializer_class<npl_mc_fe_links_bmp_db_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_fe_links_bmp_db_result_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_fe_links_bmp_db_result_t& m)
{
    serializer_class<npl_mc_fe_links_bmp_db_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_fe_links_bmp_db_result_t&);



template<>
class serializer_class<npl_mc_macro_compressed_fields_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_macro_compressed_fields_t& m) {
        uint64_t m_is_inject_up = m.is_inject_up;
        uint64_t m_not_comp_single_src = m.not_comp_single_src;
            archive(::cereal::make_nvp("is_inject_up", m_is_inject_up));
            archive(::cereal::make_nvp("not_comp_single_src", m_not_comp_single_src));
            archive(::cereal::make_nvp("curr_proto_type", m.curr_proto_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_macro_compressed_fields_t& m) {
        uint64_t m_is_inject_up;
        uint64_t m_not_comp_single_src;
            archive(::cereal::make_nvp("is_inject_up", m_is_inject_up));
            archive(::cereal::make_nvp("not_comp_single_src", m_not_comp_single_src));
            archive(::cereal::make_nvp("curr_proto_type", m.curr_proto_type));
        m.is_inject_up = m_is_inject_up;
        m.not_comp_single_src = m_not_comp_single_src;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_macro_compressed_fields_t& m)
{
    serializer_class<npl_mc_macro_compressed_fields_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_macro_compressed_fields_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_macro_compressed_fields_t& m)
{
    serializer_class<npl_mc_macro_compressed_fields_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_macro_compressed_fields_t&);



template<>
class serializer_class<npl_mc_rx_tc_map_profile_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_rx_tc_map_profile_t& m) {
        uint64_t m_val = m.val;
            archive(::cereal::make_nvp("val", m_val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_rx_tc_map_profile_t& m) {
        uint64_t m_val;
            archive(::cereal::make_nvp("val", m_val));
        m.val = m_val;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_rx_tc_map_profile_t& m)
{
    serializer_class<npl_mc_rx_tc_map_profile_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_rx_tc_map_profile_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_rx_tc_map_profile_t& m)
{
    serializer_class<npl_mc_rx_tc_map_profile_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_rx_tc_map_profile_t&);



template<>
class serializer_class<npl_mc_slice_bitmap_table_entry_t_anonymous_union_group_size_or_bitmap_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_slice_bitmap_table_entry_t_anonymous_union_group_size_or_bitmap_t& m) {
        uint64_t m_group_size = m.group_size;
            archive(::cereal::make_nvp("group_size", m_group_size));
            archive(::cereal::make_nvp("mc_bitmap", m.mc_bitmap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_slice_bitmap_table_entry_t_anonymous_union_group_size_or_bitmap_t& m) {
        uint64_t m_group_size;
            archive(::cereal::make_nvp("group_size", m_group_size));
            archive(::cereal::make_nvp("mc_bitmap", m.mc_bitmap));
        m.group_size = m_group_size;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_slice_bitmap_table_entry_t_anonymous_union_group_size_or_bitmap_t& m)
{
    serializer_class<npl_mc_slice_bitmap_table_entry_t_anonymous_union_group_size_or_bitmap_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_slice_bitmap_table_entry_t_anonymous_union_group_size_or_bitmap_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_slice_bitmap_table_entry_t_anonymous_union_group_size_or_bitmap_t& m)
{
    serializer_class<npl_mc_slice_bitmap_table_entry_t_anonymous_union_group_size_or_bitmap_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_slice_bitmap_table_entry_t_anonymous_union_group_size_or_bitmap_t&);



template<>
class serializer_class<npl_mc_tx_tc_map_profile_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_tx_tc_map_profile_t& m) {
        uint64_t m_val = m.val;
            archive(::cereal::make_nvp("val", m_val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_tx_tc_map_profile_t& m) {
        uint64_t m_val;
            archive(::cereal::make_nvp("val", m_val));
        m.val = m_val;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_tx_tc_map_profile_t& m)
{
    serializer_class<npl_mc_tx_tc_map_profile_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_tx_tc_map_profile_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_tx_tc_map_profile_t& m)
{
    serializer_class<npl_mc_tx_tc_map_profile_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_tx_tc_map_profile_t&);



template<>
class serializer_class<npl_mcid_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mcid_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mcid_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mcid_t& m)
{
    serializer_class<npl_mcid_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mcid_t&);

template <class Archive>
void
load(Archive& archive, npl_mcid_t& m)
{
    serializer_class<npl_mcid_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mcid_t&);



template<>
class serializer_class<npl_meg_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_meg_id_t& m) {
            archive(::cereal::make_nvp("id", m.id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_meg_id_t& m) {
            archive(::cereal::make_nvp("id", m.id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_meg_id_t& m)
{
    serializer_class<npl_meg_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_meg_id_t&);

template <class Archive>
void
load(Archive& archive, npl_meg_id_t& m)
{
    serializer_class<npl_meg_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_meg_id_t&);



template<>
class serializer_class<npl_meter_action_profile_len_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_meter_action_profile_len_t& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_meter_action_profile_len_t& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_meter_action_profile_len_t& m)
{
    serializer_class<npl_meter_action_profile_len_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_meter_action_profile_len_t&);

template <class Archive>
void
load(Archive& archive, npl_meter_action_profile_len_t& m)
{
    serializer_class<npl_meter_action_profile_len_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_meter_action_profile_len_t&);



template<>
class serializer_class<npl_meter_count_mode_len_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_meter_count_mode_len_t& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_meter_count_mode_len_t& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_meter_count_mode_len_t& m)
{
    serializer_class<npl_meter_count_mode_len_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_meter_count_mode_len_t&);

template <class Archive>
void
load(Archive& archive, npl_meter_count_mode_len_t& m)
{
    serializer_class<npl_meter_count_mode_len_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_meter_count_mode_len_t&);



template<>
class serializer_class<npl_meter_mode_len_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_meter_mode_len_t& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_meter_mode_len_t& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_meter_mode_len_t& m)
{
    serializer_class<npl_meter_mode_len_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_meter_mode_len_t&);

template <class Archive>
void
load(Archive& archive, npl_meter_mode_len_t& m)
{
    serializer_class<npl_meter_mode_len_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_meter_mode_len_t&);



template<>
class serializer_class<npl_meter_profile_len_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_meter_profile_len_t& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_meter_profile_len_t& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_meter_profile_len_t& m)
{
    serializer_class<npl_meter_profile_len_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_meter_profile_len_t&);

template <class Archive>
void
load(Archive& archive, npl_meter_profile_len_t& m)
{
    serializer_class<npl_meter_profile_len_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_meter_profile_len_t&);



template<>
class serializer_class<npl_meter_weight_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_meter_weight_t& m) {
        uint64_t m_weight_factor = m.weight_factor;
        uint64_t m_weight = m.weight;
            archive(::cereal::make_nvp("weight_factor", m_weight_factor));
            archive(::cereal::make_nvp("weight", m_weight));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_meter_weight_t& m) {
        uint64_t m_weight_factor;
        uint64_t m_weight;
            archive(::cereal::make_nvp("weight_factor", m_weight_factor));
            archive(::cereal::make_nvp("weight", m_weight));
        m.weight_factor = m_weight_factor;
        m.weight = m_weight;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_meter_weight_t& m)
{
    serializer_class<npl_meter_weight_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_meter_weight_t&);

template <class Archive>
void
load(Archive& archive, npl_meter_weight_t& m)
{
    serializer_class<npl_meter_weight_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_meter_weight_t&);



template<>
class serializer_class<npl_mii_loopback_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mii_loopback_data_t& m) {
            archive(::cereal::make_nvp("mode", m.mode));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mii_loopback_data_t& m) {
            archive(::cereal::make_nvp("mode", m.mode));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mii_loopback_data_t& m)
{
    serializer_class<npl_mii_loopback_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mii_loopback_data_t&);

template <class Archive>
void
load(Archive& archive, npl_mii_loopback_data_t& m)
{
    serializer_class<npl_mii_loopback_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mii_loopback_data_t&);



template<>
class serializer_class<npl_minimal_l3_lp_attributes_t_anonymous_union_disable_mpls_or_mc_tunnel_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_minimal_l3_lp_attributes_t_anonymous_union_disable_mpls_or_mc_tunnel_t& m) {
        uint64_t m_disable_mpls = m.disable_mpls;
        uint64_t m_disable_mc_tunnel_decap = m.disable_mc_tunnel_decap;
            archive(::cereal::make_nvp("disable_mpls", m_disable_mpls));
            archive(::cereal::make_nvp("disable_mc_tunnel_decap", m_disable_mc_tunnel_decap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_minimal_l3_lp_attributes_t_anonymous_union_disable_mpls_or_mc_tunnel_t& m) {
        uint64_t m_disable_mpls;
        uint64_t m_disable_mc_tunnel_decap;
            archive(::cereal::make_nvp("disable_mpls", m_disable_mpls));
            archive(::cereal::make_nvp("disable_mc_tunnel_decap", m_disable_mc_tunnel_decap));
        m.disable_mpls = m_disable_mpls;
        m.disable_mc_tunnel_decap = m_disable_mc_tunnel_decap;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_minimal_l3_lp_attributes_t_anonymous_union_disable_mpls_or_mc_tunnel_t& m)
{
    serializer_class<npl_minimal_l3_lp_attributes_t_anonymous_union_disable_mpls_or_mc_tunnel_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_minimal_l3_lp_attributes_t_anonymous_union_disable_mpls_or_mc_tunnel_t&);

template <class Archive>
void
load(Archive& archive, npl_minimal_l3_lp_attributes_t_anonymous_union_disable_mpls_or_mc_tunnel_t& m)
{
    serializer_class<npl_minimal_l3_lp_attributes_t_anonymous_union_disable_mpls_or_mc_tunnel_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_minimal_l3_lp_attributes_t_anonymous_union_disable_mpls_or_mc_tunnel_t&);



template<>
class serializer_class<npl_mismatch_indications_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mismatch_indications_t& m) {
        uint64_t m_issu_codespace = m.issu_codespace;
        uint64_t m_first_packet_size = m.first_packet_size;
        uint64_t m_is_single_fragment = m.is_single_fragment;
            archive(::cereal::make_nvp("issu_codespace", m_issu_codespace));
            archive(::cereal::make_nvp("first_packet_size", m_first_packet_size));
            archive(::cereal::make_nvp("is_single_fragment", m_is_single_fragment));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mismatch_indications_t& m) {
        uint64_t m_issu_codespace;
        uint64_t m_first_packet_size;
        uint64_t m_is_single_fragment;
            archive(::cereal::make_nvp("issu_codespace", m_issu_codespace));
            archive(::cereal::make_nvp("first_packet_size", m_first_packet_size));
            archive(::cereal::make_nvp("is_single_fragment", m_is_single_fragment));
        m.issu_codespace = m_issu_codespace;
        m.first_packet_size = m_first_packet_size;
        m.is_single_fragment = m_is_single_fragment;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mismatch_indications_t& m)
{
    serializer_class<npl_mismatch_indications_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mismatch_indications_t&);

template <class Archive>
void
load(Archive& archive, npl_mismatch_indications_t& m)
{
    serializer_class<npl_mismatch_indications_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mismatch_indications_t&);



template<>
class serializer_class<npl_mldp_protection_entry_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mldp_protection_entry_t& m) {
            archive(::cereal::make_nvp("drop_protect", m.drop_protect));
            archive(::cereal::make_nvp("drop_primary", m.drop_primary));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mldp_protection_entry_t& m) {
            archive(::cereal::make_nvp("drop_protect", m.drop_protect));
            archive(::cereal::make_nvp("drop_primary", m.drop_primary));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mldp_protection_entry_t& m)
{
    serializer_class<npl_mldp_protection_entry_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mldp_protection_entry_t&);

template <class Archive>
void
load(Archive& archive, npl_mldp_protection_entry_t& m)
{
    serializer_class<npl_mldp_protection_entry_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mldp_protection_entry_t&);



template<>
class serializer_class<npl_mldp_protection_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mldp_protection_id_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mldp_protection_id_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mldp_protection_id_t& m)
{
    serializer_class<npl_mldp_protection_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mldp_protection_id_t&);

template <class Archive>
void
load(Archive& archive, npl_mldp_protection_id_t& m)
{
    serializer_class<npl_mldp_protection_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mldp_protection_id_t&);



template<>
class serializer_class<npl_mldp_protection_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mldp_protection_t& m) {
            archive(::cereal::make_nvp("id", m.id));
            archive(::cereal::make_nvp("sel", m.sel));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mldp_protection_t& m) {
            archive(::cereal::make_nvp("id", m.id));
            archive(::cereal::make_nvp("sel", m.sel));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mldp_protection_t& m)
{
    serializer_class<npl_mldp_protection_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mldp_protection_t&);

template <class Archive>
void
load(Archive& archive, npl_mldp_protection_t& m)
{
    serializer_class<npl_mldp_protection_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mldp_protection_t&);



template<>
class serializer_class<npl_more_labels_index_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_more_labels_index_t& m) {
        uint64_t m_more_labels_index = m.more_labels_index;
            archive(::cereal::make_nvp("more_labels_index", m_more_labels_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_more_labels_index_t& m) {
        uint64_t m_more_labels_index;
            archive(::cereal::make_nvp("more_labels_index", m_more_labels_index));
        m.more_labels_index = m_more_labels_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_more_labels_index_t& m)
{
    serializer_class<npl_more_labels_index_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_more_labels_index_t&);

template <class Archive>
void
load(Archive& archive, npl_more_labels_index_t& m)
{
    serializer_class<npl_more_labels_index_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_more_labels_index_t&);



template<>
class serializer_class<npl_mp_table_app_t_anonymous_union_mp2_data_union_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mp_table_app_t_anonymous_union_mp2_data_union_t& m) {
            archive(::cereal::make_nvp("transmit_b", m.transmit_b));
            archive(::cereal::make_nvp("bfd2", m.bfd2));
            archive(::cereal::make_nvp("hw", m.hw));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mp_table_app_t_anonymous_union_mp2_data_union_t& m) {
            archive(::cereal::make_nvp("transmit_b", m.transmit_b));
            archive(::cereal::make_nvp("bfd2", m.bfd2));
            archive(::cereal::make_nvp("hw", m.hw));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mp_table_app_t_anonymous_union_mp2_data_union_t& m)
{
    serializer_class<npl_mp_table_app_t_anonymous_union_mp2_data_union_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mp_table_app_t_anonymous_union_mp2_data_union_t&);

template <class Archive>
void
load(Archive& archive, npl_mp_table_app_t_anonymous_union_mp2_data_union_t& m)
{
    serializer_class<npl_mp_table_app_t_anonymous_union_mp2_data_union_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mp_table_app_t_anonymous_union_mp2_data_union_t&);



template<>
class serializer_class<npl_mpls_encap_control_bits_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_encap_control_bits_t& m) {
        uint64_t m_is_midpoint = m.is_midpoint;
        uint64_t m_mpls_labels_lookup = m.mpls_labels_lookup;
        uint64_t m_is_asbr_or_ldpote = m.is_asbr_or_ldpote;
            archive(::cereal::make_nvp("is_midpoint", m_is_midpoint));
            archive(::cereal::make_nvp("mpls_labels_lookup", m_mpls_labels_lookup));
            archive(::cereal::make_nvp("is_asbr_or_ldpote", m_is_asbr_or_ldpote));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_encap_control_bits_t& m) {
        uint64_t m_is_midpoint;
        uint64_t m_mpls_labels_lookup;
        uint64_t m_is_asbr_or_ldpote;
            archive(::cereal::make_nvp("is_midpoint", m_is_midpoint));
            archive(::cereal::make_nvp("mpls_labels_lookup", m_mpls_labels_lookup));
            archive(::cereal::make_nvp("is_asbr_or_ldpote", m_is_asbr_or_ldpote));
        m.is_midpoint = m_is_midpoint;
        m.mpls_labels_lookup = m_mpls_labels_lookup;
        m.is_asbr_or_ldpote = m_is_asbr_or_ldpote;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_encap_control_bits_t& m)
{
    serializer_class<npl_mpls_encap_control_bits_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_encap_control_bits_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_encap_control_bits_t& m)
{
    serializer_class<npl_mpls_encap_control_bits_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_encap_control_bits_t&);



template<>
class serializer_class<npl_mpls_first_ene_macro_control_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_first_ene_macro_control_t& m) {
        uint64_t m_no_first_ene_macro = m.no_first_ene_macro;
        uint64_t m_vpn_label_lookup = m.vpn_label_lookup;
            archive(::cereal::make_nvp("no_first_ene_macro", m_no_first_ene_macro));
            archive(::cereal::make_nvp("vpn_label_lookup", m_vpn_label_lookup));
            archive(::cereal::make_nvp("qos_first_macro_code", m.qos_first_macro_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_first_ene_macro_control_t& m) {
        uint64_t m_no_first_ene_macro;
        uint64_t m_vpn_label_lookup;
            archive(::cereal::make_nvp("no_first_ene_macro", m_no_first_ene_macro));
            archive(::cereal::make_nvp("vpn_label_lookup", m_vpn_label_lookup));
            archive(::cereal::make_nvp("qos_first_macro_code", m.qos_first_macro_code));
        m.no_first_ene_macro = m_no_first_ene_macro;
        m.vpn_label_lookup = m_vpn_label_lookup;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_first_ene_macro_control_t& m)
{
    serializer_class<npl_mpls_first_ene_macro_control_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_first_ene_macro_control_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_first_ene_macro_control_t& m)
{
    serializer_class<npl_mpls_first_ene_macro_control_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_first_ene_macro_control_t&);



template<>
class serializer_class<npl_mpls_header_flags_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_header_flags_t& m) {
        uint64_t m_illegal_ipv4 = m.illegal_ipv4;
        uint64_t m_is_null_labels = m.is_null_labels;
        uint64_t m_is_bos = m.is_bos;
            archive(::cereal::make_nvp("illegal_ipv4", m_illegal_ipv4));
            archive(::cereal::make_nvp("is_null_labels", m_is_null_labels));
            archive(::cereal::make_nvp("is_bos", m_is_bos));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_header_flags_t& m) {
        uint64_t m_illegal_ipv4;
        uint64_t m_is_null_labels;
        uint64_t m_is_bos;
            archive(::cereal::make_nvp("illegal_ipv4", m_illegal_ipv4));
            archive(::cereal::make_nvp("is_null_labels", m_is_null_labels));
            archive(::cereal::make_nvp("is_bos", m_is_bos));
        m.illegal_ipv4 = m_illegal_ipv4;
        m.is_null_labels = m_is_null_labels;
        m.is_bos = m_is_bos;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_header_flags_t& m)
{
    serializer_class<npl_mpls_header_flags_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_header_flags_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_header_flags_t& m)
{
    serializer_class<npl_mpls_header_flags_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_header_flags_t&);



template<>
class serializer_class<npl_mpls_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_header_t& m) {
        uint64_t m_label = m.label;
        uint64_t m_exp = m.exp;
        uint64_t m_bos = m.bos;
        uint64_t m_ttl = m.ttl;
            archive(::cereal::make_nvp("label", m_label));
            archive(::cereal::make_nvp("exp", m_exp));
            archive(::cereal::make_nvp("bos", m_bos));
            archive(::cereal::make_nvp("ttl", m_ttl));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_header_t& m) {
        uint64_t m_label;
        uint64_t m_exp;
        uint64_t m_bos;
        uint64_t m_ttl;
            archive(::cereal::make_nvp("label", m_label));
            archive(::cereal::make_nvp("exp", m_exp));
            archive(::cereal::make_nvp("bos", m_bos));
            archive(::cereal::make_nvp("ttl", m_ttl));
        m.label = m_label;
        m.exp = m_exp;
        m.bos = m_bos;
        m.ttl = m_ttl;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_header_t& m)
{
    serializer_class<npl_mpls_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_header_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_header_t& m)
{
    serializer_class<npl_mpls_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_header_t&);



template<>
class serializer_class<npl_mpls_relay_packed_labels_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_relay_packed_labels_t& m) {
        uint64_t m_adjust_next_hdr_offset = m.adjust_next_hdr_offset;
        uint64_t m_next_label_above_null = m.next_label_above_null;
            archive(::cereal::make_nvp("adjust_next_hdr_offset", m_adjust_next_hdr_offset));
            archive(::cereal::make_nvp("label_above_null", m.label_above_null));
            archive(::cereal::make_nvp("next_label_above_null", m_next_label_above_null));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_relay_packed_labels_t& m) {
        uint64_t m_adjust_next_hdr_offset;
        uint64_t m_next_label_above_null;
            archive(::cereal::make_nvp("adjust_next_hdr_offset", m_adjust_next_hdr_offset));
            archive(::cereal::make_nvp("label_above_null", m.label_above_null));
            archive(::cereal::make_nvp("next_label_above_null", m_next_label_above_null));
        m.adjust_next_hdr_offset = m_adjust_next_hdr_offset;
        m.next_label_above_null = m_next_label_above_null;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_relay_packed_labels_t& m)
{
    serializer_class<npl_mpls_relay_packed_labels_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_relay_packed_labels_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_relay_packed_labels_t& m)
{
    serializer_class<npl_mpls_relay_packed_labels_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_relay_packed_labels_t&);



template<>
class serializer_class<npl_mpls_termination_mldp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_termination_mldp_t& m) {
        uint64_t m_rpf_id = m.rpf_id;
            archive(::cereal::make_nvp("rpf_id", m_rpf_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_termination_mldp_t& m) {
        uint64_t m_rpf_id;
            archive(::cereal::make_nvp("rpf_id", m_rpf_id));
        m.rpf_id = m_rpf_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_termination_mldp_t& m)
{
    serializer_class<npl_mpls_termination_mldp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_termination_mldp_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_termination_mldp_t& m)
{
    serializer_class<npl_mpls_termination_mldp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_termination_mldp_t&);



template<>
class serializer_class<npl_mpls_tp_em_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_tp_em_t& m) {
        uint64_t m_dummy = m.dummy;
            archive(::cereal::make_nvp("dummy", m_dummy));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_tp_em_t& m) {
        uint64_t m_dummy;
            archive(::cereal::make_nvp("dummy", m_dummy));
        m.dummy = m_dummy;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_tp_em_t& m)
{
    serializer_class<npl_mpls_tp_em_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_tp_em_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_tp_em_t& m)
{
    serializer_class<npl_mpls_tp_em_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_tp_em_t&);



template<>
class serializer_class<npl_mpls_traps_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_traps_t& m) {
        uint64_t m_unknown_protocol_after_bos = m.unknown_protocol_after_bos;
        uint64_t m_ttl_is_zero = m.ttl_is_zero;
        uint64_t m_bfd_over_pwe_ttl = m.bfd_over_pwe_ttl;
        uint64_t m_bfd_over_pwe_raw = m.bfd_over_pwe_raw;
        uint64_t m_bfd_over_pwe_ipv4 = m.bfd_over_pwe_ipv4;
        uint64_t m_bfd_over_pwe_ipv6 = m.bfd_over_pwe_ipv6;
        uint64_t m_unknown_bfd_g_ach_channel_type = m.unknown_bfd_g_ach_channel_type;
        uint64_t m_bfd_over_pwe_ra = m.bfd_over_pwe_ra;
        uint64_t m_mpls_tp_over_pwe = m.mpls_tp_over_pwe;
        uint64_t m_unknown_g_ach = m.unknown_g_ach;
        uint64_t m_mpls_tp_over_lsp = m.mpls_tp_over_lsp;
        uint64_t m_oam_alert_label = m.oam_alert_label;
        uint64_t m_extension_label = m.extension_label;
        uint64_t m_router_alert_label = m.router_alert_label;
        uint64_t m_unexpected_reserved_label = m.unexpected_reserved_label;
        uint64_t m_forwarding_disabled = m.forwarding_disabled;
        uint64_t m_ilm_miss = m.ilm_miss;
        uint64_t m_ipv4_over_ipv6_explicit_null = m.ipv4_over_ipv6_explicit_null;
        uint64_t m_invalid_ttl = m.invalid_ttl;
        uint64_t m_te_midpopint_ldp_labels_miss = m.te_midpopint_ldp_labels_miss;
        uint64_t m_asbr_label_miss = m.asbr_label_miss;
        uint64_t m_ilm_vrf_label_miss = m.ilm_vrf_label_miss;
        uint64_t m_pwe_pwach = m.pwe_pwach;
        uint64_t m_vpn_ttl_one = m.vpn_ttl_one;
        uint64_t m_missing_fwd_label_after_pop = m.missing_fwd_label_after_pop;
            archive(::cereal::make_nvp("unknown_protocol_after_bos", m_unknown_protocol_after_bos));
            archive(::cereal::make_nvp("ttl_is_zero", m_ttl_is_zero));
            archive(::cereal::make_nvp("bfd_over_pwe_ttl", m_bfd_over_pwe_ttl));
            archive(::cereal::make_nvp("bfd_over_pwe_raw", m_bfd_over_pwe_raw));
            archive(::cereal::make_nvp("bfd_over_pwe_ipv4", m_bfd_over_pwe_ipv4));
            archive(::cereal::make_nvp("bfd_over_pwe_ipv6", m_bfd_over_pwe_ipv6));
            archive(::cereal::make_nvp("unknown_bfd_g_ach_channel_type", m_unknown_bfd_g_ach_channel_type));
            archive(::cereal::make_nvp("bfd_over_pwe_ra", m_bfd_over_pwe_ra));
            archive(::cereal::make_nvp("mpls_tp_over_pwe", m_mpls_tp_over_pwe));
            archive(::cereal::make_nvp("unknown_g_ach", m_unknown_g_ach));
            archive(::cereal::make_nvp("mpls_tp_over_lsp", m_mpls_tp_over_lsp));
            archive(::cereal::make_nvp("oam_alert_label", m_oam_alert_label));
            archive(::cereal::make_nvp("extension_label", m_extension_label));
            archive(::cereal::make_nvp("router_alert_label", m_router_alert_label));
            archive(::cereal::make_nvp("unexpected_reserved_label", m_unexpected_reserved_label));
            archive(::cereal::make_nvp("forwarding_disabled", m_forwarding_disabled));
            archive(::cereal::make_nvp("ilm_miss", m_ilm_miss));
            archive(::cereal::make_nvp("ipv4_over_ipv6_explicit_null", m_ipv4_over_ipv6_explicit_null));
            archive(::cereal::make_nvp("invalid_ttl", m_invalid_ttl));
            archive(::cereal::make_nvp("te_midpopint_ldp_labels_miss", m_te_midpopint_ldp_labels_miss));
            archive(::cereal::make_nvp("asbr_label_miss", m_asbr_label_miss));
            archive(::cereal::make_nvp("ilm_vrf_label_miss", m_ilm_vrf_label_miss));
            archive(::cereal::make_nvp("pwe_pwach", m_pwe_pwach));
            archive(::cereal::make_nvp("vpn_ttl_one", m_vpn_ttl_one));
            archive(::cereal::make_nvp("missing_fwd_label_after_pop", m_missing_fwd_label_after_pop));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_traps_t& m) {
        uint64_t m_unknown_protocol_after_bos;
        uint64_t m_ttl_is_zero;
        uint64_t m_bfd_over_pwe_ttl;
        uint64_t m_bfd_over_pwe_raw;
        uint64_t m_bfd_over_pwe_ipv4;
        uint64_t m_bfd_over_pwe_ipv6;
        uint64_t m_unknown_bfd_g_ach_channel_type;
        uint64_t m_bfd_over_pwe_ra;
        uint64_t m_mpls_tp_over_pwe;
        uint64_t m_unknown_g_ach;
        uint64_t m_mpls_tp_over_lsp;
        uint64_t m_oam_alert_label;
        uint64_t m_extension_label;
        uint64_t m_router_alert_label;
        uint64_t m_unexpected_reserved_label;
        uint64_t m_forwarding_disabled;
        uint64_t m_ilm_miss;
        uint64_t m_ipv4_over_ipv6_explicit_null;
        uint64_t m_invalid_ttl;
        uint64_t m_te_midpopint_ldp_labels_miss;
        uint64_t m_asbr_label_miss;
        uint64_t m_ilm_vrf_label_miss;
        uint64_t m_pwe_pwach;
        uint64_t m_vpn_ttl_one;
        uint64_t m_missing_fwd_label_after_pop;
            archive(::cereal::make_nvp("unknown_protocol_after_bos", m_unknown_protocol_after_bos));
            archive(::cereal::make_nvp("ttl_is_zero", m_ttl_is_zero));
            archive(::cereal::make_nvp("bfd_over_pwe_ttl", m_bfd_over_pwe_ttl));
            archive(::cereal::make_nvp("bfd_over_pwe_raw", m_bfd_over_pwe_raw));
            archive(::cereal::make_nvp("bfd_over_pwe_ipv4", m_bfd_over_pwe_ipv4));
            archive(::cereal::make_nvp("bfd_over_pwe_ipv6", m_bfd_over_pwe_ipv6));
            archive(::cereal::make_nvp("unknown_bfd_g_ach_channel_type", m_unknown_bfd_g_ach_channel_type));
            archive(::cereal::make_nvp("bfd_over_pwe_ra", m_bfd_over_pwe_ra));
            archive(::cereal::make_nvp("mpls_tp_over_pwe", m_mpls_tp_over_pwe));
            archive(::cereal::make_nvp("unknown_g_ach", m_unknown_g_ach));
            archive(::cereal::make_nvp("mpls_tp_over_lsp", m_mpls_tp_over_lsp));
            archive(::cereal::make_nvp("oam_alert_label", m_oam_alert_label));
            archive(::cereal::make_nvp("extension_label", m_extension_label));
            archive(::cereal::make_nvp("router_alert_label", m_router_alert_label));
            archive(::cereal::make_nvp("unexpected_reserved_label", m_unexpected_reserved_label));
            archive(::cereal::make_nvp("forwarding_disabled", m_forwarding_disabled));
            archive(::cereal::make_nvp("ilm_miss", m_ilm_miss));
            archive(::cereal::make_nvp("ipv4_over_ipv6_explicit_null", m_ipv4_over_ipv6_explicit_null));
            archive(::cereal::make_nvp("invalid_ttl", m_invalid_ttl));
            archive(::cereal::make_nvp("te_midpopint_ldp_labels_miss", m_te_midpopint_ldp_labels_miss));
            archive(::cereal::make_nvp("asbr_label_miss", m_asbr_label_miss));
            archive(::cereal::make_nvp("ilm_vrf_label_miss", m_ilm_vrf_label_miss));
            archive(::cereal::make_nvp("pwe_pwach", m_pwe_pwach));
            archive(::cereal::make_nvp("vpn_ttl_one", m_vpn_ttl_one));
            archive(::cereal::make_nvp("missing_fwd_label_after_pop", m_missing_fwd_label_after_pop));
        m.unknown_protocol_after_bos = m_unknown_protocol_after_bos;
        m.ttl_is_zero = m_ttl_is_zero;
        m.bfd_over_pwe_ttl = m_bfd_over_pwe_ttl;
        m.bfd_over_pwe_raw = m_bfd_over_pwe_raw;
        m.bfd_over_pwe_ipv4 = m_bfd_over_pwe_ipv4;
        m.bfd_over_pwe_ipv6 = m_bfd_over_pwe_ipv6;
        m.unknown_bfd_g_ach_channel_type = m_unknown_bfd_g_ach_channel_type;
        m.bfd_over_pwe_ra = m_bfd_over_pwe_ra;
        m.mpls_tp_over_pwe = m_mpls_tp_over_pwe;
        m.unknown_g_ach = m_unknown_g_ach;
        m.mpls_tp_over_lsp = m_mpls_tp_over_lsp;
        m.oam_alert_label = m_oam_alert_label;
        m.extension_label = m_extension_label;
        m.router_alert_label = m_router_alert_label;
        m.unexpected_reserved_label = m_unexpected_reserved_label;
        m.forwarding_disabled = m_forwarding_disabled;
        m.ilm_miss = m_ilm_miss;
        m.ipv4_over_ipv6_explicit_null = m_ipv4_over_ipv6_explicit_null;
        m.invalid_ttl = m_invalid_ttl;
        m.te_midpopint_ldp_labels_miss = m_te_midpopint_ldp_labels_miss;
        m.asbr_label_miss = m_asbr_label_miss;
        m.ilm_vrf_label_miss = m_ilm_vrf_label_miss;
        m.pwe_pwach = m_pwe_pwach;
        m.vpn_ttl_one = m_vpn_ttl_one;
        m.missing_fwd_label_after_pop = m_missing_fwd_label_after_pop;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_traps_t& m)
{
    serializer_class<npl_mpls_traps_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_traps_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_traps_t& m)
{
    serializer_class<npl_mpls_traps_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_traps_t&);



template<>
class serializer_class<npl_ms_voq_fabric_context_offset_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ms_voq_fabric_context_offset_table_result_t& m) {
        uint64_t m_ms_voq_fabric_context_offset = m.ms_voq_fabric_context_offset;
            archive(::cereal::make_nvp("ms_voq_fabric_context_offset", m_ms_voq_fabric_context_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ms_voq_fabric_context_offset_table_result_t& m) {
        uint64_t m_ms_voq_fabric_context_offset;
            archive(::cereal::make_nvp("ms_voq_fabric_context_offset", m_ms_voq_fabric_context_offset));
        m.ms_voq_fabric_context_offset = m_ms_voq_fabric_context_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ms_voq_fabric_context_offset_table_result_t& m)
{
    serializer_class<npl_ms_voq_fabric_context_offset_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ms_voq_fabric_context_offset_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_ms_voq_fabric_context_offset_table_result_t& m)
{
    serializer_class<npl_ms_voq_fabric_context_offset_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ms_voq_fabric_context_offset_table_result_t&);



template<>
class serializer_class<npl_my_dummy_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_my_dummy_result_t& m) {
        uint64_t m_val = m.val;
            archive(::cereal::make_nvp("val", m_val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_my_dummy_result_t& m) {
        uint64_t m_val;
            archive(::cereal::make_nvp("val", m_val));
        m.val = m_val;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_my_dummy_result_t& m)
{
    serializer_class<npl_my_dummy_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_my_dummy_result_t&);

template <class Archive>
void
load(Archive& archive, npl_my_dummy_result_t& m)
{
    serializer_class<npl_my_dummy_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_my_dummy_result_t&);



template<>
class serializer_class<npl_my_frag_max_result_128_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_my_frag_max_result_128_t& m) {
            archive(::cereal::make_nvp("val", m.val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_my_frag_max_result_128_t& m) {
            archive(::cereal::make_nvp("val", m.val));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_my_frag_max_result_128_t& m)
{
    serializer_class<npl_my_frag_max_result_128_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_my_frag_max_result_128_t&);

template <class Archive>
void
load(Archive& archive, npl_my_frag_max_result_128_t& m)
{
    serializer_class<npl_my_frag_max_result_128_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_my_frag_max_result_128_t&);



template<>
class serializer_class<npl_my_one_bit_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_my_one_bit_result_t& m) {
        uint64_t m_val = m.val;
            archive(::cereal::make_nvp("val", m_val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_my_one_bit_result_t& m) {
        uint64_t m_val;
            archive(::cereal::make_nvp("val", m_val));
        m.val = m_val;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_my_one_bit_result_t& m)
{
    serializer_class<npl_my_one_bit_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_my_one_bit_result_t&);

template <class Archive>
void
load(Archive& archive, npl_my_one_bit_result_t& m)
{
    serializer_class<npl_my_one_bit_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_my_one_bit_result_t&);



template<>
class serializer_class<npl_next_header_and_hop_limit_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_next_header_and_hop_limit_t& m) {
        uint64_t m_next_header = m.next_header;
        uint64_t m_hop_limit = m.hop_limit;
            archive(::cereal::make_nvp("next_header", m_next_header));
            archive(::cereal::make_nvp("hop_limit", m_hop_limit));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_next_header_and_hop_limit_t& m) {
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
save(Archive& archive, const npl_next_header_and_hop_limit_t& m)
{
    serializer_class<npl_next_header_and_hop_limit_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_next_header_and_hop_limit_t&);

template <class Archive>
void
load(Archive& archive, npl_next_header_and_hop_limit_t& m)
{
    serializer_class<npl_next_header_and_hop_limit_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_next_header_and_hop_limit_t&);



template<>
class serializer_class<npl_nhlfe_type_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_nhlfe_type_attributes_t& m) {
            archive(::cereal::make_nvp("encap_type", m.encap_type));
            archive(::cereal::make_nvp("midpoint_nh_destination_encoding", m.midpoint_nh_destination_encoding));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_nhlfe_type_attributes_t& m) {
            archive(::cereal::make_nvp("encap_type", m.encap_type));
            archive(::cereal::make_nvp("midpoint_nh_destination_encoding", m.midpoint_nh_destination_encoding));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_nhlfe_type_attributes_t& m)
{
    serializer_class<npl_nhlfe_type_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_nhlfe_type_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_nhlfe_type_attributes_t& m)
{
    serializer_class<npl_nhlfe_type_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_nhlfe_type_attributes_t&);



template<>
class serializer_class<npl_npl_internal_info_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npl_internal_info_t& m) {
        uint64_t m_tx_redirect_code = m.tx_redirect_code;
            archive(::cereal::make_nvp("tx_redirect_code", m_tx_redirect_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npl_internal_info_t& m) {
        uint64_t m_tx_redirect_code;
            archive(::cereal::make_nvp("tx_redirect_code", m_tx_redirect_code));
        m.tx_redirect_code = m_tx_redirect_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npl_internal_info_t& m)
{
    serializer_class<npl_npl_internal_info_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npl_internal_info_t&);

template <class Archive>
void
load(Archive& archive, npl_npl_internal_info_t& m)
{
    serializer_class<npl_npl_internal_info_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npl_internal_info_t&);



template<>
class serializer_class<npl_npp_sgt_map_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npp_sgt_map_header_t& m) {
        uint64_t m_security_group = m.security_group;
            archive(::cereal::make_nvp("security_group", m_security_group));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npp_sgt_map_header_t& m) {
        uint64_t m_security_group;
            archive(::cereal::make_nvp("security_group", m_security_group));
        m.security_group = m_security_group;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npp_sgt_map_header_t& m)
{
    serializer_class<npl_npp_sgt_map_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npp_sgt_map_header_t&);

template <class Archive>
void
load(Archive& archive, npl_npp_sgt_map_header_t& m)
{
    serializer_class<npl_npp_sgt_map_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npp_sgt_map_header_t&);



template<>
class serializer_class<npl_npu_app_pack_fields_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npu_app_pack_fields_t& m) {
        uint64_t m_force_pipe_ttl = m.force_pipe_ttl;
        uint64_t m_ttl = m.ttl;
            archive(::cereal::make_nvp("force_pipe_ttl", m_force_pipe_ttl));
            archive(::cereal::make_nvp("is_inject_up_and_ip_first_fragment", m.is_inject_up_and_ip_first_fragment));
            archive(::cereal::make_nvp("ttl", m_ttl));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npu_app_pack_fields_t& m) {
        uint64_t m_force_pipe_ttl;
        uint64_t m_ttl;
            archive(::cereal::make_nvp("force_pipe_ttl", m_force_pipe_ttl));
            archive(::cereal::make_nvp("is_inject_up_and_ip_first_fragment", m.is_inject_up_and_ip_first_fragment));
            archive(::cereal::make_nvp("ttl", m_ttl));
        m.force_pipe_ttl = m_force_pipe_ttl;
        m.ttl = m_ttl;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npu_app_pack_fields_t& m)
{
    serializer_class<npl_npu_app_pack_fields_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npu_app_pack_fields_t&);

template <class Archive>
void
load(Archive& archive, npl_npu_app_pack_fields_t& m)
{
    serializer_class<npl_npu_app_pack_fields_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npu_app_pack_fields_t&);



template<>
class serializer_class<npl_npu_encap_header_l2_dlp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npu_encap_header_l2_dlp_t& m) {
            archive(::cereal::make_nvp("l2_dlp", m.l2_dlp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npu_encap_header_l2_dlp_t& m) {
            archive(::cereal::make_nvp("l2_dlp", m.l2_dlp));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npu_encap_header_l2_dlp_t& m)
{
    serializer_class<npl_npu_encap_header_l2_dlp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npu_encap_header_l2_dlp_t&);

template <class Archive>
void
load(Archive& archive, npl_npu_encap_header_l2_dlp_t& m)
{
    serializer_class<npl_npu_encap_header_l2_dlp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npu_encap_header_l2_dlp_t&);



template<>
class serializer_class<npl_npu_host_data_result_count_phase_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npu_host_data_result_count_phase_t& m) {
        uint64_t m_dm_count_phase = m.dm_count_phase;
        uint64_t m_dm_period = m.dm_period;
        uint64_t m_lm_count_phase = m.lm_count_phase;
        uint64_t m_lm_period = m.lm_period;
        uint64_t m_ccm_count_phase = m.ccm_count_phase;
            archive(::cereal::make_nvp("mp_data", m.mp_data));
            archive(::cereal::make_nvp("dm_count_phase", m_dm_count_phase));
            archive(::cereal::make_nvp("dm_period", m_dm_period));
            archive(::cereal::make_nvp("lm_count_phase", m_lm_count_phase));
            archive(::cereal::make_nvp("lm_period", m_lm_period));
            archive(::cereal::make_nvp("ccm_count_phase", m_ccm_count_phase));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npu_host_data_result_count_phase_t& m) {
        uint64_t m_dm_count_phase;
        uint64_t m_dm_period;
        uint64_t m_lm_count_phase;
        uint64_t m_lm_period;
        uint64_t m_ccm_count_phase;
            archive(::cereal::make_nvp("mp_data", m.mp_data));
            archive(::cereal::make_nvp("dm_count_phase", m_dm_count_phase));
            archive(::cereal::make_nvp("dm_period", m_dm_period));
            archive(::cereal::make_nvp("lm_count_phase", m_lm_count_phase));
            archive(::cereal::make_nvp("lm_period", m_lm_period));
            archive(::cereal::make_nvp("ccm_count_phase", m_ccm_count_phase));
        m.dm_count_phase = m_dm_count_phase;
        m.dm_period = m_dm_period;
        m.lm_count_phase = m_lm_count_phase;
        m.lm_period = m_lm_period;
        m.ccm_count_phase = m_ccm_count_phase;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npu_host_data_result_count_phase_t& m)
{
    serializer_class<npl_npu_host_data_result_count_phase_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npu_host_data_result_count_phase_t&);

template <class Archive>
void
load(Archive& archive, npl_npu_host_data_result_count_phase_t& m)
{
    serializer_class<npl_npu_host_data_result_count_phase_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npu_host_data_result_count_phase_t&);



template<>
class serializer_class<npl_npu_l3_mc_accounting_encap_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npu_l3_mc_accounting_encap_data_t& m) {
            archive(::cereal::make_nvp("mcg_counter_ptr", m.mcg_counter_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npu_l3_mc_accounting_encap_data_t& m) {
            archive(::cereal::make_nvp("mcg_counter_ptr", m.mcg_counter_ptr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npu_l3_mc_accounting_encap_data_t& m)
{
    serializer_class<npl_npu_l3_mc_accounting_encap_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npu_l3_mc_accounting_encap_data_t&);

template <class Archive>
void
load(Archive& archive, npl_npu_l3_mc_accounting_encap_data_t& m)
{
    serializer_class<npl_npu_l3_mc_accounting_encap_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npu_l3_mc_accounting_encap_data_t&);



template<>
class serializer_class<npl_num_labels_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_num_labels_t& m) {
        uint64_t m_total_num_labels = m.total_num_labels;
            archive(::cereal::make_nvp("total_num_labels", m_total_num_labels));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_num_labels_t& m) {
        uint64_t m_total_num_labels;
            archive(::cereal::make_nvp("total_num_labels", m_total_num_labels));
        m.total_num_labels = m_total_num_labels;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_num_labels_t& m)
{
    serializer_class<npl_num_labels_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_num_labels_t&);

template <class Archive>
void
load(Archive& archive, npl_num_labels_t& m)
{
    serializer_class<npl_num_labels_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_num_labels_t&);



template<>
class serializer_class<npl_num_outer_transport_labels_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_num_outer_transport_labels_t& m) {
        uint64_t m_total_num_labels = m.total_num_labels;
        uint64_t m_num_labels_is_3 = m.num_labels_is_3;
            archive(::cereal::make_nvp("total_num_labels", m_total_num_labels));
            archive(::cereal::make_nvp("num_labels_is_3", m_num_labels_is_3));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_num_outer_transport_labels_t& m) {
        uint64_t m_total_num_labels;
        uint64_t m_num_labels_is_3;
            archive(::cereal::make_nvp("total_num_labels", m_total_num_labels));
            archive(::cereal::make_nvp("num_labels_is_3", m_num_labels_is_3));
        m.total_num_labels = m_total_num_labels;
        m.num_labels_is_3 = m_num_labels_is_3;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_num_outer_transport_labels_t& m)
{
    serializer_class<npl_num_outer_transport_labels_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_num_outer_transport_labels_t&);

template <class Archive>
void
load(Archive& archive, npl_num_outer_transport_labels_t& m)
{
    serializer_class<npl_num_outer_transport_labels_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_num_outer_transport_labels_t&);



template<>
class serializer_class<npl_oamp_traps_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_traps_t& m) {
        uint64_t m_eth_unknown_punt_reason = m.eth_unknown_punt_reason;
        uint64_t m_eth_mep_mapping_failed = m.eth_mep_mapping_failed;
        uint64_t m_eth_mp_type_mismatch = m.eth_mp_type_mismatch;
        uint64_t m_eth_meg_level_mismatch = m.eth_meg_level_mismatch;
        uint64_t m_eth_bad_md_name_format = m.eth_bad_md_name_format;
        uint64_t m_eth_unicast_da_no_match = m.eth_unicast_da_no_match;
        uint64_t m_eth_multicast_da_no_match = m.eth_multicast_da_no_match;
        uint64_t m_eth_wrong_meg_id_format = m.eth_wrong_meg_id_format;
        uint64_t m_eth_meg_id_no_match = m.eth_meg_id_no_match;
        uint64_t m_eth_ccm_period_no_match = m.eth_ccm_period_no_match;
        uint64_t m_eth_ccm_tlv_no_match = m.eth_ccm_tlv_no_match;
        uint64_t m_eth_lmm_tlv_no_match = m.eth_lmm_tlv_no_match;
        uint64_t m_eth_not_supported_oam_opcode = m.eth_not_supported_oam_opcode;
        uint64_t m_bfd_transport_not_supported = m.bfd_transport_not_supported;
        uint64_t m_bfd_session_lookup_failed = m.bfd_session_lookup_failed;
        uint64_t m_bfd_incorrect_ttl = m.bfd_incorrect_ttl;
        uint64_t m_bfd_invalid_protocol = m.bfd_invalid_protocol;
        uint64_t m_bfd_invalid_udp_port = m.bfd_invalid_udp_port;
        uint64_t m_bfd_incorrect_version = m.bfd_incorrect_version;
        uint64_t m_bfd_incorrect_address = m.bfd_incorrect_address;
        uint64_t m_bfd_mismatch_discr = m.bfd_mismatch_discr;
        uint64_t m_bfd_state_flag_change = m.bfd_state_flag_change;
        uint64_t m_bfd_session_received = m.bfd_session_received;
        uint64_t m_pfc_lookup_failed = m.pfc_lookup_failed;
        uint64_t m_pfc_drop_invalid_rx = m.pfc_drop_invalid_rx;
            archive(::cereal::make_nvp("eth_unknown_punt_reason", m_eth_unknown_punt_reason));
            archive(::cereal::make_nvp("eth_mep_mapping_failed", m_eth_mep_mapping_failed));
            archive(::cereal::make_nvp("eth_mp_type_mismatch", m_eth_mp_type_mismatch));
            archive(::cereal::make_nvp("eth_meg_level_mismatch", m_eth_meg_level_mismatch));
            archive(::cereal::make_nvp("eth_bad_md_name_format", m_eth_bad_md_name_format));
            archive(::cereal::make_nvp("eth_unicast_da_no_match", m_eth_unicast_da_no_match));
            archive(::cereal::make_nvp("eth_multicast_da_no_match", m_eth_multicast_da_no_match));
            archive(::cereal::make_nvp("eth_wrong_meg_id_format", m_eth_wrong_meg_id_format));
            archive(::cereal::make_nvp("eth_meg_id_no_match", m_eth_meg_id_no_match));
            archive(::cereal::make_nvp("eth_ccm_period_no_match", m_eth_ccm_period_no_match));
            archive(::cereal::make_nvp("eth_ccm_tlv_no_match", m_eth_ccm_tlv_no_match));
            archive(::cereal::make_nvp("eth_lmm_tlv_no_match", m_eth_lmm_tlv_no_match));
            archive(::cereal::make_nvp("eth_not_supported_oam_opcode", m_eth_not_supported_oam_opcode));
            archive(::cereal::make_nvp("bfd_transport_not_supported", m_bfd_transport_not_supported));
            archive(::cereal::make_nvp("bfd_session_lookup_failed", m_bfd_session_lookup_failed));
            archive(::cereal::make_nvp("bfd_incorrect_ttl", m_bfd_incorrect_ttl));
            archive(::cereal::make_nvp("bfd_invalid_protocol", m_bfd_invalid_protocol));
            archive(::cereal::make_nvp("bfd_invalid_udp_port", m_bfd_invalid_udp_port));
            archive(::cereal::make_nvp("bfd_incorrect_version", m_bfd_incorrect_version));
            archive(::cereal::make_nvp("bfd_incorrect_address", m_bfd_incorrect_address));
            archive(::cereal::make_nvp("bfd_mismatch_discr", m_bfd_mismatch_discr));
            archive(::cereal::make_nvp("bfd_state_flag_change", m_bfd_state_flag_change));
            archive(::cereal::make_nvp("bfd_session_received", m_bfd_session_received));
            archive(::cereal::make_nvp("pfc_lookup_failed", m_pfc_lookup_failed));
            archive(::cereal::make_nvp("pfc_drop_invalid_rx", m_pfc_drop_invalid_rx));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_traps_t& m) {
        uint64_t m_eth_unknown_punt_reason;
        uint64_t m_eth_mep_mapping_failed;
        uint64_t m_eth_mp_type_mismatch;
        uint64_t m_eth_meg_level_mismatch;
        uint64_t m_eth_bad_md_name_format;
        uint64_t m_eth_unicast_da_no_match;
        uint64_t m_eth_multicast_da_no_match;
        uint64_t m_eth_wrong_meg_id_format;
        uint64_t m_eth_meg_id_no_match;
        uint64_t m_eth_ccm_period_no_match;
        uint64_t m_eth_ccm_tlv_no_match;
        uint64_t m_eth_lmm_tlv_no_match;
        uint64_t m_eth_not_supported_oam_opcode;
        uint64_t m_bfd_transport_not_supported;
        uint64_t m_bfd_session_lookup_failed;
        uint64_t m_bfd_incorrect_ttl;
        uint64_t m_bfd_invalid_protocol;
        uint64_t m_bfd_invalid_udp_port;
        uint64_t m_bfd_incorrect_version;
        uint64_t m_bfd_incorrect_address;
        uint64_t m_bfd_mismatch_discr;
        uint64_t m_bfd_state_flag_change;
        uint64_t m_bfd_session_received;
        uint64_t m_pfc_lookup_failed;
        uint64_t m_pfc_drop_invalid_rx;
            archive(::cereal::make_nvp("eth_unknown_punt_reason", m_eth_unknown_punt_reason));
            archive(::cereal::make_nvp("eth_mep_mapping_failed", m_eth_mep_mapping_failed));
            archive(::cereal::make_nvp("eth_mp_type_mismatch", m_eth_mp_type_mismatch));
            archive(::cereal::make_nvp("eth_meg_level_mismatch", m_eth_meg_level_mismatch));
            archive(::cereal::make_nvp("eth_bad_md_name_format", m_eth_bad_md_name_format));
            archive(::cereal::make_nvp("eth_unicast_da_no_match", m_eth_unicast_da_no_match));
            archive(::cereal::make_nvp("eth_multicast_da_no_match", m_eth_multicast_da_no_match));
            archive(::cereal::make_nvp("eth_wrong_meg_id_format", m_eth_wrong_meg_id_format));
            archive(::cereal::make_nvp("eth_meg_id_no_match", m_eth_meg_id_no_match));
            archive(::cereal::make_nvp("eth_ccm_period_no_match", m_eth_ccm_period_no_match));
            archive(::cereal::make_nvp("eth_ccm_tlv_no_match", m_eth_ccm_tlv_no_match));
            archive(::cereal::make_nvp("eth_lmm_tlv_no_match", m_eth_lmm_tlv_no_match));
            archive(::cereal::make_nvp("eth_not_supported_oam_opcode", m_eth_not_supported_oam_opcode));
            archive(::cereal::make_nvp("bfd_transport_not_supported", m_bfd_transport_not_supported));
            archive(::cereal::make_nvp("bfd_session_lookup_failed", m_bfd_session_lookup_failed));
            archive(::cereal::make_nvp("bfd_incorrect_ttl", m_bfd_incorrect_ttl));
            archive(::cereal::make_nvp("bfd_invalid_protocol", m_bfd_invalid_protocol));
            archive(::cereal::make_nvp("bfd_invalid_udp_port", m_bfd_invalid_udp_port));
            archive(::cereal::make_nvp("bfd_incorrect_version", m_bfd_incorrect_version));
            archive(::cereal::make_nvp("bfd_incorrect_address", m_bfd_incorrect_address));
            archive(::cereal::make_nvp("bfd_mismatch_discr", m_bfd_mismatch_discr));
            archive(::cereal::make_nvp("bfd_state_flag_change", m_bfd_state_flag_change));
            archive(::cereal::make_nvp("bfd_session_received", m_bfd_session_received));
            archive(::cereal::make_nvp("pfc_lookup_failed", m_pfc_lookup_failed));
            archive(::cereal::make_nvp("pfc_drop_invalid_rx", m_pfc_drop_invalid_rx));
        m.eth_unknown_punt_reason = m_eth_unknown_punt_reason;
        m.eth_mep_mapping_failed = m_eth_mep_mapping_failed;
        m.eth_mp_type_mismatch = m_eth_mp_type_mismatch;
        m.eth_meg_level_mismatch = m_eth_meg_level_mismatch;
        m.eth_bad_md_name_format = m_eth_bad_md_name_format;
        m.eth_unicast_da_no_match = m_eth_unicast_da_no_match;
        m.eth_multicast_da_no_match = m_eth_multicast_da_no_match;
        m.eth_wrong_meg_id_format = m_eth_wrong_meg_id_format;
        m.eth_meg_id_no_match = m_eth_meg_id_no_match;
        m.eth_ccm_period_no_match = m_eth_ccm_period_no_match;
        m.eth_ccm_tlv_no_match = m_eth_ccm_tlv_no_match;
        m.eth_lmm_tlv_no_match = m_eth_lmm_tlv_no_match;
        m.eth_not_supported_oam_opcode = m_eth_not_supported_oam_opcode;
        m.bfd_transport_not_supported = m_bfd_transport_not_supported;
        m.bfd_session_lookup_failed = m_bfd_session_lookup_failed;
        m.bfd_incorrect_ttl = m_bfd_incorrect_ttl;
        m.bfd_invalid_protocol = m_bfd_invalid_protocol;
        m.bfd_invalid_udp_port = m_bfd_invalid_udp_port;
        m.bfd_incorrect_version = m_bfd_incorrect_version;
        m.bfd_incorrect_address = m_bfd_incorrect_address;
        m.bfd_mismatch_discr = m_bfd_mismatch_discr;
        m.bfd_state_flag_change = m_bfd_state_flag_change;
        m.bfd_session_received = m_bfd_session_received;
        m.pfc_lookup_failed = m_pfc_lookup_failed;
        m.pfc_drop_invalid_rx = m_pfc_drop_invalid_rx;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_traps_t& m)
{
    serializer_class<npl_oamp_traps_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_traps_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_traps_t& m)
{
    serializer_class<npl_oamp_traps_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_traps_t&);



template<>
class serializer_class<npl_obm_to_inject_packed_vars_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_obm_to_inject_packed_vars_t& m) {
        uint64_t m_redirect_code = m.redirect_code;
        uint64_t m_l2_slp = m.l2_slp;
            archive(::cereal::make_nvp("redirect_code", m_redirect_code));
            archive(::cereal::make_nvp("l2_slp", m_l2_slp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_obm_to_inject_packed_vars_t& m) {
        uint64_t m_redirect_code;
        uint64_t m_l2_slp;
            archive(::cereal::make_nvp("redirect_code", m_redirect_code));
            archive(::cereal::make_nvp("l2_slp", m_l2_slp));
        m.redirect_code = m_redirect_code;
        m.l2_slp = m_l2_slp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_obm_to_inject_packed_vars_t& m)
{
    serializer_class<npl_obm_to_inject_packed_vars_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_obm_to_inject_packed_vars_t&);

template <class Archive>
void
load(Archive& archive, npl_obm_to_inject_packed_vars_t& m)
{
    serializer_class<npl_obm_to_inject_packed_vars_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_obm_to_inject_packed_vars_t&);



template<>
class serializer_class<npl_og_lpm_compression_code_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_og_lpm_compression_code_t& m) {
        uint64_t m_bits_n_18 = m.bits_n_18;
        uint64_t m_zero = m.zero;
        uint64_t m_bits_17_0 = m.bits_17_0;
            archive(::cereal::make_nvp("bits_n_18", m_bits_n_18));
            archive(::cereal::make_nvp("zero", m_zero));
            archive(::cereal::make_nvp("bits_17_0", m_bits_17_0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_og_lpm_compression_code_t& m) {
        uint64_t m_bits_n_18;
        uint64_t m_zero;
        uint64_t m_bits_17_0;
            archive(::cereal::make_nvp("bits_n_18", m_bits_n_18));
            archive(::cereal::make_nvp("zero", m_zero));
            archive(::cereal::make_nvp("bits_17_0", m_bits_17_0));
        m.bits_n_18 = m_bits_n_18;
        m.zero = m_zero;
        m.bits_17_0 = m_bits_17_0;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_og_lpm_compression_code_t& m)
{
    serializer_class<npl_og_lpm_compression_code_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_og_lpm_compression_code_t&);

template <class Archive>
void
load(Archive& archive, npl_og_lpm_compression_code_t& m)
{
    serializer_class<npl_og_lpm_compression_code_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_og_lpm_compression_code_t&);



template<>
class serializer_class<npl_og_lpts_compression_code_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_og_lpts_compression_code_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_og_lpts_compression_code_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_og_lpts_compression_code_t& m)
{
    serializer_class<npl_og_lpts_compression_code_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_og_lpts_compression_code_t&);

template <class Archive>
void
load(Archive& archive, npl_og_lpts_compression_code_t& m)
{
    serializer_class<npl_og_lpts_compression_code_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_og_lpts_compression_code_t&);



template<>
class serializer_class<npl_og_pcl_compress_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_og_pcl_compress_t& m) {
        uint64_t m_src_compress = m.src_compress;
        uint64_t m_dest_compress = m.dest_compress;
            archive(::cereal::make_nvp("src_compress", m_src_compress));
            archive(::cereal::make_nvp("dest_compress", m_dest_compress));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_og_pcl_compress_t& m) {
        uint64_t m_src_compress;
        uint64_t m_dest_compress;
            archive(::cereal::make_nvp("src_compress", m_src_compress));
            archive(::cereal::make_nvp("dest_compress", m_dest_compress));
        m.src_compress = m_src_compress;
        m.dest_compress = m_dest_compress;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_og_pcl_compress_t& m)
{
    serializer_class<npl_og_pcl_compress_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_og_pcl_compress_t&);

template <class Archive>
void
load(Archive& archive, npl_og_pcl_compress_t& m)
{
    serializer_class<npl_og_pcl_compress_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_og_pcl_compress_t&);



template<>
class serializer_class<npl_og_pcl_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_og_pcl_id_t& m) {
        uint64_t m_val = m.val;
            archive(::cereal::make_nvp("val", m_val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_og_pcl_id_t& m) {
        uint64_t m_val;
            archive(::cereal::make_nvp("val", m_val));
        m.val = m_val;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_og_pcl_id_t& m)
{
    serializer_class<npl_og_pcl_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_og_pcl_id_t&);

template <class Archive>
void
load(Archive& archive, npl_og_pcl_id_t& m)
{
    serializer_class<npl_og_pcl_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_og_pcl_id_t&);



template<>
class serializer_class<npl_og_pcl_ids_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_og_pcl_ids_t& m) {
            archive(::cereal::make_nvp("src_pcl_id", m.src_pcl_id));
            archive(::cereal::make_nvp("dest_pcl_id", m.dest_pcl_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_og_pcl_ids_t& m) {
            archive(::cereal::make_nvp("src_pcl_id", m.src_pcl_id));
            archive(::cereal::make_nvp("dest_pcl_id", m.dest_pcl_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_og_pcl_ids_t& m)
{
    serializer_class<npl_og_pcl_ids_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_og_pcl_ids_t&);

template <class Archive>
void
load(Archive& archive, npl_og_pcl_ids_t& m)
{
    serializer_class<npl_og_pcl_ids_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_og_pcl_ids_t&);



template<>
class serializer_class<npl_og_pd_compression_code_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_og_pd_compression_code_t& m) {
        uint64_t m_bits_n_18 = m.bits_n_18;
        uint64_t m_bits_17_0 = m.bits_17_0;
            archive(::cereal::make_nvp("bits_n_18", m_bits_n_18));
            archive(::cereal::make_nvp("bits_17_0", m_bits_17_0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_og_pd_compression_code_t& m) {
        uint64_t m_bits_n_18;
        uint64_t m_bits_17_0;
            archive(::cereal::make_nvp("bits_n_18", m_bits_n_18));
            archive(::cereal::make_nvp("bits_17_0", m_bits_17_0));
        m.bits_n_18 = m_bits_n_18;
        m.bits_17_0 = m_bits_17_0;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_og_pd_compression_code_t& m)
{
    serializer_class<npl_og_pd_compression_code_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_og_pd_compression_code_t&);

template <class Archive>
void
load(Archive& archive, npl_og_pd_compression_code_t& m)
{
    serializer_class<npl_og_pd_compression_code_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_og_pd_compression_code_t&);



template<>
class serializer_class<npl_omd_txpp_parsed_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_omd_txpp_parsed_t& m) {
        uint64_t m_oq_pair = m.oq_pair;
        uint64_t m_pif = m.pif;
        uint64_t m_ifg = m.ifg;
            archive(::cereal::make_nvp("oq_pair", m_oq_pair));
            archive(::cereal::make_nvp("pif", m_pif));
            archive(::cereal::make_nvp("ifg", m_ifg));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_omd_txpp_parsed_t& m) {
        uint64_t m_oq_pair;
        uint64_t m_pif;
        uint64_t m_ifg;
            archive(::cereal::make_nvp("oq_pair", m_oq_pair));
            archive(::cereal::make_nvp("pif", m_pif));
            archive(::cereal::make_nvp("ifg", m_ifg));
        m.oq_pair = m_oq_pair;
        m.pif = m_pif;
        m.ifg = m_ifg;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_omd_txpp_parsed_t& m)
{
    serializer_class<npl_omd_txpp_parsed_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_omd_txpp_parsed_t&);

template <class Archive>
void
load(Archive& archive, npl_omd_txpp_parsed_t& m)
{
    serializer_class<npl_omd_txpp_parsed_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_omd_txpp_parsed_t&);



template<>
class serializer_class<npl_oq_group_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oq_group_t& m) {
        uint64_t m_val = m.val;
            archive(::cereal::make_nvp("val", m_val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oq_group_t& m) {
        uint64_t m_val;
            archive(::cereal::make_nvp("val", m_val));
        m.val = m_val;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oq_group_t& m)
{
    serializer_class<npl_oq_group_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oq_group_t&);

template <class Archive>
void
load(Archive& archive, npl_oq_group_t& m)
{
    serializer_class<npl_oq_group_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oq_group_t&);



template<>
class serializer_class<npl_oqse_pair_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oqse_pair_t& m) {
        uint64_t m_index = m.index;
            archive(::cereal::make_nvp("index", m_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oqse_pair_t& m) {
        uint64_t m_index;
            archive(::cereal::make_nvp("index", m_index));
        m.index = m_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oqse_pair_t& m)
{
    serializer_class<npl_oqse_pair_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oqse_pair_t&);

template <class Archive>
void
load(Archive& archive, npl_oqse_pair_t& m)
{
    serializer_class<npl_oqse_pair_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oqse_pair_t&);



template<>
class serializer_class<npl_oqse_topology_4p_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oqse_topology_4p_t& m) {
            archive(::cereal::make_nvp("lpse_tpse_4p", m.lpse_tpse_4p));
            archive(::cereal::make_nvp("lpse_2p", m.lpse_2p));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oqse_topology_4p_t& m) {
            archive(::cereal::make_nvp("lpse_tpse_4p", m.lpse_tpse_4p));
            archive(::cereal::make_nvp("lpse_2p", m.lpse_2p));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oqse_topology_4p_t& m)
{
    serializer_class<npl_oqse_topology_4p_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oqse_topology_4p_t&);

template <class Archive>
void
load(Archive& archive, npl_oqse_topology_4p_t& m)
{
    serializer_class<npl_oqse_topology_4p_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oqse_topology_4p_t&);



template<>
class serializer_class<npl_overlay_nh_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_overlay_nh_data_t& m) {
        uint64_t m_mac_da = m.mac_da;
        uint64_t m_sa_prefix_index = m.sa_prefix_index;
        uint64_t m_sa_lsb = m.sa_lsb;
            archive(::cereal::make_nvp("mac_da", m_mac_da));
            archive(::cereal::make_nvp("sa_prefix_index", m_sa_prefix_index));
            archive(::cereal::make_nvp("sa_lsb", m_sa_lsb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_overlay_nh_data_t& m) {
        uint64_t m_mac_da;
        uint64_t m_sa_prefix_index;
        uint64_t m_sa_lsb;
            archive(::cereal::make_nvp("mac_da", m_mac_da));
            archive(::cereal::make_nvp("sa_prefix_index", m_sa_prefix_index));
            archive(::cereal::make_nvp("sa_lsb", m_sa_lsb));
        m.mac_da = m_mac_da;
        m.sa_prefix_index = m_sa_prefix_index;
        m.sa_lsb = m_sa_lsb;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_overlay_nh_data_t& m)
{
    serializer_class<npl_overlay_nh_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_overlay_nh_data_t&);

template <class Archive>
void
load(Archive& archive, npl_overlay_nh_data_t& m)
{
    serializer_class<npl_overlay_nh_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_overlay_nh_data_t&);



template<>
class serializer_class<npl_override_enable_ipv4_ipv6_uc_bits_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_override_enable_ipv4_ipv6_uc_bits_t& m) {
        uint64_t m_override_enable_ipv4_uc = m.override_enable_ipv4_uc;
        uint64_t m_override_enable_ipv6_uc = m.override_enable_ipv6_uc;
            archive(::cereal::make_nvp("override_enable_ipv4_uc", m_override_enable_ipv4_uc));
            archive(::cereal::make_nvp("override_enable_ipv6_uc", m_override_enable_ipv6_uc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_override_enable_ipv4_ipv6_uc_bits_t& m) {
        uint64_t m_override_enable_ipv4_uc;
        uint64_t m_override_enable_ipv6_uc;
            archive(::cereal::make_nvp("override_enable_ipv4_uc", m_override_enable_ipv4_uc));
            archive(::cereal::make_nvp("override_enable_ipv6_uc", m_override_enable_ipv6_uc));
        m.override_enable_ipv4_uc = m_override_enable_ipv4_uc;
        m.override_enable_ipv6_uc = m_override_enable_ipv6_uc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_override_enable_ipv4_ipv6_uc_bits_t& m)
{
    serializer_class<npl_override_enable_ipv4_ipv6_uc_bits_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_override_enable_ipv4_ipv6_uc_bits_t&);

template <class Archive>
void
load(Archive& archive, npl_override_enable_ipv4_ipv6_uc_bits_t& m)
{
    serializer_class<npl_override_enable_ipv4_ipv6_uc_bits_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_override_enable_ipv4_ipv6_uc_bits_t&);



template<>
class serializer_class<npl_packed_ud_160_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_packed_ud_160_key_t& m) {
            archive(::cereal::make_nvp("key", m.key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_packed_ud_160_key_t& m) {
            archive(::cereal::make_nvp("key", m.key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_packed_ud_160_key_t& m)
{
    serializer_class<npl_packed_ud_160_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_packed_ud_160_key_t&);

template <class Archive>
void
load(Archive& archive, npl_packed_ud_160_key_t& m)
{
    serializer_class<npl_packed_ud_160_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_packed_ud_160_key_t&);



template<>
class serializer_class<npl_packed_ud_320_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_packed_ud_320_key_t& m) {
            archive(::cereal::make_nvp("key_part0", m.key_part0));
            archive(::cereal::make_nvp("key_part1", m.key_part1));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_packed_ud_320_key_t& m) {
            archive(::cereal::make_nvp("key_part0", m.key_part0));
            archive(::cereal::make_nvp("key_part1", m.key_part1));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_packed_ud_320_key_t& m)
{
    serializer_class<npl_packed_ud_320_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_packed_ud_320_key_t&);

template <class Archive>
void
load(Archive& archive, npl_packed_ud_320_key_t& m)
{
    serializer_class<npl_packed_ud_320_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_packed_ud_320_key_t&);



template<>
class serializer_class<npl_padding_for_sm_tcam_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_padding_for_sm_tcam_t& m) {
            archive(::cereal::make_nvp("junk", m.junk));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_padding_for_sm_tcam_t& m) {
            archive(::cereal::make_nvp("junk", m.junk));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_padding_for_sm_tcam_t& m)
{
    serializer_class<npl_padding_for_sm_tcam_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_padding_for_sm_tcam_t&);

template <class Archive>
void
load(Archive& archive, npl_padding_for_sm_tcam_t& m)
{
    serializer_class<npl_padding_for_sm_tcam_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_padding_for_sm_tcam_t&);



template<>
class serializer_class<npl_padding_or_ipv6_len_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_padding_or_ipv6_len_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_padding_or_ipv6_len_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_padding_or_ipv6_len_t& m)
{
    serializer_class<npl_padding_or_ipv6_len_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_padding_or_ipv6_len_t&);

template <class Archive>
void
load(Archive& archive, npl_padding_or_ipv6_len_t& m)
{
    serializer_class<npl_padding_or_ipv6_len_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_padding_or_ipv6_len_t&);



template<>
class serializer_class<npl_pbts_map_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pbts_map_result_t& m) {
        uint64_t m_pbts_offset = m.pbts_offset;
        uint64_t m_destination_shift = m.destination_shift;
        uint64_t m_and_mask = m.and_mask;
            archive(::cereal::make_nvp("pbts_offset", m_pbts_offset));
            archive(::cereal::make_nvp("destination_shift", m_destination_shift));
            archive(::cereal::make_nvp("and_mask", m_and_mask));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pbts_map_result_t& m) {
        uint64_t m_pbts_offset;
        uint64_t m_destination_shift;
        uint64_t m_and_mask;
            archive(::cereal::make_nvp("pbts_offset", m_pbts_offset));
            archive(::cereal::make_nvp("destination_shift", m_destination_shift));
            archive(::cereal::make_nvp("and_mask", m_and_mask));
        m.pbts_offset = m_pbts_offset;
        m.destination_shift = m_destination_shift;
        m.and_mask = m_and_mask;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pbts_map_result_t& m)
{
    serializer_class<npl_pbts_map_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pbts_map_result_t&);

template <class Archive>
void
load(Archive& archive, npl_pbts_map_result_t& m)
{
    serializer_class<npl_pbts_map_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pbts_map_result_t&);



template<>
class serializer_class<npl_pcp_dei_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pcp_dei_t& m) {
        uint64_t m_pcp = m.pcp;
        uint64_t m_dei = m.dei;
            archive(::cereal::make_nvp("pcp", m_pcp));
            archive(::cereal::make_nvp("dei", m_dei));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pcp_dei_t& m) {
        uint64_t m_pcp;
        uint64_t m_dei;
            archive(::cereal::make_nvp("pcp", m_pcp));
            archive(::cereal::make_nvp("dei", m_dei));
        m.pcp = m_pcp;
        m.dei = m_dei;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pcp_dei_t& m)
{
    serializer_class<npl_pcp_dei_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pcp_dei_t&);

template <class Archive>
void
load(Archive& archive, npl_pcp_dei_t& m)
{
    serializer_class<npl_pcp_dei_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pcp_dei_t&);



template<>
class serializer_class<npl_pd_lp_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pd_lp_attributes_t& m) {
            archive(::cereal::make_nvp("update", m.update));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pd_lp_attributes_t& m) {
            archive(::cereal::make_nvp("update", m.update));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pd_lp_attributes_t& m)
{
    serializer_class<npl_pd_lp_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pd_lp_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_pd_lp_attributes_t& m)
{
    serializer_class<npl_pd_lp_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pd_lp_attributes_t&);



template<>
class serializer_class<npl_pd_rx_slb_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pd_rx_slb_t& m) {
        uint64_t m_eos = m.eos;
        uint64_t m_close_prev_segment = m.close_prev_segment;
            archive(::cereal::make_nvp("eos", m_eos));
            archive(::cereal::make_nvp("close_prev_segment", m_close_prev_segment));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pd_rx_slb_t& m) {
        uint64_t m_eos;
        uint64_t m_close_prev_segment;
            archive(::cereal::make_nvp("eos", m_eos));
            archive(::cereal::make_nvp("close_prev_segment", m_close_prev_segment));
        m.eos = m_eos;
        m.close_prev_segment = m_close_prev_segment;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pd_rx_slb_t& m)
{
    serializer_class<npl_pd_rx_slb_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pd_rx_slb_t&);

template <class Archive>
void
load(Archive& archive, npl_pd_rx_slb_t& m)
{
    serializer_class<npl_pd_rx_slb_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pd_rx_slb_t&);



template<>
class serializer_class<npl_pd_svl_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pd_svl_attributes_t& m) {
        uint64_t m_svl_dsp_remote_flag = m.svl_dsp_remote_flag;
        uint64_t m_svl_encap_forward_flag = m.svl_encap_forward_flag;
        uint64_t m_svl_bvn_flag = m.svl_bvn_flag;
            archive(::cereal::make_nvp("svl_dsp_remote_flag", m_svl_dsp_remote_flag));
            archive(::cereal::make_nvp("svl_encap_forward_flag", m_svl_encap_forward_flag));
            archive(::cereal::make_nvp("svl_bvn_flag", m_svl_bvn_flag));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pd_svl_attributes_t& m) {
        uint64_t m_svl_dsp_remote_flag;
        uint64_t m_svl_encap_forward_flag;
        uint64_t m_svl_bvn_flag;
            archive(::cereal::make_nvp("svl_dsp_remote_flag", m_svl_dsp_remote_flag));
            archive(::cereal::make_nvp("svl_encap_forward_flag", m_svl_encap_forward_flag));
            archive(::cereal::make_nvp("svl_bvn_flag", m_svl_bvn_flag));
        m.svl_dsp_remote_flag = m_svl_dsp_remote_flag;
        m.svl_encap_forward_flag = m_svl_encap_forward_flag;
        m.svl_bvn_flag = m_svl_bvn_flag;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pd_svl_attributes_t& m)
{
    serializer_class<npl_pd_svl_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pd_svl_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_pd_svl_attributes_t& m)
{
    serializer_class<npl_pd_svl_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pd_svl_attributes_t&);



template<>
class serializer_class<npl_pdoq_oq_ifc_mapping_result_t_anonymous_union_txpp_map_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pdoq_oq_ifc_mapping_result_t_anonymous_union_txpp_map_data_t& m) {
        uint64_t m_raw = m.raw;
            archive(::cereal::make_nvp("parsed", m.parsed));
            archive(::cereal::make_nvp("raw", m_raw));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pdoq_oq_ifc_mapping_result_t_anonymous_union_txpp_map_data_t& m) {
        uint64_t m_raw;
            archive(::cereal::make_nvp("parsed", m.parsed));
            archive(::cereal::make_nvp("raw", m_raw));
        m.raw = m_raw;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pdoq_oq_ifc_mapping_result_t_anonymous_union_txpp_map_data_t& m)
{
    serializer_class<npl_pdoq_oq_ifc_mapping_result_t_anonymous_union_txpp_map_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pdoq_oq_ifc_mapping_result_t_anonymous_union_txpp_map_data_t&);

template <class Archive>
void
load(Archive& archive, npl_pdoq_oq_ifc_mapping_result_t_anonymous_union_txpp_map_data_t& m)
{
    serializer_class<npl_pdoq_oq_ifc_mapping_result_t_anonymous_union_txpp_map_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pdoq_oq_ifc_mapping_result_t_anonymous_union_txpp_map_data_t&);



template<>
class serializer_class<npl_pdvoq_bank_pair_offset_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pdvoq_bank_pair_offset_t& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pdvoq_bank_pair_offset_t& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pdvoq_bank_pair_offset_t& m)
{
    serializer_class<npl_pdvoq_bank_pair_offset_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pdvoq_bank_pair_offset_t&);

template <class Archive>
void
load(Archive& archive, npl_pdvoq_bank_pair_offset_t& m)
{
    serializer_class<npl_pdvoq_bank_pair_offset_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pdvoq_bank_pair_offset_t&);



template<>
class serializer_class<npl_per_rtf_step_og_pcl_compress_bits_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_per_rtf_step_og_pcl_compress_bits_t& m) {
            archive(::cereal::make_nvp("ipv4_compress_bits", m.ipv4_compress_bits));
            archive(::cereal::make_nvp("ipv6_compress_bits", m.ipv6_compress_bits));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_per_rtf_step_og_pcl_compress_bits_t& m) {
            archive(::cereal::make_nvp("ipv4_compress_bits", m.ipv4_compress_bits));
            archive(::cereal::make_nvp("ipv6_compress_bits", m.ipv6_compress_bits));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_per_rtf_step_og_pcl_compress_bits_t& m)
{
    serializer_class<npl_per_rtf_step_og_pcl_compress_bits_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_per_rtf_step_og_pcl_compress_bits_t&);

template <class Archive>
void
load(Archive& archive, npl_per_rtf_step_og_pcl_compress_bits_t& m)
{
    serializer_class<npl_per_rtf_step_og_pcl_compress_bits_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_per_rtf_step_og_pcl_compress_bits_t&);



template<>
class serializer_class<npl_per_rtf_step_og_pcl_ids_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_per_rtf_step_og_pcl_ids_t& m) {
            archive(::cereal::make_nvp("ipv4_og_pcl_ids", m.ipv4_og_pcl_ids));
            archive(::cereal::make_nvp("ipv6_og_pcl_ids", m.ipv6_og_pcl_ids));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_per_rtf_step_og_pcl_ids_t& m) {
            archive(::cereal::make_nvp("ipv4_og_pcl_ids", m.ipv4_og_pcl_ids));
            archive(::cereal::make_nvp("ipv6_og_pcl_ids", m.ipv6_og_pcl_ids));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_per_rtf_step_og_pcl_ids_t& m)
{
    serializer_class<npl_per_rtf_step_og_pcl_ids_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_per_rtf_step_og_pcl_ids_t&);

template <class Archive>
void
load(Archive& archive, npl_per_rtf_step_og_pcl_ids_t& m)
{
    serializer_class<npl_per_rtf_step_og_pcl_ids_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_per_rtf_step_og_pcl_ids_t&);



template<>
class serializer_class<npl_pfc_aux_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_aux_payload_t& m) {
            archive(::cereal::make_nvp("rx_counter", m.rx_counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_aux_payload_t& m) {
            archive(::cereal::make_nvp("rx_counter", m.rx_counter));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_aux_payload_t& m)
{
    serializer_class<npl_pfc_aux_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_aux_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_aux_payload_t& m)
{
    serializer_class<npl_pfc_aux_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_aux_payload_t&);



template<>
class serializer_class<npl_pfc_em_lookup_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_em_lookup_t& m) {
        uint64_t m_destination = m.destination;
        uint64_t m_some_padding = m.some_padding;
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("some_padding", m_some_padding));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_em_lookup_t& m) {
        uint64_t m_destination;
        uint64_t m_some_padding;
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("some_padding", m_some_padding));
        m.destination = m_destination;
        m.some_padding = m_some_padding;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_em_lookup_t& m)
{
    serializer_class<npl_pfc_em_lookup_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_em_lookup_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_em_lookup_t& m)
{
    serializer_class<npl_pfc_em_lookup_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_em_lookup_t&);



template<>
class serializer_class<npl_pfc_em_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_em_t& m) {
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
    do_load(Archive& archive, npl_pfc_em_t& m) {
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
save(Archive& archive, const npl_pfc_em_t& m)
{
    serializer_class<npl_pfc_em_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_em_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_em_t& m)
{
    serializer_class<npl_pfc_em_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_em_t&);



template<>
class serializer_class<npl_pfc_rx_counter_offset_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_rx_counter_offset_t& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_rx_counter_offset_t& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_rx_counter_offset_t& m)
{
    serializer_class<npl_pfc_rx_counter_offset_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_rx_counter_offset_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_rx_counter_offset_t& m)
{
    serializer_class<npl_pfc_rx_counter_offset_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_rx_counter_offset_t&);



template<>
class serializer_class<npl_pfc_ssp_info_table_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_ssp_info_table_t& m) {
        uint64_t m_slice = m.slice;
        uint64_t m_mp_id = m.mp_id;
            archive(::cereal::make_nvp("slice", m_slice));
            archive(::cereal::make_nvp("mp_id", m_mp_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_ssp_info_table_t& m) {
        uint64_t m_slice;
        uint64_t m_mp_id;
            archive(::cereal::make_nvp("slice", m_slice));
            archive(::cereal::make_nvp("mp_id", m_mp_id));
        m.slice = m_slice;
        m.mp_id = m_mp_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_ssp_info_table_t& m)
{
    serializer_class<npl_pfc_ssp_info_table_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_ssp_info_table_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_ssp_info_table_t& m)
{
    serializer_class<npl_pfc_ssp_info_table_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_ssp_info_table_t&);



template<>
class serializer_class<npl_phb_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_phb_t& m) {
        uint64_t m_tc = m.tc;
        uint64_t m_dp = m.dp;
            archive(::cereal::make_nvp("tc", m_tc));
            archive(::cereal::make_nvp("dp", m_dp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_phb_t& m) {
        uint64_t m_tc;
        uint64_t m_dp;
            archive(::cereal::make_nvp("tc", m_tc));
            archive(::cereal::make_nvp("dp", m_dp));
        m.tc = m_tc;
        m.dp = m_dp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_phb_t& m)
{
    serializer_class<npl_phb_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_phb_t&);

template <class Archive>
void
load(Archive& archive, npl_phb_t& m)
{
    serializer_class<npl_phb_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_phb_t&);



template<>
class serializer_class<npl_pif_ifg_base_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pif_ifg_base_t& m) {
        uint64_t m_pif = m.pif;
        uint64_t m_ifg = m.ifg;
            archive(::cereal::make_nvp("pif", m_pif));
            archive(::cereal::make_nvp("ifg", m_ifg));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pif_ifg_base_t& m) {
        uint64_t m_pif;
        uint64_t m_ifg;
            archive(::cereal::make_nvp("pif", m_pif));
            archive(::cereal::make_nvp("ifg", m_ifg));
        m.pif = m_pif;
        m.ifg = m_ifg;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pif_ifg_base_t& m)
{
    serializer_class<npl_pif_ifg_base_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pif_ifg_base_t&);

template <class Archive>
void
load(Archive& archive, npl_pif_ifg_base_t& m)
{
    serializer_class<npl_pif_ifg_base_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pif_ifg_base_t&);



template<>
class serializer_class<npl_pma_loopback_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pma_loopback_data_t& m) {
            archive(::cereal::make_nvp("mode", m.mode));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pma_loopback_data_t& m) {
            archive(::cereal::make_nvp("mode", m.mode));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pma_loopback_data_t& m)
{
    serializer_class<npl_pma_loopback_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pma_loopback_data_t&);

template <class Archive>
void
load(Archive& archive, npl_pma_loopback_data_t& m)
{
    serializer_class<npl_pma_loopback_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pma_loopback_data_t&);



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



}

