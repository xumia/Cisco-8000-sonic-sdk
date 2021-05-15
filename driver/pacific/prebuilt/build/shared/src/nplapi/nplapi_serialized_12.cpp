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

template <class Archive> void save(Archive&, const npl_bfd_mp_table_transmit_b_payload_t&);
template <class Archive> void load(Archive&, npl_bfd_mp_table_transmit_b_payload_t&);

template <class Archive> void save(Archive&, const npl_bool_t&);
template <class Archive> void load(Archive&, npl_bool_t&);

template <class Archive> void save(Archive&, const npl_counter_ptr_t&);
template <class Archive> void load(Archive&, npl_counter_ptr_t&);

template <class Archive> void save(Archive&, const npl_destination_t&);
template <class Archive> void load(Archive&, npl_destination_t&);

template <class Archive> void save(Archive&, const npl_ene_macro_id_t&);
template <class Archive> void load(Archive&, npl_ene_macro_id_t&);

template <class Archive> void save(Archive&, const npl_eth_mp_table_transmit_b_payload_t&);
template <class Archive> void load(Archive&, npl_eth_mp_table_transmit_b_payload_t&);

template <class Archive> void save(Archive&, const npl_hw_mp_table_app_t&);
template <class Archive> void load(Archive&, npl_hw_mp_table_app_t&);

template <class Archive> void save(Archive&, const npl_is_inject_up_and_ip_first_fragment_t&);
template <class Archive> void load(Archive&, npl_is_inject_up_and_ip_first_fragment_t&);

template <class Archive> void save(Archive&, const npl_l2_dlp_t&);
template <class Archive> void load(Archive&, npl_l2_dlp_t&);

template <class Archive> void save(Archive&, const npl_lp_attr_update_raw_bits_t&);
template <class Archive> void load(Archive&, npl_lp_attr_update_raw_bits_t&);

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
            archive(::cereal::make_nvp("q_m_counter_ptr", m.q_m_counter_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_macro_compressed_fields_t& m) {
        uint64_t m_is_inject_up;
        uint64_t m_not_comp_single_src;
            archive(::cereal::make_nvp("is_inject_up", m_is_inject_up));
            archive(::cereal::make_nvp("not_comp_single_src", m_not_comp_single_src));
            archive(::cereal::make_nvp("curr_proto_type", m.curr_proto_type));
            archive(::cereal::make_nvp("q_m_counter_ptr", m.q_m_counter_ptr));
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
class serializer_class<npl_mtu_and_pkt_size_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mtu_and_pkt_size_t& m) {
        uint64_t m_muxed_pad_constant = m.muxed_pad_constant;
        uint64_t m_dsp_mtu = m.dsp_mtu;
        uint64_t m_pd_pkt_size = m.pd_pkt_size;
            archive(::cereal::make_nvp("muxed_pad_constant", m_muxed_pad_constant));
            archive(::cereal::make_nvp("dsp_mtu", m_dsp_mtu));
            archive(::cereal::make_nvp("pd_pkt_size", m_pd_pkt_size));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mtu_and_pkt_size_t& m) {
        uint64_t m_muxed_pad_constant;
        uint64_t m_dsp_mtu;
        uint64_t m_pd_pkt_size;
            archive(::cereal::make_nvp("muxed_pad_constant", m_muxed_pad_constant));
            archive(::cereal::make_nvp("dsp_mtu", m_dsp_mtu));
            archive(::cereal::make_nvp("pd_pkt_size", m_pd_pkt_size));
        m.muxed_pad_constant = m_muxed_pad_constant;
        m.dsp_mtu = m_dsp_mtu;
        m.pd_pkt_size = m_pd_pkt_size;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mtu_and_pkt_size_t& m)
{
    serializer_class<npl_mtu_and_pkt_size_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mtu_and_pkt_size_t&);

template <class Archive>
void
load(Archive& archive, npl_mtu_and_pkt_size_t& m)
{
    serializer_class<npl_mtu_and_pkt_size_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mtu_and_pkt_size_t&);



template<>
class serializer_class<npl_native_fec_destination1_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_fec_destination1_t& m) {
        uint64_t m_enc_type = m.enc_type;
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_fec_destination1_t& m) {
        uint64_t m_enc_type;
        uint64_t m_destination;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
        m.enc_type = m_enc_type;
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_fec_destination1_t& m)
{
    serializer_class<npl_native_fec_destination1_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_fec_destination1_t&);

template <class Archive>
void
load(Archive& archive, npl_native_fec_destination1_t& m)
{
    serializer_class<npl_native_fec_destination1_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_fec_destination1_t&);



template<>
class serializer_class<npl_native_fec_destination_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_fec_destination_t& m) {
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_fec_destination_t& m) {
        uint64_t m_destination;
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_fec_destination_t& m)
{
    serializer_class<npl_native_fec_destination_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_fec_destination_t&);

template <class Archive>
void
load(Archive& archive, npl_native_fec_destination_t& m)
{
    serializer_class<npl_native_fec_destination_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_fec_destination_t&);



template<>
class serializer_class<npl_native_fec_raw_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_fec_raw_t& m) {
        uint64_t m_payload = m.payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_fec_raw_t& m) {
        uint64_t m_payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
        m.payload = m_payload;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_fec_raw_t& m)
{
    serializer_class<npl_native_fec_raw_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_fec_raw_t&);

template <class Archive>
void
load(Archive& archive, npl_native_fec_raw_t& m)
{
    serializer_class<npl_native_fec_raw_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_fec_raw_t&);



template<>
class serializer_class<npl_native_fec_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_fec_table_result_t& m) {
            archive(::cereal::make_nvp("destination", m.destination));
            archive(::cereal::make_nvp("destination1", m.destination1));
            archive(::cereal::make_nvp("raw", m.raw));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_fec_table_result_t& m) {
            archive(::cereal::make_nvp("destination", m.destination));
            archive(::cereal::make_nvp("destination1", m.destination1));
            archive(::cereal::make_nvp("raw", m.raw));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_fec_table_result_t& m)
{
    serializer_class<npl_native_fec_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_fec_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_native_fec_table_result_t& m)
{
    serializer_class<npl_native_fec_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_fec_table_result_t&);



template<>
class serializer_class<npl_native_frr_destination_frr_protection_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_frr_destination_frr_protection_t& m) {
        uint64_t m_frr_protection = m.frr_protection;
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("frr_protection", m_frr_protection));
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_frr_destination_frr_protection_t& m) {
        uint64_t m_frr_protection;
        uint64_t m_destination;
            archive(::cereal::make_nvp("frr_protection", m_frr_protection));
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
        m.frr_protection = m_frr_protection;
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_frr_destination_frr_protection_t& m)
{
    serializer_class<npl_native_frr_destination_frr_protection_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_frr_destination_frr_protection_t&);

template <class Archive>
void
load(Archive& archive, npl_native_frr_destination_frr_protection_t& m)
{
    serializer_class<npl_native_frr_destination_frr_protection_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_frr_destination_frr_protection_t&);



template<>
class serializer_class<npl_native_frr_protected_raw_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_frr_protected_raw_t& m) {
        uint64_t m_payload = m.payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_frr_protected_raw_t& m) {
        uint64_t m_payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
        m.payload = m_payload;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_frr_protected_raw_t& m)
{
    serializer_class<npl_native_frr_protected_raw_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_frr_protected_raw_t&);

template <class Archive>
void
load(Archive& archive, npl_native_frr_protected_raw_t& m)
{
    serializer_class<npl_native_frr_protected_raw_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_frr_protected_raw_t&);



template<>
class serializer_class<npl_native_frr_table_protection_entry_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_frr_table_protection_entry_t& m) {
            archive(::cereal::make_nvp("destination_frr_protection", m.destination_frr_protection));
            archive(::cereal::make_nvp("raw", m.raw));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_frr_table_protection_entry_t& m) {
            archive(::cereal::make_nvp("destination_frr_protection", m.destination_frr_protection));
            archive(::cereal::make_nvp("raw", m.raw));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_frr_table_protection_entry_t& m)
{
    serializer_class<npl_native_frr_table_protection_entry_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_frr_table_protection_entry_t&);

template <class Archive>
void
load(Archive& archive, npl_native_frr_table_protection_entry_t& m)
{
    serializer_class<npl_native_frr_table_protection_entry_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_frr_table_protection_entry_t&);



template<>
class serializer_class<npl_native_l2_lp_bvn_l2_dlp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_l2_lp_bvn_l2_dlp_t& m) {
        uint64_t m_l2_dlp = m.l2_dlp;
        uint64_t m_bvn = m.bvn;
            archive(::cereal::make_nvp("l2_dlp", m_l2_dlp));
            archive(::cereal::make_nvp("bvn", m_bvn));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_l2_lp_bvn_l2_dlp_t& m) {
        uint64_t m_l2_dlp;
        uint64_t m_bvn;
            archive(::cereal::make_nvp("l2_dlp", m_l2_dlp));
            archive(::cereal::make_nvp("bvn", m_bvn));
            archive(::cereal::make_nvp("type", m.type));
        m.l2_dlp = m_l2_dlp;
        m.bvn = m_bvn;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_l2_lp_bvn_l2_dlp_t& m)
{
    serializer_class<npl_native_l2_lp_bvn_l2_dlp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_l2_lp_bvn_l2_dlp_t&);

template <class Archive>
void
load(Archive& archive, npl_native_l2_lp_bvn_l2_dlp_t& m)
{
    serializer_class<npl_native_l2_lp_bvn_l2_dlp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_l2_lp_bvn_l2_dlp_t&);



template<>
class serializer_class<npl_native_l2_lp_destination1_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_l2_lp_destination1_t& m) {
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_l2_lp_destination1_t& m) {
        uint64_t m_destination;
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_l2_lp_destination1_t& m)
{
    serializer_class<npl_native_l2_lp_destination1_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_l2_lp_destination1_t&);

template <class Archive>
void
load(Archive& archive, npl_native_l2_lp_destination1_t& m)
{
    serializer_class<npl_native_l2_lp_destination1_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_l2_lp_destination1_t&);



template<>
class serializer_class<npl_native_l2_lp_destination2_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_l2_lp_destination2_t& m) {
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_l2_lp_destination2_t& m) {
        uint64_t m_destination;
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_l2_lp_destination2_t& m)
{
    serializer_class<npl_native_l2_lp_destination2_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_l2_lp_destination2_t&);

template <class Archive>
void
load(Archive& archive, npl_native_l2_lp_destination2_t& m)
{
    serializer_class<npl_native_l2_lp_destination2_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_l2_lp_destination2_t&);



template<>
class serializer_class<npl_native_l2_lp_destination_ip_tunnel_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_l2_lp_destination_ip_tunnel_t& m) {
        uint64_t m_enc_type = m.enc_type;
        uint64_t m_ip_tunnel = m.ip_tunnel;
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("ip_tunnel", m_ip_tunnel));
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_l2_lp_destination_ip_tunnel_t& m) {
        uint64_t m_enc_type;
        uint64_t m_ip_tunnel;
        uint64_t m_destination;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("ip_tunnel", m_ip_tunnel));
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
        m.enc_type = m_enc_type;
        m.ip_tunnel = m_ip_tunnel;
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_l2_lp_destination_ip_tunnel_t& m)
{
    serializer_class<npl_native_l2_lp_destination_ip_tunnel_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_l2_lp_destination_ip_tunnel_t&);

template <class Archive>
void
load(Archive& archive, npl_native_l2_lp_destination_ip_tunnel_t& m)
{
    serializer_class<npl_native_l2_lp_destination_ip_tunnel_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_l2_lp_destination_ip_tunnel_t&);



template<>
class serializer_class<npl_native_l2_lp_destination_overlay_nh_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_l2_lp_destination_overlay_nh_t& m) {
        uint64_t m_enc_type = m.enc_type;
        uint64_t m_overlay_nh = m.overlay_nh;
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("overlay_nh", m_overlay_nh));
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_l2_lp_destination_overlay_nh_t& m) {
        uint64_t m_enc_type;
        uint64_t m_overlay_nh;
        uint64_t m_destination;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("overlay_nh", m_overlay_nh));
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
        m.enc_type = m_enc_type;
        m.overlay_nh = m_overlay_nh;
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_l2_lp_destination_overlay_nh_t& m)
{
    serializer_class<npl_native_l2_lp_destination_overlay_nh_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_l2_lp_destination_overlay_nh_t&);

template <class Archive>
void
load(Archive& archive, npl_native_l2_lp_destination_overlay_nh_t& m)
{
    serializer_class<npl_native_l2_lp_destination_overlay_nh_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_l2_lp_destination_overlay_nh_t&);



template<>
class serializer_class<npl_native_l2_lp_destination_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_l2_lp_destination_t& m) {
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_l2_lp_destination_t& m) {
        uint64_t m_destination;
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_l2_lp_destination_t& m)
{
    serializer_class<npl_native_l2_lp_destination_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_l2_lp_destination_t&);

template <class Archive>
void
load(Archive& archive, npl_native_l2_lp_destination_t& m)
{
    serializer_class<npl_native_l2_lp_destination_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_l2_lp_destination_t&);



template<>
class serializer_class<npl_native_l2_lp_destination_te_tunnel16b_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_l2_lp_destination_te_tunnel16b_t& m) {
        uint64_t m_enc_type = m.enc_type;
        uint64_t m_te_tunnel16b = m.te_tunnel16b;
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("te_tunnel16b", m_te_tunnel16b));
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_l2_lp_destination_te_tunnel16b_t& m) {
        uint64_t m_enc_type;
        uint64_t m_te_tunnel16b;
        uint64_t m_destination;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("te_tunnel16b", m_te_tunnel16b));
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
        m.enc_type = m_enc_type;
        m.te_tunnel16b = m_te_tunnel16b;
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_l2_lp_destination_te_tunnel16b_t& m)
{
    serializer_class<npl_native_l2_lp_destination_te_tunnel16b_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_l2_lp_destination_te_tunnel16b_t&);

template <class Archive>
void
load(Archive& archive, npl_native_l2_lp_destination_te_tunnel16b_t& m)
{
    serializer_class<npl_native_l2_lp_destination_te_tunnel16b_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_l2_lp_destination_te_tunnel16b_t&);



template<>
class serializer_class<npl_native_l2_lp_dsp_l2_dlp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_l2_lp_dsp_l2_dlp_t& m) {
        uint64_t m_enc_type = m.enc_type;
        uint64_t m_l2_dlp = m.l2_dlp;
        uint64_t m_dsp = m.dsp;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("l2_dlp", m_l2_dlp));
            archive(::cereal::make_nvp("dsp", m_dsp));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_l2_lp_dsp_l2_dlp_t& m) {
        uint64_t m_enc_type;
        uint64_t m_l2_dlp;
        uint64_t m_dsp;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("l2_dlp", m_l2_dlp));
            archive(::cereal::make_nvp("dsp", m_dsp));
            archive(::cereal::make_nvp("type", m.type));
        m.enc_type = m_enc_type;
        m.l2_dlp = m_l2_dlp;
        m.dsp = m_dsp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_l2_lp_dsp_l2_dlp_t& m)
{
    serializer_class<npl_native_l2_lp_dsp_l2_dlp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_l2_lp_dsp_l2_dlp_t&);

template <class Archive>
void
load(Archive& archive, npl_native_l2_lp_dsp_l2_dlp_t& m)
{
    serializer_class<npl_native_l2_lp_dsp_l2_dlp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_l2_lp_dsp_l2_dlp_t&);



template<>
class serializer_class<npl_native_l2_lp_dspa_l2_dlp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_l2_lp_dspa_l2_dlp_t& m) {
        uint64_t m_enc_type = m.enc_type;
        uint64_t m_l2_dlp = m.l2_dlp;
        uint64_t m_dspa = m.dspa;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("l2_dlp", m_l2_dlp));
            archive(::cereal::make_nvp("dspa", m_dspa));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_l2_lp_dspa_l2_dlp_t& m) {
        uint64_t m_enc_type;
        uint64_t m_l2_dlp;
        uint64_t m_dspa;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("l2_dlp", m_l2_dlp));
            archive(::cereal::make_nvp("dspa", m_dspa));
            archive(::cereal::make_nvp("type", m.type));
        m.enc_type = m_enc_type;
        m.l2_dlp = m_l2_dlp;
        m.dspa = m_dspa;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_l2_lp_dspa_l2_dlp_t& m)
{
    serializer_class<npl_native_l2_lp_dspa_l2_dlp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_l2_lp_dspa_l2_dlp_t&);

template <class Archive>
void
load(Archive& archive, npl_native_l2_lp_dspa_l2_dlp_t& m)
{
    serializer_class<npl_native_l2_lp_dspa_l2_dlp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_l2_lp_dspa_l2_dlp_t&);



template<>
class serializer_class<npl_native_l2_lp_narrow_raw_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_l2_lp_narrow_raw_t& m) {
        uint64_t m_payload = m.payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_l2_lp_narrow_raw_t& m) {
        uint64_t m_payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
        m.payload = m_payload;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_l2_lp_narrow_raw_t& m)
{
    serializer_class<npl_native_l2_lp_narrow_raw_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_l2_lp_narrow_raw_t&);

template <class Archive>
void
load(Archive& archive, npl_native_l2_lp_narrow_raw_t& m)
{
    serializer_class<npl_native_l2_lp_narrow_raw_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_l2_lp_narrow_raw_t&);



template<>
class serializer_class<npl_native_l2_lp_protected_raw_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_l2_lp_protected_raw_t& m) {
        uint64_t m_payload = m.payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_l2_lp_protected_raw_t& m) {
        uint64_t m_payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
        m.payload = m_payload;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_l2_lp_protected_raw_t& m)
{
    serializer_class<npl_native_l2_lp_protected_raw_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_l2_lp_protected_raw_t&);

template <class Archive>
void
load(Archive& archive, npl_native_l2_lp_protected_raw_t& m)
{
    serializer_class<npl_native_l2_lp_protected_raw_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_l2_lp_protected_raw_t&);



template<>
class serializer_class<npl_native_l2_lp_stage2_ecmp_ce_ptr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_l2_lp_stage2_ecmp_ce_ptr_t& m) {
        uint64_t m_ce_ptr = m.ce_ptr;
        uint64_t m_stage2_ecmp = m.stage2_ecmp;
            archive(::cereal::make_nvp("ce_ptr", m_ce_ptr));
            archive(::cereal::make_nvp("stage2_ecmp", m_stage2_ecmp));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_l2_lp_stage2_ecmp_ce_ptr_t& m) {
        uint64_t m_ce_ptr;
        uint64_t m_stage2_ecmp;
            archive(::cereal::make_nvp("ce_ptr", m_ce_ptr));
            archive(::cereal::make_nvp("stage2_ecmp", m_stage2_ecmp));
            archive(::cereal::make_nvp("type", m.type));
        m.ce_ptr = m_ce_ptr;
        m.stage2_ecmp = m_stage2_ecmp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_l2_lp_stage2_ecmp_ce_ptr_t& m)
{
    serializer_class<npl_native_l2_lp_stage2_ecmp_ce_ptr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_l2_lp_stage2_ecmp_ce_ptr_t&);

template <class Archive>
void
load(Archive& archive, npl_native_l2_lp_stage2_ecmp_ce_ptr_t& m)
{
    serializer_class<npl_native_l2_lp_stage2_ecmp_ce_ptr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_l2_lp_stage2_ecmp_ce_ptr_t&);



template<>
class serializer_class<npl_native_l2_lp_stage2_ecmp_vpn_inter_as_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_l2_lp_stage2_ecmp_vpn_inter_as_t& m) {
        uint64_t m_vpn_inter_as = m.vpn_inter_as;
        uint64_t m_stage2_ecmp = m.stage2_ecmp;
            archive(::cereal::make_nvp("vpn_inter_as", m_vpn_inter_as));
            archive(::cereal::make_nvp("stage2_ecmp", m_stage2_ecmp));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_l2_lp_stage2_ecmp_vpn_inter_as_t& m) {
        uint64_t m_vpn_inter_as;
        uint64_t m_stage2_ecmp;
            archive(::cereal::make_nvp("vpn_inter_as", m_vpn_inter_as));
            archive(::cereal::make_nvp("stage2_ecmp", m_stage2_ecmp));
            archive(::cereal::make_nvp("type", m.type));
        m.vpn_inter_as = m_vpn_inter_as;
        m.stage2_ecmp = m_stage2_ecmp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_l2_lp_stage2_ecmp_vpn_inter_as_t& m)
{
    serializer_class<npl_native_l2_lp_stage2_ecmp_vpn_inter_as_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_l2_lp_stage2_ecmp_vpn_inter_as_t&);

template <class Archive>
void
load(Archive& archive, npl_native_l2_lp_stage2_ecmp_vpn_inter_as_t& m)
{
    serializer_class<npl_native_l2_lp_stage2_ecmp_vpn_inter_as_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_l2_lp_stage2_ecmp_vpn_inter_as_t&);



template<>
class serializer_class<npl_native_l2_lp_stage2_p_nh_ce_ptr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_l2_lp_stage2_p_nh_ce_ptr_t& m) {
        uint64_t m_enc_type = m.enc_type;
        uint64_t m_ce_ptr = m.ce_ptr;
        uint64_t m_stage2_p_nh = m.stage2_p_nh;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("ce_ptr", m_ce_ptr));
            archive(::cereal::make_nvp("stage2_p_nh", m_stage2_p_nh));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_l2_lp_stage2_p_nh_ce_ptr_t& m) {
        uint64_t m_enc_type;
        uint64_t m_ce_ptr;
        uint64_t m_stage2_p_nh;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("ce_ptr", m_ce_ptr));
            archive(::cereal::make_nvp("stage2_p_nh", m_stage2_p_nh));
            archive(::cereal::make_nvp("type", m.type));
        m.enc_type = m_enc_type;
        m.ce_ptr = m_ce_ptr;
        m.stage2_p_nh = m_stage2_p_nh;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_l2_lp_stage2_p_nh_ce_ptr_t& m)
{
    serializer_class<npl_native_l2_lp_stage2_p_nh_ce_ptr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_l2_lp_stage2_p_nh_ce_ptr_t&);

template <class Archive>
void
load(Archive& archive, npl_native_l2_lp_stage2_p_nh_ce_ptr_t& m)
{
    serializer_class<npl_native_l2_lp_stage2_p_nh_ce_ptr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_l2_lp_stage2_p_nh_ce_ptr_t&);



template<>
class serializer_class<npl_native_l2_lp_stage3_nh_ce_ptr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_l2_lp_stage3_nh_ce_ptr_t& m) {
        uint64_t m_enc_type = m.enc_type;
        uint64_t m_ce_ptr = m.ce_ptr;
        uint64_t m_stage3_nh = m.stage3_nh;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("ce_ptr", m_ce_ptr));
            archive(::cereal::make_nvp("stage3_nh", m_stage3_nh));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_l2_lp_stage3_nh_ce_ptr_t& m) {
        uint64_t m_enc_type;
        uint64_t m_ce_ptr;
        uint64_t m_stage3_nh;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("ce_ptr", m_ce_ptr));
            archive(::cereal::make_nvp("stage3_nh", m_stage3_nh));
            archive(::cereal::make_nvp("type", m.type));
        m.enc_type = m_enc_type;
        m.ce_ptr = m_ce_ptr;
        m.stage3_nh = m_stage3_nh;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_l2_lp_stage3_nh_ce_ptr_t& m)
{
    serializer_class<npl_native_l2_lp_stage3_nh_ce_ptr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_l2_lp_stage3_nh_ce_ptr_t&);

template <class Archive>
void
load(Archive& archive, npl_native_l2_lp_stage3_nh_ce_ptr_t& m)
{
    serializer_class<npl_native_l2_lp_stage3_nh_ce_ptr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_l2_lp_stage3_nh_ce_ptr_t&);



template<>
class serializer_class<npl_native_l2_lp_table_protection_entry_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_l2_lp_table_protection_entry_t& m) {
            archive(::cereal::make_nvp("dsp_l2_dlp", m.dsp_l2_dlp));
            archive(::cereal::make_nvp("dspa_l2_dlp", m.dspa_l2_dlp));
            archive(::cereal::make_nvp("bvn_l2_dlp", m.bvn_l2_dlp));
            archive(::cereal::make_nvp("raw", m.raw));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_l2_lp_table_protection_entry_t& m) {
            archive(::cereal::make_nvp("dsp_l2_dlp", m.dsp_l2_dlp));
            archive(::cereal::make_nvp("dspa_l2_dlp", m.dspa_l2_dlp));
            archive(::cereal::make_nvp("bvn_l2_dlp", m.bvn_l2_dlp));
            archive(::cereal::make_nvp("raw", m.raw));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_l2_lp_table_protection_entry_t& m)
{
    serializer_class<npl_native_l2_lp_table_protection_entry_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_l2_lp_table_protection_entry_t&);

template <class Archive>
void
load(Archive& archive, npl_native_l2_lp_table_protection_entry_t& m)
{
    serializer_class<npl_native_l2_lp_table_protection_entry_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_l2_lp_table_protection_entry_t&);



template<>
class serializer_class<npl_native_l2_lp_table_result_narrow_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_l2_lp_table_result_narrow_t& m) {
            archive(::cereal::make_nvp("destination", m.destination));
            archive(::cereal::make_nvp("destination1", m.destination1));
            archive(::cereal::make_nvp("destination2", m.destination2));
            archive(::cereal::make_nvp("stage2_ecmp_vpn_inter_as", m.stage2_ecmp_vpn_inter_as));
            archive(::cereal::make_nvp("raw", m.raw));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_l2_lp_table_result_narrow_t& m) {
            archive(::cereal::make_nvp("destination", m.destination));
            archive(::cereal::make_nvp("destination1", m.destination1));
            archive(::cereal::make_nvp("destination2", m.destination2));
            archive(::cereal::make_nvp("stage2_ecmp_vpn_inter_as", m.stage2_ecmp_vpn_inter_as));
            archive(::cereal::make_nvp("raw", m.raw));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_l2_lp_table_result_narrow_t& m)
{
    serializer_class<npl_native_l2_lp_table_result_narrow_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_l2_lp_table_result_narrow_t&);

template <class Archive>
void
load(Archive& archive, npl_native_l2_lp_table_result_narrow_t& m)
{
    serializer_class<npl_native_l2_lp_table_result_narrow_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_l2_lp_table_result_narrow_t&);



template<>
class serializer_class<npl_native_l2_lp_wide_raw_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_l2_lp_wide_raw_t& m) {
        uint64_t m_payload = m.payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_l2_lp_wide_raw_t& m) {
        uint64_t m_payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
        m.payload = m_payload;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_l2_lp_wide_raw_t& m)
{
    serializer_class<npl_native_l2_lp_wide_raw_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_l2_lp_wide_raw_t&);

template <class Archive>
void
load(Archive& archive, npl_native_l2_lp_wide_raw_t& m)
{
    serializer_class<npl_native_l2_lp_wide_raw_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_l2_lp_wide_raw_t&);



template<>
class serializer_class<npl_native_lb_destination1_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_lb_destination1_t& m) {
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_lb_destination1_t& m) {
        uint64_t m_destination;
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_lb_destination1_t& m)
{
    serializer_class<npl_native_lb_destination1_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_lb_destination1_t&);

template <class Archive>
void
load(Archive& archive, npl_native_lb_destination1_t& m)
{
    serializer_class<npl_native_lb_destination1_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_lb_destination1_t&);



template<>
class serializer_class<npl_native_lb_destination2_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_lb_destination2_t& m) {
        uint64_t m_enc_type = m.enc_type;
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_lb_destination2_t& m) {
        uint64_t m_enc_type;
        uint64_t m_destination;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
        m.enc_type = m_enc_type;
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_lb_destination2_t& m)
{
    serializer_class<npl_native_lb_destination2_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_lb_destination2_t&);

template <class Archive>
void
load(Archive& archive, npl_native_lb_destination2_t& m)
{
    serializer_class<npl_native_lb_destination2_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_lb_destination2_t&);



template<>
class serializer_class<npl_native_lb_destination_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_lb_destination_t& m) {
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_lb_destination_t& m) {
        uint64_t m_destination;
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_lb_destination_t& m)
{
    serializer_class<npl_native_lb_destination_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_lb_destination_t&);

template <class Archive>
void
load(Archive& archive, npl_native_lb_destination_t& m)
{
    serializer_class<npl_native_lb_destination_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_lb_destination_t&);



template<>
class serializer_class<npl_native_lb_raw_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_lb_raw_t& m) {
        uint64_t m_payload = m.payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_lb_raw_t& m) {
        uint64_t m_payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
        m.payload = m_payload;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_lb_raw_t& m)
{
    serializer_class<npl_native_lb_raw_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_lb_raw_t&);

template <class Archive>
void
load(Archive& archive, npl_native_lb_raw_t& m)
{
    serializer_class<npl_native_lb_raw_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_lb_raw_t&);



template<>
class serializer_class<npl_native_lb_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_lb_table_result_t& m) {
            archive(::cereal::make_nvp("destination", m.destination));
            archive(::cereal::make_nvp("destination1", m.destination1));
            archive(::cereal::make_nvp("destination2", m.destination2));
            archive(::cereal::make_nvp("raw", m.raw));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_lb_table_result_t& m) {
            archive(::cereal::make_nvp("destination", m.destination));
            archive(::cereal::make_nvp("destination1", m.destination1));
            archive(::cereal::make_nvp("destination2", m.destination2));
            archive(::cereal::make_nvp("raw", m.raw));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_lb_table_result_t& m)
{
    serializer_class<npl_native_lb_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_lb_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_native_lb_table_result_t& m)
{
    serializer_class<npl_native_lb_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_lb_table_result_t&);



template<>
class serializer_class<npl_native_protection_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_protection_id_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_protection_id_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_protection_id_t& m)
{
    serializer_class<npl_native_protection_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_protection_id_t&);

template <class Archive>
void
load(Archive& archive, npl_native_protection_id_t& m)
{
    serializer_class<npl_native_protection_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_protection_id_t&);



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
class serializer_class<npl_no_acls_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_no_acls_t& m) {
        uint64_t m_no_acls = m.no_acls;
            archive(::cereal::make_nvp("no_acls", m_no_acls));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_no_acls_t& m) {
        uint64_t m_no_acls;
            archive(::cereal::make_nvp("no_acls", m_no_acls));
        m.no_acls = m_no_acls;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_no_acls_t& m)
{
    serializer_class<npl_no_acls_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_no_acls_t&);

template <class Archive>
void
load(Archive& archive, npl_no_acls_t& m)
{
    serializer_class<npl_no_acls_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_no_acls_t&);



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
class serializer_class<npl_npp_protection_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npp_protection_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npp_protection_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npp_protection_t& m)
{
    serializer_class<npl_npp_protection_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npp_protection_t&);

template <class Archive>
void
load(Archive& archive, npl_npp_protection_t& m)
{
    serializer_class<npl_npp_protection_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npp_protection_t&);



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
        uint64_t m_pad = m.pad;
        uint64_t m_bits_17_0 = m.bits_17_0;
            archive(::cereal::make_nvp("bits_n_18", m_bits_n_18));
            archive(::cereal::make_nvp("pad", m_pad));
            archive(::cereal::make_nvp("bits_17_0", m_bits_17_0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_og_pd_compression_code_t& m) {
        uint64_t m_bits_n_18;
        uint64_t m_pad;
        uint64_t m_bits_17_0;
            archive(::cereal::make_nvp("bits_n_18", m_bits_n_18));
            archive(::cereal::make_nvp("pad", m_pad));
            archive(::cereal::make_nvp("bits_17_0", m_bits_17_0));
        m.bits_n_18 = m_bits_n_18;
        m.pad = m_pad;
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
            archive(::cereal::make_nvp("key_part1", m.key_part1));
            archive(::cereal::make_nvp("key_part0", m.key_part0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_packed_ud_320_key_t& m) {
            archive(::cereal::make_nvp("key_part1", m.key_part1));
            archive(::cereal::make_nvp("key_part0", m.key_part0));
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
class serializer_class<npl_path_lb_destination1_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lb_destination1_t& m) {
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lb_destination1_t& m) {
        uint64_t m_destination;
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lb_destination1_t& m)
{
    serializer_class<npl_path_lb_destination1_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lb_destination1_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lb_destination1_t& m)
{
    serializer_class<npl_path_lb_destination1_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lb_destination1_t&);



template<>
class serializer_class<npl_path_lb_destination_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lb_destination_t& m) {
        uint64_t m_enc_type = m.enc_type;
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lb_destination_t& m) {
        uint64_t m_enc_type;
        uint64_t m_destination;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
        m.enc_type = m_enc_type;
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lb_destination_t& m)
{
    serializer_class<npl_path_lb_destination_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lb_destination_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lb_destination_t& m)
{
    serializer_class<npl_path_lb_destination_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lb_destination_t&);



template<>
class serializer_class<npl_path_lb_raw_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lb_raw_t& m) {
        uint64_t m_payload = m.payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lb_raw_t& m) {
        uint64_t m_payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
        m.payload = m_payload;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lb_raw_t& m)
{
    serializer_class<npl_path_lb_raw_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lb_raw_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lb_raw_t& m)
{
    serializer_class<npl_path_lb_raw_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lb_raw_t&);



template<>
class serializer_class<npl_path_lb_stage2_p_nh_11b_asbr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lb_stage2_p_nh_11b_asbr_t& m) {
        uint64_t m_asbr = m.asbr;
        uint64_t m_stage2_p_nh_11b = m.stage2_p_nh_11b;
            archive(::cereal::make_nvp("asbr", m_asbr));
            archive(::cereal::make_nvp("stage2_p_nh_11b", m_stage2_p_nh_11b));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lb_stage2_p_nh_11b_asbr_t& m) {
        uint64_t m_asbr;
        uint64_t m_stage2_p_nh_11b;
            archive(::cereal::make_nvp("asbr", m_asbr));
            archive(::cereal::make_nvp("stage2_p_nh_11b", m_stage2_p_nh_11b));
            archive(::cereal::make_nvp("type", m.type));
        m.asbr = m_asbr;
        m.stage2_p_nh_11b = m_stage2_p_nh_11b;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lb_stage2_p_nh_11b_asbr_t& m)
{
    serializer_class<npl_path_lb_stage2_p_nh_11b_asbr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lb_stage2_p_nh_11b_asbr_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lb_stage2_p_nh_11b_asbr_t& m)
{
    serializer_class<npl_path_lb_stage2_p_nh_11b_asbr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lb_stage2_p_nh_11b_asbr_t&);



template<>
class serializer_class<npl_path_lb_stage2_p_nh_te_tunnel14b1_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lb_stage2_p_nh_te_tunnel14b1_t& m) {
        uint64_t m_te_tunnel14b = m.te_tunnel14b;
        uint64_t m_stage2_p_nh = m.stage2_p_nh;
            archive(::cereal::make_nvp("te_tunnel14b", m_te_tunnel14b));
            archive(::cereal::make_nvp("stage2_p_nh", m_stage2_p_nh));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lb_stage2_p_nh_te_tunnel14b1_t& m) {
        uint64_t m_te_tunnel14b;
        uint64_t m_stage2_p_nh;
            archive(::cereal::make_nvp("te_tunnel14b", m_te_tunnel14b));
            archive(::cereal::make_nvp("stage2_p_nh", m_stage2_p_nh));
            archive(::cereal::make_nvp("type", m.type));
        m.te_tunnel14b = m_te_tunnel14b;
        m.stage2_p_nh = m_stage2_p_nh;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lb_stage2_p_nh_te_tunnel14b1_t& m)
{
    serializer_class<npl_path_lb_stage2_p_nh_te_tunnel14b1_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lb_stage2_p_nh_te_tunnel14b1_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lb_stage2_p_nh_te_tunnel14b1_t& m)
{
    serializer_class<npl_path_lb_stage2_p_nh_te_tunnel14b1_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lb_stage2_p_nh_te_tunnel14b1_t&);



template<>
class serializer_class<npl_path_lb_stage2_p_nh_te_tunnel14b_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lb_stage2_p_nh_te_tunnel14b_t& m) {
        uint64_t m_te_tunnel14b = m.te_tunnel14b;
        uint64_t m_stage2_p_nh = m.stage2_p_nh;
            archive(::cereal::make_nvp("te_tunnel14b", m_te_tunnel14b));
            archive(::cereal::make_nvp("stage2_p_nh", m_stage2_p_nh));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lb_stage2_p_nh_te_tunnel14b_t& m) {
        uint64_t m_te_tunnel14b;
        uint64_t m_stage2_p_nh;
            archive(::cereal::make_nvp("te_tunnel14b", m_te_tunnel14b));
            archive(::cereal::make_nvp("stage2_p_nh", m_stage2_p_nh));
            archive(::cereal::make_nvp("type", m.type));
        m.te_tunnel14b = m_te_tunnel14b;
        m.stage2_p_nh = m_stage2_p_nh;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lb_stage2_p_nh_te_tunnel14b_t& m)
{
    serializer_class<npl_path_lb_stage2_p_nh_te_tunnel14b_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lb_stage2_p_nh_te_tunnel14b_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lb_stage2_p_nh_te_tunnel14b_t& m)
{
    serializer_class<npl_path_lb_stage2_p_nh_te_tunnel14b_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lb_stage2_p_nh_te_tunnel14b_t&);



template<>
class serializer_class<npl_path_lb_stage3_nh_11b_asbr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lb_stage3_nh_11b_asbr_t& m) {
        uint64_t m_asbr = m.asbr;
        uint64_t m_stage3_nh_11b = m.stage3_nh_11b;
            archive(::cereal::make_nvp("asbr", m_asbr));
            archive(::cereal::make_nvp("stage3_nh_11b", m_stage3_nh_11b));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lb_stage3_nh_11b_asbr_t& m) {
        uint64_t m_asbr;
        uint64_t m_stage3_nh_11b;
            archive(::cereal::make_nvp("asbr", m_asbr));
            archive(::cereal::make_nvp("stage3_nh_11b", m_stage3_nh_11b));
            archive(::cereal::make_nvp("type", m.type));
        m.asbr = m_asbr;
        m.stage3_nh_11b = m_stage3_nh_11b;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lb_stage3_nh_11b_asbr_t& m)
{
    serializer_class<npl_path_lb_stage3_nh_11b_asbr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lb_stage3_nh_11b_asbr_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lb_stage3_nh_11b_asbr_t& m)
{
    serializer_class<npl_path_lb_stage3_nh_11b_asbr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lb_stage3_nh_11b_asbr_t&);



template<>
class serializer_class<npl_path_lb_stage3_nh_te_tunnel14b1_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lb_stage3_nh_te_tunnel14b1_t& m) {
        uint64_t m_te_tunnel14b = m.te_tunnel14b;
        uint64_t m_stage3_nh = m.stage3_nh;
            archive(::cereal::make_nvp("te_tunnel14b", m_te_tunnel14b));
            archive(::cereal::make_nvp("stage3_nh", m_stage3_nh));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lb_stage3_nh_te_tunnel14b1_t& m) {
        uint64_t m_te_tunnel14b;
        uint64_t m_stage3_nh;
            archive(::cereal::make_nvp("te_tunnel14b", m_te_tunnel14b));
            archive(::cereal::make_nvp("stage3_nh", m_stage3_nh));
            archive(::cereal::make_nvp("type", m.type));
        m.te_tunnel14b = m_te_tunnel14b;
        m.stage3_nh = m_stage3_nh;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lb_stage3_nh_te_tunnel14b1_t& m)
{
    serializer_class<npl_path_lb_stage3_nh_te_tunnel14b1_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lb_stage3_nh_te_tunnel14b1_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lb_stage3_nh_te_tunnel14b1_t& m)
{
    serializer_class<npl_path_lb_stage3_nh_te_tunnel14b1_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lb_stage3_nh_te_tunnel14b1_t&);



template<>
class serializer_class<npl_path_lb_stage3_nh_te_tunnel14b_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lb_stage3_nh_te_tunnel14b_t& m) {
        uint64_t m_te_tunnel14b = m.te_tunnel14b;
        uint64_t m_stage3_nh = m.stage3_nh;
            archive(::cereal::make_nvp("te_tunnel14b", m_te_tunnel14b));
            archive(::cereal::make_nvp("stage3_nh", m_stage3_nh));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lb_stage3_nh_te_tunnel14b_t& m) {
        uint64_t m_te_tunnel14b;
        uint64_t m_stage3_nh;
            archive(::cereal::make_nvp("te_tunnel14b", m_te_tunnel14b));
            archive(::cereal::make_nvp("stage3_nh", m_stage3_nh));
            archive(::cereal::make_nvp("type", m.type));
        m.te_tunnel14b = m_te_tunnel14b;
        m.stage3_nh = m_stage3_nh;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lb_stage3_nh_te_tunnel14b_t& m)
{
    serializer_class<npl_path_lb_stage3_nh_te_tunnel14b_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lb_stage3_nh_te_tunnel14b_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lb_stage3_nh_te_tunnel14b_t& m)
{
    serializer_class<npl_path_lb_stage3_nh_te_tunnel14b_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lb_stage3_nh_te_tunnel14b_t&);



template<>
class serializer_class<npl_path_lp_narrow_raw_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_narrow_raw_t& m) {
        uint64_t m_payload = m.payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_narrow_raw_t& m) {
        uint64_t m_payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
        m.payload = m_payload;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_narrow_raw_t& m)
{
    serializer_class<npl_path_lp_narrow_raw_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_narrow_raw_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_narrow_raw_t& m)
{
    serializer_class<npl_path_lp_narrow_raw_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_narrow_raw_t&);



template<>
class serializer_class<npl_path_lp_protected_raw_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_protected_raw_t& m) {
        uint64_t m_payload = m.payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_protected_raw_t& m) {
        uint64_t m_payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
        m.payload = m_payload;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_protected_raw_t& m)
{
    serializer_class<npl_path_lp_protected_raw_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_protected_raw_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_protected_raw_t& m)
{
    serializer_class<npl_path_lp_protected_raw_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_protected_raw_t&);



template<>
class serializer_class<npl_path_lp_stage3_nh1_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_stage3_nh1_t& m) {
        uint64_t m_stage3_nh = m.stage3_nh;
            archive(::cereal::make_nvp("stage3_nh", m_stage3_nh));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_stage3_nh1_t& m) {
        uint64_t m_stage3_nh;
            archive(::cereal::make_nvp("stage3_nh", m_stage3_nh));
            archive(::cereal::make_nvp("type", m.type));
        m.stage3_nh = m_stage3_nh;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_stage3_nh1_t& m)
{
    serializer_class<npl_path_lp_stage3_nh1_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_stage3_nh1_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_stage3_nh1_t& m)
{
    serializer_class<npl_path_lp_stage3_nh1_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_stage3_nh1_t&);



template<>
class serializer_class<npl_path_lp_stage3_nh_te_tunnel16b_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_stage3_nh_te_tunnel16b_t& m) {
        uint64_t m_te_tunnel16b = m.te_tunnel16b;
        uint64_t m_stage3_nh = m.stage3_nh;
            archive(::cereal::make_nvp("te_tunnel16b", m_te_tunnel16b));
            archive(::cereal::make_nvp("stage3_nh", m_stage3_nh));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_stage3_nh_te_tunnel16b_t& m) {
        uint64_t m_te_tunnel16b;
        uint64_t m_stage3_nh;
            archive(::cereal::make_nvp("te_tunnel16b", m_te_tunnel16b));
            archive(::cereal::make_nvp("stage3_nh", m_stage3_nh));
            archive(::cereal::make_nvp("type", m.type));
        m.te_tunnel16b = m_te_tunnel16b;
        m.stage3_nh = m_stage3_nh;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_stage3_nh_te_tunnel16b_t& m)
{
    serializer_class<npl_path_lp_stage3_nh_te_tunnel16b_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_stage3_nh_te_tunnel16b_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_stage3_nh_te_tunnel16b_t& m)
{
    serializer_class<npl_path_lp_stage3_nh_te_tunnel16b_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_stage3_nh_te_tunnel16b_t&);



template<>
class serializer_class<npl_path_lp_table_protection_entry_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_table_protection_entry_t& m) {
            archive(::cereal::make_nvp("stage3_nh1", m.stage3_nh1));
            archive(::cereal::make_nvp("stage3_nh_te_tunnel16b", m.stage3_nh_te_tunnel16b));
            archive(::cereal::make_nvp("raw", m.raw));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_table_protection_entry_t& m) {
            archive(::cereal::make_nvp("stage3_nh1", m.stage3_nh1));
            archive(::cereal::make_nvp("stage3_nh_te_tunnel16b", m.stage3_nh_te_tunnel16b));
            archive(::cereal::make_nvp("raw", m.raw));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_table_protection_entry_t& m)
{
    serializer_class<npl_path_lp_table_protection_entry_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_table_protection_entry_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_table_protection_entry_t& m)
{
    serializer_class<npl_path_lp_table_protection_entry_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_table_protection_entry_t&);



template<>
class serializer_class<npl_path_lp_table_result_narrow_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_table_result_narrow_t& m) {
            archive(::cereal::make_nvp("raw", m.raw));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_table_result_narrow_t& m) {
            archive(::cereal::make_nvp("raw", m.raw));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_table_result_narrow_t& m)
{
    serializer_class<npl_path_lp_table_result_narrow_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_table_result_narrow_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_table_result_narrow_t& m)
{
    serializer_class<npl_path_lp_table_result_narrow_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_table_result_narrow_t&);



template<>
class serializer_class<npl_path_lp_wide_raw_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_wide_raw_t& m) {
        uint64_t m_payload = m.payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_wide_raw_t& m) {
        uint64_t m_payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
        m.payload = m_payload;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_wide_raw_t& m)
{
    serializer_class<npl_path_lp_wide_raw_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_wide_raw_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_wide_raw_t& m)
{
    serializer_class<npl_path_lp_wide_raw_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_wide_raw_t&);



template<>
class serializer_class<npl_path_protection_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_protection_id_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_protection_id_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_protection_id_t& m)
{
    serializer_class<npl_path_protection_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_protection_id_t&);

template <class Archive>
void
load(Archive& archive, npl_path_protection_id_t& m)
{
    serializer_class<npl_path_protection_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_protection_id_t&);



template<>
class serializer_class<npl_pbts_map_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pbts_map_table_key_t& m) {
        uint64_t m_qos = m.qos;
        uint64_t m_profile = m.profile;
            archive(::cereal::make_nvp("qos", m_qos));
            archive(::cereal::make_nvp("profile", m_profile));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pbts_map_table_key_t& m) {
        uint64_t m_qos;
        uint64_t m_profile;
            archive(::cereal::make_nvp("qos", m_qos));
            archive(::cereal::make_nvp("profile", m_profile));
        m.qos = m_qos;
        m.profile = m_profile;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pbts_map_table_key_t& m)
{
    serializer_class<npl_pbts_map_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pbts_map_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pbts_map_table_key_t& m)
{
    serializer_class<npl_pbts_map_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pbts_map_table_key_t&);



template<>
class serializer_class<npl_pbts_map_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pbts_map_table_result_t& m) {
        uint64_t m_pbts_offset = m.pbts_offset;
        uint64_t m_destination_shift = m.destination_shift;
        uint64_t m_and_mask = m.and_mask;
            archive(::cereal::make_nvp("pbts_offset", m_pbts_offset));
            archive(::cereal::make_nvp("destination_shift", m_destination_shift));
            archive(::cereal::make_nvp("and_mask", m_and_mask));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pbts_map_table_result_t& m) {
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
save(Archive& archive, const npl_pbts_map_table_result_t& m)
{
    serializer_class<npl_pbts_map_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pbts_map_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_pbts_map_table_result_t& m)
{
    serializer_class<npl_pbts_map_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pbts_map_table_result_t&);



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
class serializer_class<npl_pfc_latency_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_latency_t& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_latency_t& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_latency_t& m)
{
    serializer_class<npl_pfc_latency_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_latency_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_latency_t& m)
{
    serializer_class<npl_pfc_latency_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_latency_t&);



template<>
class serializer_class<npl_pfc_quanta_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_quanta_table_result_t& m) {
        uint64_t m_dual_entry = m.dual_entry;
            archive(::cereal::make_nvp("dual_entry", m_dual_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_quanta_table_result_t& m) {
        uint64_t m_dual_entry;
            archive(::cereal::make_nvp("dual_entry", m_dual_entry));
        m.dual_entry = m_dual_entry;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_quanta_table_result_t& m)
{
    serializer_class<npl_pfc_quanta_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_quanta_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_quanta_table_result_t& m)
{
    serializer_class<npl_pfc_quanta_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_quanta_table_result_t&);



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
class serializer_class<npl_port_dspa_dsp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_dspa_dsp_t& m) {
        uint64_t m_dsp = m.dsp;
            archive(::cereal::make_nvp("dsp", m_dsp));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_dspa_dsp_t& m) {
        uint64_t m_dsp;
            archive(::cereal::make_nvp("dsp", m_dsp));
            archive(::cereal::make_nvp("type", m.type));
        m.dsp = m_dsp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_dspa_dsp_t& m)
{
    serializer_class<npl_port_dspa_dsp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_dspa_dsp_t&);

template <class Archive>
void
load(Archive& archive, npl_port_dspa_dsp_t& m)
{
    serializer_class<npl_port_dspa_dsp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_dspa_dsp_t&);



template<>
class serializer_class<npl_port_dspa_raw_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_dspa_raw_t& m) {
        uint64_t m_payload = m.payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_dspa_raw_t& m) {
        uint64_t m_payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
        m.payload = m_payload;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_dspa_raw_t& m)
{
    serializer_class<npl_port_dspa_raw_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_dspa_raw_t&);

template <class Archive>
void
load(Archive& archive, npl_port_dspa_raw_t& m)
{
    serializer_class<npl_port_dspa_raw_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_dspa_raw_t&);



template<>
class serializer_class<npl_port_dspa_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_dspa_table_result_t& m) {
            archive(::cereal::make_nvp("dsp", m.dsp));
            archive(::cereal::make_nvp("raw", m.raw));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_dspa_table_result_t& m) {
            archive(::cereal::make_nvp("dsp", m.dsp));
            archive(::cereal::make_nvp("raw", m.raw));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_dspa_table_result_t& m)
{
    serializer_class<npl_port_dspa_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_dspa_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_port_dspa_table_result_t& m)
{
    serializer_class<npl_port_dspa_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_dspa_table_result_t&);



template<>
class serializer_class<npl_port_npp_protection_protected_raw_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_npp_protection_protected_raw_t& m) {
        uint64_t m_payload = m.payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_npp_protection_protected_raw_t& m) {
        uint64_t m_payload;
            archive(::cereal::make_nvp("payload", m_payload));
            archive(::cereal::make_nvp("type", m.type));
        m.payload = m_payload;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_npp_protection_protected_raw_t& m)
{
    serializer_class<npl_port_npp_protection_protected_raw_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_npp_protection_protected_raw_t&);

template <class Archive>
void
load(Archive& archive, npl_port_npp_protection_protected_raw_t& m)
{
    serializer_class<npl_port_npp_protection_protected_raw_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_npp_protection_protected_raw_t&);



}

