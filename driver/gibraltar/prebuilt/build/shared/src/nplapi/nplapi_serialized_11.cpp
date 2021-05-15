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
class serializer_class<npl_common_data_ecmp2_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_common_data_ecmp2_t& m) {
        uint64_t m_enc_type = m.enc_type;
        uint64_t m_te_tunnel14b_or_asbr = m.te_tunnel14b_or_asbr;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("te_tunnel14b_or_asbr", m_te_tunnel14b_or_asbr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_common_data_ecmp2_t& m) {
        uint64_t m_enc_type;
        uint64_t m_te_tunnel14b_or_asbr;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("te_tunnel14b_or_asbr", m_te_tunnel14b_or_asbr));
        m.enc_type = m_enc_type;
        m.te_tunnel14b_or_asbr = m_te_tunnel14b_or_asbr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_common_data_ecmp2_t& m)
{
    serializer_class<npl_common_data_ecmp2_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_common_data_ecmp2_t&);

template <class Archive>
void
load(Archive& archive, npl_common_data_ecmp2_t& m)
{
    serializer_class<npl_common_data_ecmp2_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_common_data_ecmp2_t&);



template<>
class serializer_class<npl_common_data_prefix_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_common_data_prefix_t& m) {
        uint64_t m_te_tunnel16b = m.te_tunnel16b;
            archive(::cereal::make_nvp("te_tunnel16b", m_te_tunnel16b));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_common_data_prefix_t& m) {
        uint64_t m_te_tunnel16b;
            archive(::cereal::make_nvp("te_tunnel16b", m_te_tunnel16b));
        m.te_tunnel16b = m_te_tunnel16b;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_common_data_prefix_t& m)
{
    serializer_class<npl_common_data_prefix_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_common_data_prefix_t&);

template <class Archive>
void
load(Archive& archive, npl_common_data_prefix_t& m)
{
    serializer_class<npl_common_data_prefix_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_common_data_prefix_t&);



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
class serializer_class<npl_db_access_common_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_db_access_common_header_t& m) {
        uint64_t m_num_of_macros_to_perform = m.num_of_macros_to_perform;
            archive(::cereal::make_nvp("num_of_macros_to_perform", m_num_of_macros_to_perform));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_db_access_common_header_t& m) {
        uint64_t m_num_of_macros_to_perform;
            archive(::cereal::make_nvp("num_of_macros_to_perform", m_num_of_macros_to_perform));
        m.num_of_macros_to_perform = m_num_of_macros_to_perform;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_db_access_common_header_t& m)
{
    serializer_class<npl_db_access_common_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_db_access_common_header_t&);

template <class Archive>
void
load(Archive& archive, npl_db_access_common_header_t& m)
{
    serializer_class<npl_db_access_common_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_db_access_common_header_t&);



template<>
class serializer_class<npl_db_access_fwd_info_header_t_anonymous_union_macro_or_fwd_dest_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_db_access_fwd_info_header_t_anonymous_union_macro_or_fwd_dest_t& m) {
        uint64_t m_fwd_dest = m.fwd_dest;
            archive(::cereal::make_nvp("common_header", m.common_header));
            archive(::cereal::make_nvp("fwd_dest", m_fwd_dest));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_db_access_fwd_info_header_t_anonymous_union_macro_or_fwd_dest_t& m) {
        uint64_t m_fwd_dest;
            archive(::cereal::make_nvp("common_header", m.common_header));
            archive(::cereal::make_nvp("fwd_dest", m_fwd_dest));
        m.fwd_dest = m_fwd_dest;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_db_access_fwd_info_header_t_anonymous_union_macro_or_fwd_dest_t& m)
{
    serializer_class<npl_db_access_fwd_info_header_t_anonymous_union_macro_or_fwd_dest_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_db_access_fwd_info_header_t_anonymous_union_macro_or_fwd_dest_t&);

template <class Archive>
void
load(Archive& archive, npl_db_access_fwd_info_header_t_anonymous_union_macro_or_fwd_dest_t& m)
{
    serializer_class<npl_db_access_fwd_info_header_t_anonymous_union_macro_or_fwd_dest_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_db_access_fwd_info_header_t_anonymous_union_macro_or_fwd_dest_t&);



template<>
class serializer_class<npl_db_access_key_selectors_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_db_access_key_selectors_header_t& m) {
        uint64_t m_bucket_a_key_selector = m.bucket_a_key_selector;
        uint64_t m_bucket_b_key_selector = m.bucket_b_key_selector;
        uint64_t m_bucket_c_key_selector = m.bucket_c_key_selector;
        uint64_t m_bucket_d_key_selector = m.bucket_d_key_selector;
            archive(::cereal::make_nvp("bucket_a_key_selector", m_bucket_a_key_selector));
            archive(::cereal::make_nvp("bucket_b_key_selector", m_bucket_b_key_selector));
            archive(::cereal::make_nvp("bucket_c_key_selector", m_bucket_c_key_selector));
            archive(::cereal::make_nvp("bucket_d_key_selector", m_bucket_d_key_selector));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_db_access_key_selectors_header_t& m) {
        uint64_t m_bucket_a_key_selector;
        uint64_t m_bucket_b_key_selector;
        uint64_t m_bucket_c_key_selector;
        uint64_t m_bucket_d_key_selector;
            archive(::cereal::make_nvp("bucket_a_key_selector", m_bucket_a_key_selector));
            archive(::cereal::make_nvp("bucket_b_key_selector", m_bucket_b_key_selector));
            archive(::cereal::make_nvp("bucket_c_key_selector", m_bucket_c_key_selector));
            archive(::cereal::make_nvp("bucket_d_key_selector", m_bucket_d_key_selector));
        m.bucket_a_key_selector = m_bucket_a_key_selector;
        m.bucket_b_key_selector = m_bucket_b_key_selector;
        m.bucket_c_key_selector = m_bucket_c_key_selector;
        m.bucket_d_key_selector = m_bucket_d_key_selector;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_db_access_key_selectors_header_t& m)
{
    serializer_class<npl_db_access_key_selectors_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_db_access_key_selectors_header_t&);

template <class Archive>
void
load(Archive& archive, npl_db_access_key_selectors_header_t& m)
{
    serializer_class<npl_db_access_key_selectors_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_db_access_key_selectors_header_t&);



template<>
class serializer_class<npl_db_access_lu_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_db_access_lu_data_t& m) {
        uint64_t m_check_result = m.check_result;
        uint64_t m_expected_result = m.expected_result;
        uint64_t m_key = m.key;
            archive(::cereal::make_nvp("check_result", m_check_result));
            archive(::cereal::make_nvp("expected_result", m_expected_result));
            archive(::cereal::make_nvp("key", m_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_db_access_lu_data_t& m) {
        uint64_t m_check_result;
        uint64_t m_expected_result;
        uint64_t m_key;
            archive(::cereal::make_nvp("check_result", m_check_result));
            archive(::cereal::make_nvp("expected_result", m_expected_result));
            archive(::cereal::make_nvp("key", m_key));
        m.check_result = m_check_result;
        m.expected_result = m_expected_result;
        m.key = m_key;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_db_access_lu_data_t& m)
{
    serializer_class<npl_db_access_lu_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_db_access_lu_data_t&);

template <class Archive>
void
load(Archive& archive, npl_db_access_lu_data_t& m)
{
    serializer_class<npl_db_access_lu_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_db_access_lu_data_t&);



template<>
class serializer_class<npl_db_access_service_mapping_access_attr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_db_access_service_mapping_access_attr_t& m) {
        uint64_t m_key_lsbs = m.key_lsbs;
            archive(::cereal::make_nvp("key_lsbs", m_key_lsbs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_db_access_service_mapping_access_attr_t& m) {
        uint64_t m_key_lsbs;
            archive(::cereal::make_nvp("key_lsbs", m_key_lsbs));
        m.key_lsbs = m_key_lsbs;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_db_access_service_mapping_access_attr_t& m)
{
    serializer_class<npl_db_access_service_mapping_access_attr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_db_access_service_mapping_access_attr_t&);

template <class Archive>
void
load(Archive& archive, npl_db_access_service_mapping_access_attr_t& m)
{
    serializer_class<npl_db_access_service_mapping_access_attr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_db_access_service_mapping_access_attr_t&);



template<>
class serializer_class<npl_db_access_service_mapping_tcam_access_attr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_db_access_service_mapping_tcam_access_attr_t& m) {
        uint64_t m_key_lsbs = m.key_lsbs;
            archive(::cereal::make_nvp("key_lsbs", m_key_lsbs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_db_access_service_mapping_tcam_access_attr_t& m) {
        uint64_t m_key_lsbs;
            archive(::cereal::make_nvp("key_lsbs", m_key_lsbs));
        m.key_lsbs = m_key_lsbs;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_db_access_service_mapping_tcam_access_attr_t& m)
{
    serializer_class<npl_db_access_service_mapping_tcam_access_attr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_db_access_service_mapping_tcam_access_attr_t&);

template <class Archive>
void
load(Archive& archive, npl_db_access_service_mapping_tcam_access_attr_t& m)
{
    serializer_class<npl_db_access_service_mapping_tcam_access_attr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_db_access_service_mapping_tcam_access_attr_t&);



template<>
class serializer_class<npl_db_access_splitter_action_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_db_access_splitter_action_t& m) {
        uint64_t m_access_type = m.access_type;
            archive(::cereal::make_nvp("access_type", m_access_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_db_access_splitter_action_t& m) {
        uint64_t m_access_type;
            archive(::cereal::make_nvp("access_type", m_access_type));
        m.access_type = m_access_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_db_access_splitter_action_t& m)
{
    serializer_class<npl_db_access_splitter_action_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_db_access_splitter_action_t&);

template <class Archive>
void
load(Archive& archive, npl_db_access_splitter_action_t& m)
{
    serializer_class<npl_db_access_splitter_action_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_db_access_splitter_action_t&);



template<>
class serializer_class<npl_db_access_term_macro_dests_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_db_access_term_macro_dests_header_t& m) {
            archive(::cereal::make_nvp("bucket_a_lu_dest", m.bucket_a_lu_dest));
            archive(::cereal::make_nvp("bucket_b_lu_dest", m.bucket_b_lu_dest));
            archive(::cereal::make_nvp("bucket_c_lu_dest", m.bucket_c_lu_dest));
            archive(::cereal::make_nvp("bucket_d_lu_dest", m.bucket_d_lu_dest));
            archive(::cereal::make_nvp("bucket_a_result_dest", m.bucket_a_result_dest));
            archive(::cereal::make_nvp("bucket_b_result_dest", m.bucket_b_result_dest));
            archive(::cereal::make_nvp("bucket_c_result_dest", m.bucket_c_result_dest));
            archive(::cereal::make_nvp("bucket_d_result_dest", m.bucket_d_result_dest));
            archive(::cereal::make_nvp("db_access_key_selectors_header", m.db_access_key_selectors_header));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_db_access_term_macro_dests_header_t& m) {
            archive(::cereal::make_nvp("bucket_a_lu_dest", m.bucket_a_lu_dest));
            archive(::cereal::make_nvp("bucket_b_lu_dest", m.bucket_b_lu_dest));
            archive(::cereal::make_nvp("bucket_c_lu_dest", m.bucket_c_lu_dest));
            archive(::cereal::make_nvp("bucket_d_lu_dest", m.bucket_d_lu_dest));
            archive(::cereal::make_nvp("bucket_a_result_dest", m.bucket_a_result_dest));
            archive(::cereal::make_nvp("bucket_b_result_dest", m.bucket_b_result_dest));
            archive(::cereal::make_nvp("bucket_c_result_dest", m.bucket_c_result_dest));
            archive(::cereal::make_nvp("bucket_d_result_dest", m.bucket_d_result_dest));
            archive(::cereal::make_nvp("db_access_key_selectors_header", m.db_access_key_selectors_header));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_db_access_term_macro_dests_header_t& m)
{
    serializer_class<npl_db_access_term_macro_dests_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_db_access_term_macro_dests_header_t&);

template <class Archive>
void
load(Archive& archive, npl_db_access_term_macro_dests_header_t& m)
{
    serializer_class<npl_db_access_term_macro_dests_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_db_access_term_macro_dests_header_t&);



template<>
class serializer_class<npl_db_access_transmit_macro_dests_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_db_access_transmit_macro_dests_header_t& m) {
            archive(::cereal::make_nvp("bucket_a_lu_dest", m.bucket_a_lu_dest));
            archive(::cereal::make_nvp("bucket_b_lu_dest", m.bucket_b_lu_dest));
            archive(::cereal::make_nvp("bucket_c_lu_dest", m.bucket_c_lu_dest));
            archive(::cereal::make_nvp("bucket_d_lu_dest", m.bucket_d_lu_dest));
            archive(::cereal::make_nvp("bucket_a_result_dest", m.bucket_a_result_dest));
            archive(::cereal::make_nvp("bucket_b_result_dest", m.bucket_b_result_dest));
            archive(::cereal::make_nvp("bucket_c_result_dest", m.bucket_c_result_dest));
            archive(::cereal::make_nvp("bucket_d_result_dest", m.bucket_d_result_dest));
            archive(::cereal::make_nvp("db_access_key_selectors_header", m.db_access_key_selectors_header));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_db_access_transmit_macro_dests_header_t& m) {
            archive(::cereal::make_nvp("bucket_a_lu_dest", m.bucket_a_lu_dest));
            archive(::cereal::make_nvp("bucket_b_lu_dest", m.bucket_b_lu_dest));
            archive(::cereal::make_nvp("bucket_c_lu_dest", m.bucket_c_lu_dest));
            archive(::cereal::make_nvp("bucket_d_lu_dest", m.bucket_d_lu_dest));
            archive(::cereal::make_nvp("bucket_a_result_dest", m.bucket_a_result_dest));
            archive(::cereal::make_nvp("bucket_b_result_dest", m.bucket_b_result_dest));
            archive(::cereal::make_nvp("bucket_c_result_dest", m.bucket_c_result_dest));
            archive(::cereal::make_nvp("bucket_d_result_dest", m.bucket_d_result_dest));
            archive(::cereal::make_nvp("db_access_key_selectors_header", m.db_access_key_selectors_header));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_db_access_transmit_macro_dests_header_t& m)
{
    serializer_class<npl_db_access_transmit_macro_dests_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_db_access_transmit_macro_dests_header_t&);

template <class Archive>
void
load(Archive& archive, npl_db_access_transmit_macro_dests_header_t& m)
{
    serializer_class<npl_db_access_transmit_macro_dests_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_db_access_transmit_macro_dests_header_t&);



template<>
class serializer_class<npl_db_access_transmit_per_dest_port_npu_host_macro_stamping_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_db_access_transmit_per_dest_port_npu_host_macro_stamping_t& m) {
        uint64_t m_npu_host_macro = m.npu_host_macro;
        uint64_t m_stamp_npu_host_macro_on_packet = m.stamp_npu_host_macro_on_packet;
            archive(::cereal::make_nvp("npu_host_macro", m_npu_host_macro));
            archive(::cereal::make_nvp("stamp_npu_host_macro_on_packet", m_stamp_npu_host_macro_on_packet));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_db_access_transmit_per_dest_port_npu_host_macro_stamping_t& m) {
        uint64_t m_npu_host_macro;
        uint64_t m_stamp_npu_host_macro_on_packet;
            archive(::cereal::make_nvp("npu_host_macro", m_npu_host_macro));
            archive(::cereal::make_nvp("stamp_npu_host_macro_on_packet", m_stamp_npu_host_macro_on_packet));
        m.npu_host_macro = m_npu_host_macro;
        m.stamp_npu_host_macro_on_packet = m_stamp_npu_host_macro_on_packet;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_db_access_transmit_per_dest_port_npu_host_macro_stamping_t& m)
{
    serializer_class<npl_db_access_transmit_per_dest_port_npu_host_macro_stamping_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_db_access_transmit_per_dest_port_npu_host_macro_stamping_t&);

template <class Archive>
void
load(Archive& archive, npl_db_access_transmit_per_dest_port_npu_host_macro_stamping_t& m)
{
    serializer_class<npl_db_access_transmit_per_dest_port_npu_host_macro_stamping_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_db_access_transmit_per_dest_port_npu_host_macro_stamping_t&);



template<>
class serializer_class<npl_db_access_tx_basic_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_db_access_tx_basic_header_t& m) {
        uint64_t m_num_of_macros_to_perform = m.num_of_macros_to_perform;
        uint64_t m_num_of_ene_instructions_to_perform = m.num_of_ene_instructions_to_perform;
            archive(::cereal::make_nvp("num_of_macros_to_perform", m_num_of_macros_to_perform));
            archive(::cereal::make_nvp("num_of_ene_instructions_to_perform", m_num_of_ene_instructions_to_perform));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_db_access_tx_basic_header_t& m) {
        uint64_t m_num_of_macros_to_perform;
        uint64_t m_num_of_ene_instructions_to_perform;
            archive(::cereal::make_nvp("num_of_macros_to_perform", m_num_of_macros_to_perform));
            archive(::cereal::make_nvp("num_of_ene_instructions_to_perform", m_num_of_ene_instructions_to_perform));
        m.num_of_macros_to_perform = m_num_of_macros_to_perform;
        m.num_of_ene_instructions_to_perform = m_num_of_ene_instructions_to_perform;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_db_access_tx_basic_header_t& m)
{
    serializer_class<npl_db_access_tx_basic_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_db_access_tx_basic_header_t&);

template <class Archive>
void
load(Archive& archive, npl_db_access_tx_basic_header_t& m)
{
    serializer_class<npl_db_access_tx_basic_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_db_access_tx_basic_header_t&);



template<>
class serializer_class<npl_db_fc_tx_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_db_fc_tx_result_t& m) {
        uint64_t m_data = m.data;
            archive(::cereal::make_nvp("data", m_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_db_fc_tx_result_t& m) {
        uint64_t m_data;
            archive(::cereal::make_nvp("data", m_data));
        m.data = m_data;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_db_fc_tx_result_t& m)
{
    serializer_class<npl_db_fc_tx_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_db_fc_tx_result_t&);

template <class Archive>
void
load(Archive& archive, npl_db_fc_tx_result_t& m)
{
    serializer_class<npl_db_fc_tx_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_db_fc_tx_result_t&);



template<>
class serializer_class<npl_dest_class_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dest_class_id_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dest_class_id_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dest_class_id_t& m)
{
    serializer_class<npl_dest_class_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dest_class_id_t&);

template <class Archive>
void
load(Archive& archive, npl_dest_class_id_t& m)
{
    serializer_class<npl_dest_class_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dest_class_id_t&);



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
class serializer_class<npl_dest_with_class_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dest_with_class_id_t& m) {
        uint64_t m_dest_19_15 = m.dest_19_15;
        uint64_t m_has_class_id = m.has_class_id;
        uint64_t m_dest_13_12 = m.dest_13_12;
        uint64_t m_class_id = m.class_id;
        uint64_t m_dest_7_0 = m.dest_7_0;
            archive(::cereal::make_nvp("dest_19_15", m_dest_19_15));
            archive(::cereal::make_nvp("has_class_id", m_has_class_id));
            archive(::cereal::make_nvp("dest_13_12", m_dest_13_12));
            archive(::cereal::make_nvp("class_id", m_class_id));
            archive(::cereal::make_nvp("dest_7_0", m_dest_7_0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dest_with_class_id_t& m) {
        uint64_t m_dest_19_15;
        uint64_t m_has_class_id;
        uint64_t m_dest_13_12;
        uint64_t m_class_id;
        uint64_t m_dest_7_0;
            archive(::cereal::make_nvp("dest_19_15", m_dest_19_15));
            archive(::cereal::make_nvp("has_class_id", m_has_class_id));
            archive(::cereal::make_nvp("dest_13_12", m_dest_13_12));
            archive(::cereal::make_nvp("class_id", m_class_id));
            archive(::cereal::make_nvp("dest_7_0", m_dest_7_0));
        m.dest_19_15 = m_dest_19_15;
        m.has_class_id = m_has_class_id;
        m.dest_13_12 = m_dest_13_12;
        m.class_id = m_class_id;
        m.dest_7_0 = m_dest_7_0;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dest_with_class_id_t& m)
{
    serializer_class<npl_dest_with_class_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dest_with_class_id_t&);

template <class Archive>
void
load(Archive& archive, npl_dest_with_class_id_t& m)
{
    serializer_class<npl_dest_with_class_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dest_with_class_id_t&);



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
class serializer_class<npl_dlp_profile_local_vars_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dlp_profile_local_vars_t& m) {
        uint64_t m_dlp_type = m.dlp_type;
        uint64_t m_dlp_mask = m.dlp_mask;
        uint64_t m_dlp_offset = m.dlp_offset;
            archive(::cereal::make_nvp("dlp_type", m_dlp_type));
            archive(::cereal::make_nvp("dlp_mask", m_dlp_mask));
            archive(::cereal::make_nvp("dlp_offset", m_dlp_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dlp_profile_local_vars_t& m) {
        uint64_t m_dlp_type;
        uint64_t m_dlp_mask;
        uint64_t m_dlp_offset;
            archive(::cereal::make_nvp("dlp_type", m_dlp_type));
            archive(::cereal::make_nvp("dlp_mask", m_dlp_mask));
            archive(::cereal::make_nvp("dlp_offset", m_dlp_offset));
        m.dlp_type = m_dlp_type;
        m.dlp_mask = m_dlp_mask;
        m.dlp_offset = m_dlp_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dlp_profile_local_vars_t& m)
{
    serializer_class<npl_dlp_profile_local_vars_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dlp_profile_local_vars_t&);

template <class Archive>
void
load(Archive& archive, npl_dlp_profile_local_vars_t& m)
{
    serializer_class<npl_dlp_profile_local_vars_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dlp_profile_local_vars_t&);



template<>
class serializer_class<npl_dram_cgm_cgm_lut_results_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dram_cgm_cgm_lut_results_t& m) {
        uint64_t m_dp1 = m.dp1;
        uint64_t m_dp0 = m.dp0;
        uint64_t m_mark1 = m.mark1;
        uint64_t m_mark0 = m.mark0;
        uint64_t m_set_aging = m.set_aging;
        uint64_t m_clr_aging = m.clr_aging;
            archive(::cereal::make_nvp("dp1", m_dp1));
            archive(::cereal::make_nvp("dp0", m_dp0));
            archive(::cereal::make_nvp("mark1", m_mark1));
            archive(::cereal::make_nvp("mark0", m_mark0));
            archive(::cereal::make_nvp("set_aging", m_set_aging));
            archive(::cereal::make_nvp("clr_aging", m_clr_aging));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dram_cgm_cgm_lut_results_t& m) {
        uint64_t m_dp1;
        uint64_t m_dp0;
        uint64_t m_mark1;
        uint64_t m_mark0;
        uint64_t m_set_aging;
        uint64_t m_clr_aging;
            archive(::cereal::make_nvp("dp1", m_dp1));
            archive(::cereal::make_nvp("dp0", m_dp0));
            archive(::cereal::make_nvp("mark1", m_mark1));
            archive(::cereal::make_nvp("mark0", m_mark0));
            archive(::cereal::make_nvp("set_aging", m_set_aging));
            archive(::cereal::make_nvp("clr_aging", m_clr_aging));
        m.dp1 = m_dp1;
        m.dp0 = m_dp0;
        m.mark1 = m_mark1;
        m.mark0 = m_mark0;
        m.set_aging = m_set_aging;
        m.clr_aging = m_clr_aging;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dram_cgm_cgm_lut_results_t& m)
{
    serializer_class<npl_dram_cgm_cgm_lut_results_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dram_cgm_cgm_lut_results_t&);

template <class Archive>
void
load(Archive& archive, npl_dram_cgm_cgm_lut_results_t& m)
{
    serializer_class<npl_dram_cgm_cgm_lut_results_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dram_cgm_cgm_lut_results_t&);



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
class serializer_class<npl_dsp_group_policy_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dsp_group_policy_t& m) {
        uint64_t m_enable = m.enable;
            archive(::cereal::make_nvp("enable", m_enable));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dsp_group_policy_t& m) {
        uint64_t m_enable;
            archive(::cereal::make_nvp("enable", m_enable));
        m.enable = m_enable;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dsp_group_policy_t& m)
{
    serializer_class<npl_dsp_group_policy_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dsp_group_policy_t&);

template <class Archive>
void
load(Archive& archive, npl_dsp_group_policy_t& m)
{
    serializer_class<npl_dsp_group_policy_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dsp_group_policy_t&);



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
class serializer_class<npl_em_common_data_raw_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_em_common_data_raw_t& m) {
        uint64_t m_common_data = m.common_data;
            archive(::cereal::make_nvp("common_data", m_common_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_em_common_data_raw_t& m) {
        uint64_t m_common_data;
            archive(::cereal::make_nvp("common_data", m_common_data));
        m.common_data = m_common_data;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_em_common_data_raw_t& m)
{
    serializer_class<npl_em_common_data_raw_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_em_common_data_raw_t&);

template <class Archive>
void
load(Archive& archive, npl_em_common_data_raw_t& m)
{
    serializer_class<npl_em_common_data_raw_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_em_common_data_raw_t&);



template<>
class serializer_class<npl_em_common_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_em_common_data_t& m) {
            archive(::cereal::make_nvp("common_data_ecmp2", m.common_data_ecmp2));
            archive(::cereal::make_nvp("common_data_prefix", m.common_data_prefix));
            archive(::cereal::make_nvp("raw", m.raw));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_em_common_data_t& m) {
            archive(::cereal::make_nvp("common_data_ecmp2", m.common_data_ecmp2));
            archive(::cereal::make_nvp("common_data_prefix", m.common_data_prefix));
            archive(::cereal::make_nvp("raw", m.raw));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_em_common_data_t& m)
{
    serializer_class<npl_em_common_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_em_common_data_t&);

template <class Archive>
void
load(Archive& archive, npl_em_common_data_t& m)
{
    serializer_class<npl_em_common_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_em_common_data_t&);



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
class serializer_class<npl_em_result_dsp_host_w_class_t_anonymous_union_dest_type_or_has_class_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_em_result_dsp_host_w_class_t_anonymous_union_dest_type_or_has_class_t& m) {
        uint64_t m_dest_type = m.dest_type;
        uint64_t m_has_class = m.has_class;
            archive(::cereal::make_nvp("dest_type", m_dest_type));
            archive(::cereal::make_nvp("has_class", m_has_class));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_em_result_dsp_host_w_class_t_anonymous_union_dest_type_or_has_class_t& m) {
        uint64_t m_dest_type;
        uint64_t m_has_class;
            archive(::cereal::make_nvp("dest_type", m_dest_type));
            archive(::cereal::make_nvp("has_class", m_has_class));
        m.dest_type = m_dest_type;
        m.has_class = m_has_class;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_em_result_dsp_host_w_class_t_anonymous_union_dest_type_or_has_class_t& m)
{
    serializer_class<npl_em_result_dsp_host_w_class_t_anonymous_union_dest_type_or_has_class_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_em_result_dsp_host_w_class_t_anonymous_union_dest_type_or_has_class_t&);

template <class Archive>
void
load(Archive& archive, npl_em_result_dsp_host_w_class_t_anonymous_union_dest_type_or_has_class_t& m)
{
    serializer_class<npl_em_result_dsp_host_w_class_t_anonymous_union_dest_type_or_has_class_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_em_result_dsp_host_w_class_t_anonymous_union_dest_type_or_has_class_t&);



template<>
class serializer_class<npl_em_result_dsp_host_wo_class_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_em_result_dsp_host_wo_class_t& m) {
        uint64_t m_dest_type = m.dest_type;
        uint64_t m_dest = m.dest;
        uint64_t m_host_mac_msb = m.host_mac_msb;
        uint64_t m_extra_dest_bit = m.extra_dest_bit;
        uint64_t m_host_mac_lsb = m.host_mac_lsb;
            archive(::cereal::make_nvp("dest_type", m_dest_type));
            archive(::cereal::make_nvp("dest", m_dest));
            archive(::cereal::make_nvp("host_mac_msb", m_host_mac_msb));
            archive(::cereal::make_nvp("extra_dest_bit", m_extra_dest_bit));
            archive(::cereal::make_nvp("host_mac_lsb", m_host_mac_lsb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_em_result_dsp_host_wo_class_t& m) {
        uint64_t m_dest_type;
        uint64_t m_dest;
        uint64_t m_host_mac_msb;
        uint64_t m_extra_dest_bit;
        uint64_t m_host_mac_lsb;
            archive(::cereal::make_nvp("dest_type", m_dest_type));
            archive(::cereal::make_nvp("dest", m_dest));
            archive(::cereal::make_nvp("host_mac_msb", m_host_mac_msb));
            archive(::cereal::make_nvp("extra_dest_bit", m_extra_dest_bit));
            archive(::cereal::make_nvp("host_mac_lsb", m_host_mac_lsb));
        m.dest_type = m_dest_type;
        m.dest = m_dest;
        m.host_mac_msb = m_host_mac_msb;
        m.extra_dest_bit = m_extra_dest_bit;
        m.host_mac_lsb = m_host_mac_lsb;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_em_result_dsp_host_wo_class_t& m)
{
    serializer_class<npl_em_result_dsp_host_wo_class_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_em_result_dsp_host_wo_class_t&);

template <class Archive>
void
load(Archive& archive, npl_em_result_dsp_host_wo_class_t& m)
{
    serializer_class<npl_em_result_dsp_host_wo_class_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_em_result_dsp_host_wo_class_t&);



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
class serializer_class<npl_expanded_forward_response_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_expanded_forward_response_t& m) {
        uint64_t m_dest = m.dest;
        uint64_t m_pad = m.pad;
            archive(::cereal::make_nvp("dest", m_dest));
            archive(::cereal::make_nvp("pad", m_pad));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_expanded_forward_response_t& m) {
        uint64_t m_dest;
        uint64_t m_pad;
            archive(::cereal::make_nvp("dest", m_dest));
            archive(::cereal::make_nvp("pad", m_pad));
        m.dest = m_dest;
        m.pad = m_pad;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_expanded_forward_response_t& m)
{
    serializer_class<npl_expanded_forward_response_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_expanded_forward_response_t&);

template <class Archive>
void
load(Archive& archive, npl_expanded_forward_response_t& m)
{
    serializer_class<npl_expanded_forward_response_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_expanded_forward_response_t&);



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
class serializer_class<npl_fabric_port_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_port_id_t& m) {
        uint64_t m_val = m.val;
            archive(::cereal::make_nvp("val", m_val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_port_id_t& m) {
        uint64_t m_val;
            archive(::cereal::make_nvp("val", m_val));
        m.val = m_val;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_port_id_t& m)
{
    serializer_class<npl_fabric_port_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_port_id_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_port_id_t& m)
{
    serializer_class<npl_fabric_port_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_port_id_t&);



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
class serializer_class<npl_fec_destination1_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fec_destination1_t& m) {
        uint64_t m_enc_type = m.enc_type;
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("enc_type", m_enc_type));
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fec_destination1_t& m) {
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
save(Archive& archive, const npl_fec_destination1_t& m)
{
    serializer_class<npl_fec_destination1_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fec_destination1_t&);

template <class Archive>
void
load(Archive& archive, npl_fec_destination1_t& m)
{
    serializer_class<npl_fec_destination1_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fec_destination1_t&);



template<>
class serializer_class<npl_fec_fec_destination_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fec_fec_destination_t& m) {
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fec_fec_destination_t& m) {
        uint64_t m_destination;
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("type", m.type));
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fec_fec_destination_t& m)
{
    serializer_class<npl_fec_fec_destination_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fec_fec_destination_t&);

template <class Archive>
void
load(Archive& archive, npl_fec_fec_destination_t& m)
{
    serializer_class<npl_fec_fec_destination_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fec_fec_destination_t&);



template<>
class serializer_class<npl_fec_raw_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fec_raw_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fec_raw_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
            archive(::cereal::make_nvp("type", m.type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fec_raw_t& m)
{
    serializer_class<npl_fec_raw_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fec_raw_t&);

template <class Archive>
void
load(Archive& archive, npl_fec_raw_t& m)
{
    serializer_class<npl_fec_raw_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fec_raw_t&);



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
class serializer_class<npl_fi_tcam_hardwired_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fi_tcam_hardwired_result_t& m) {
        uint64_t m_start_new_layer = m.start_new_layer;
        uint64_t m_next_macro_id = m.next_macro_id;
            archive(::cereal::make_nvp("start_new_layer", m_start_new_layer));
            archive(::cereal::make_nvp("next_macro_id", m_next_macro_id));
            archive(::cereal::make_nvp("next_header_type", m.next_header_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fi_tcam_hardwired_result_t& m) {
        uint64_t m_start_new_layer;
        uint64_t m_next_macro_id;
            archive(::cereal::make_nvp("start_new_layer", m_start_new_layer));
            archive(::cereal::make_nvp("next_macro_id", m_next_macro_id));
            archive(::cereal::make_nvp("next_header_type", m.next_header_type));
        m.start_new_layer = m_start_new_layer;
        m.next_macro_id = m_next_macro_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fi_tcam_hardwired_result_t& m)
{
    serializer_class<npl_fi_tcam_hardwired_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fi_tcam_hardwired_result_t&);

template <class Archive>
void
load(Archive& archive, npl_fi_tcam_hardwired_result_t& m)
{
    serializer_class<npl_fi_tcam_hardwired_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fi_tcam_hardwired_result_t&);



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
class serializer_class<npl_flc_header_types_array_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_header_types_array_key_t& m) {
        uint64_t m_source_port = m.source_port;
        uint64_t m_ifg = m.ifg;
        uint64_t m_recycle_code = m.recycle_code;
        uint64_t m_fi_hdr_5to9 = m.fi_hdr_5to9;
        uint64_t m_fi_hdr_4to0 = m.fi_hdr_4to0;
            archive(::cereal::make_nvp("source_port", m_source_port));
            archive(::cereal::make_nvp("ifg", m_ifg));
            archive(::cereal::make_nvp("recycle_code", m_recycle_code));
            archive(::cereal::make_nvp("fi_hdr_5to9", m_fi_hdr_5to9));
            archive(::cereal::make_nvp("fi_hdr_4to0", m_fi_hdr_4to0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_header_types_array_key_t& m) {
        uint64_t m_source_port;
        uint64_t m_ifg;
        uint64_t m_recycle_code;
        uint64_t m_fi_hdr_5to9;
        uint64_t m_fi_hdr_4to0;
            archive(::cereal::make_nvp("source_port", m_source_port));
            archive(::cereal::make_nvp("ifg", m_ifg));
            archive(::cereal::make_nvp("recycle_code", m_recycle_code));
            archive(::cereal::make_nvp("fi_hdr_5to9", m_fi_hdr_5to9));
            archive(::cereal::make_nvp("fi_hdr_4to0", m_fi_hdr_4to0));
        m.source_port = m_source_port;
        m.ifg = m_ifg;
        m.recycle_code = m_recycle_code;
        m.fi_hdr_5to9 = m_fi_hdr_5to9;
        m.fi_hdr_4to0 = m_fi_hdr_4to0;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_header_types_array_key_t& m)
{
    serializer_class<npl_flc_header_types_array_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_header_types_array_key_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_header_types_array_key_t& m)
{
    serializer_class<npl_flc_header_types_array_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_header_types_array_key_t&);



template<>
class serializer_class<npl_flc_map_header_type_mask_id_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_map_header_type_mask_id_data_t& m) {
        uint64_t m_mask_id = m.mask_id;
            archive(::cereal::make_nvp("mask_id", m_mask_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_map_header_type_mask_id_data_t& m) {
        uint64_t m_mask_id;
            archive(::cereal::make_nvp("mask_id", m_mask_id));
        m.mask_id = m_mask_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_map_header_type_mask_id_data_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_id_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_map_header_type_mask_id_data_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_map_header_type_mask_id_data_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_id_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_map_header_type_mask_id_data_t&);



template<>
class serializer_class<npl_flc_map_header_type_mask_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_map_header_type_mask_id_t& m) {
        uint64_t m_sel = m.sel;
            archive(::cereal::make_nvp("sel", m_sel));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_map_header_type_mask_id_t& m) {
        uint64_t m_sel;
            archive(::cereal::make_nvp("sel", m_sel));
        m.sel = m_sel;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_map_header_type_mask_id_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_map_header_type_mask_id_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_map_header_type_mask_id_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_map_header_type_mask_id_t&);



template<>
class serializer_class<npl_flc_map_header_type_mask_l_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_map_header_type_mask_l_data_t& m) {
            archive(::cereal::make_nvp("cache_mask", m.cache_mask));
            archive(::cereal::make_nvp("queue_mask", m.queue_mask));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_map_header_type_mask_l_data_t& m) {
            archive(::cereal::make_nvp("cache_mask", m.cache_mask));
            archive(::cereal::make_nvp("queue_mask", m.queue_mask));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_map_header_type_mask_l_data_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_l_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_map_header_type_mask_l_data_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_map_header_type_mask_l_data_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_l_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_map_header_type_mask_l_data_t&);



template<>
class serializer_class<npl_flc_map_header_type_mask_lm_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_map_header_type_mask_lm_key_t& m) {
        uint64_t m_sel = m.sel;
            archive(::cereal::make_nvp("sel", m_sel));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_map_header_type_mask_lm_key_t& m) {
        uint64_t m_sel;
            archive(::cereal::make_nvp("sel", m_sel));
        m.sel = m_sel;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_map_header_type_mask_lm_key_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_lm_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_map_header_type_mask_lm_key_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_map_header_type_mask_lm_key_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_lm_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_map_header_type_mask_lm_key_t&);



template<>
class serializer_class<npl_flc_map_header_type_mask_m_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_map_header_type_mask_m_data_t& m) {
            archive(::cereal::make_nvp("cache_mask", m.cache_mask));
            archive(::cereal::make_nvp("queue_mask", m.queue_mask));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_map_header_type_mask_m_data_t& m) {
            archive(::cereal::make_nvp("cache_mask", m.cache_mask));
            archive(::cereal::make_nvp("queue_mask", m.queue_mask));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_map_header_type_mask_m_data_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_m_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_map_header_type_mask_m_data_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_map_header_type_mask_m_data_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_m_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_map_header_type_mask_m_data_t&);



template<>
class serializer_class<npl_flc_map_header_type_mask_s_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_map_header_type_mask_s_data_t& m) {
            archive(::cereal::make_nvp("cache_mask", m.cache_mask));
            archive(::cereal::make_nvp("queue_mask", m.queue_mask));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_map_header_type_mask_s_data_t& m) {
            archive(::cereal::make_nvp("cache_mask", m.cache_mask));
            archive(::cereal::make_nvp("queue_mask", m.queue_mask));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_map_header_type_mask_s_data_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_s_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_map_header_type_mask_s_data_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_map_header_type_mask_s_data_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_s_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_map_header_type_mask_s_data_t&);



template<>
class serializer_class<npl_flc_map_header_type_mask_s_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_map_header_type_mask_s_key_t& m) {
        uint64_t m_sel = m.sel;
            archive(::cereal::make_nvp("sel", m_sel));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_map_header_type_mask_s_key_t& m) {
        uint64_t m_sel;
            archive(::cereal::make_nvp("sel", m_sel));
        m.sel = m_sel;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_map_header_type_mask_s_key_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_s_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_map_header_type_mask_s_key_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_map_header_type_mask_s_key_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_s_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_map_header_type_mask_s_key_t&);



template<>
class serializer_class<npl_flc_range_comp_profile_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_range_comp_profile_data_t& m) {
        uint64_t m_range_set = m.range_set;
        uint64_t m_src_size = m.src_size;
        uint64_t m_src_offset = m.src_offset;
        uint64_t m_src_hdr = m.src_hdr;
            archive(::cereal::make_nvp("range_set", m_range_set));
            archive(::cereal::make_nvp("src_size", m_src_size));
            archive(::cereal::make_nvp("src_offset", m_src_offset));
            archive(::cereal::make_nvp("src_hdr", m_src_hdr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_range_comp_profile_data_t& m) {
        uint64_t m_range_set;
        uint64_t m_src_size;
        uint64_t m_src_offset;
        uint64_t m_src_hdr;
            archive(::cereal::make_nvp("range_set", m_range_set));
            archive(::cereal::make_nvp("src_size", m_src_size));
            archive(::cereal::make_nvp("src_offset", m_src_offset));
            archive(::cereal::make_nvp("src_hdr", m_src_hdr));
        m.range_set = m_range_set;
        m.src_size = m_src_size;
        m.src_offset = m_src_offset;
        m.src_hdr = m_src_hdr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_range_comp_profile_data_t& m)
{
    serializer_class<npl_flc_range_comp_profile_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_range_comp_profile_data_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_range_comp_profile_data_t& m)
{
    serializer_class<npl_flc_range_comp_profile_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_range_comp_profile_data_t&);



template<>
class serializer_class<npl_flc_range_comp_profile_sel_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_range_comp_profile_sel_t& m) {
        uint64_t m_profile_selector = m.profile_selector;
            archive(::cereal::make_nvp("profile_selector", m_profile_selector));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_range_comp_profile_sel_t& m) {
        uint64_t m_profile_selector;
            archive(::cereal::make_nvp("profile_selector", m_profile_selector));
        m.profile_selector = m_profile_selector;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_range_comp_profile_sel_t& m)
{
    serializer_class<npl_flc_range_comp_profile_sel_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_range_comp_profile_sel_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_range_comp_profile_sel_t& m)
{
    serializer_class<npl_flc_range_comp_profile_sel_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_range_comp_profile_sel_t&);



template<>
class serializer_class<npl_flc_range_comp_ranges_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_range_comp_ranges_data_t& m) {
        uint64_t m_q_lower_limit = m.q_lower_limit;
        uint64_t m_q_upper_limit = m.q_upper_limit;
        uint64_t m_cache_lower_limit = m.cache_lower_limit;
        uint64_t m_cache_upper_limit = m.cache_upper_limit;
            archive(::cereal::make_nvp("q_lower_limit", m_q_lower_limit));
            archive(::cereal::make_nvp("q_upper_limit", m_q_upper_limit));
            archive(::cereal::make_nvp("cache_lower_limit", m_cache_lower_limit));
            archive(::cereal::make_nvp("cache_upper_limit", m_cache_upper_limit));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_range_comp_ranges_data_t& m) {
        uint64_t m_q_lower_limit;
        uint64_t m_q_upper_limit;
        uint64_t m_cache_lower_limit;
        uint64_t m_cache_upper_limit;
            archive(::cereal::make_nvp("q_lower_limit", m_q_lower_limit));
            archive(::cereal::make_nvp("q_upper_limit", m_q_upper_limit));
            archive(::cereal::make_nvp("cache_lower_limit", m_cache_lower_limit));
            archive(::cereal::make_nvp("cache_upper_limit", m_cache_upper_limit));
        m.q_lower_limit = m_q_lower_limit;
        m.q_upper_limit = m_q_upper_limit;
        m.cache_lower_limit = m_cache_lower_limit;
        m.cache_upper_limit = m_cache_upper_limit;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_range_comp_ranges_data_t& m)
{
    serializer_class<npl_flc_range_comp_ranges_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_range_comp_ranges_data_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_range_comp_ranges_data_t& m)
{
    serializer_class<npl_flc_range_comp_ranges_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_range_comp_ranges_data_t&);



template<>
class serializer_class<npl_flc_range_comp_ranges_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_range_comp_ranges_key_t& m) {
        uint64_t m_range_id_msb = m.range_id_msb;
        uint64_t m_range_id_lsb = m.range_id_lsb;
            archive(::cereal::make_nvp("range_id_msb", m_range_id_msb));
            archive(::cereal::make_nvp("range_id_lsb", m_range_id_lsb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_range_comp_ranges_key_t& m) {
        uint64_t m_range_id_msb;
        uint64_t m_range_id_lsb;
            archive(::cereal::make_nvp("range_id_msb", m_range_id_msb));
            archive(::cereal::make_nvp("range_id_lsb", m_range_id_lsb));
        m.range_id_msb = m_range_id_msb;
        m.range_id_lsb = m_range_id_lsb;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_range_comp_ranges_key_t& m)
{
    serializer_class<npl_flc_range_comp_ranges_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_range_comp_ranges_key_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_range_comp_ranges_key_t& m)
{
    serializer_class<npl_flc_range_comp_ranges_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_range_comp_ranges_key_t&);



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
class serializer_class<npl_ingress_qos_remark_t_anonymous_union_encap_qos_tag_u_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_qos_remark_t_anonymous_union_encap_qos_tag_u_t& m) {
        uint64_t m_encap_qos_tag = m.encap_qos_tag;
        uint64_t m_in_mpls_exp = m.in_mpls_exp;
            archive(::cereal::make_nvp("encap_qos_tag", m_encap_qos_tag));
            archive(::cereal::make_nvp("in_mpls_exp", m_in_mpls_exp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_qos_remark_t_anonymous_union_encap_qos_tag_u_t& m) {
        uint64_t m_encap_qos_tag;
        uint64_t m_in_mpls_exp;
            archive(::cereal::make_nvp("encap_qos_tag", m_encap_qos_tag));
            archive(::cereal::make_nvp("in_mpls_exp", m_in_mpls_exp));
        m.encap_qos_tag = m_encap_qos_tag;
        m.in_mpls_exp = m_in_mpls_exp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_qos_remark_t_anonymous_union_encap_qos_tag_u_t& m)
{
    serializer_class<npl_ingress_qos_remark_t_anonymous_union_encap_qos_tag_u_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_qos_remark_t_anonymous_union_encap_qos_tag_u_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_qos_remark_t_anonymous_union_encap_qos_tag_u_t& m)
{
    serializer_class<npl_ingress_qos_remark_t_anonymous_union_encap_qos_tag_u_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_qos_remark_t_anonymous_union_encap_qos_tag_u_t&);



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
class serializer_class<npl_ip_sgt_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_sgt_result_t& m) {
        uint64_t m_valid_group = m.valid_group;
        uint64_t m_security_group_tag = m.security_group_tag;
            archive(::cereal::make_nvp("valid_group", m_valid_group));
            archive(::cereal::make_nvp("security_group_tag", m_security_group_tag));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_sgt_result_t& m) {
        uint64_t m_valid_group;
        uint64_t m_security_group_tag;
            archive(::cereal::make_nvp("valid_group", m_valid_group));
            archive(::cereal::make_nvp("security_group_tag", m_security_group_tag));
        m.valid_group = m_valid_group;
        m.security_group_tag = m_security_group_tag;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_sgt_result_t& m)
{
    serializer_class<npl_ip_sgt_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_sgt_result_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_sgt_result_t& m)
{
    serializer_class<npl_ip_sgt_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_sgt_result_t&);



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
        uint64_t m_next_header_check = m.next_header_check;
            archive(::cereal::make_nvp("header_error", m_header_error));
            archive(::cereal::make_nvp("not_first_fragment", m_not_first_fragment));
            archive(::cereal::make_nvp("next_header_check", m_next_header_check));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_header_flags_t& m) {
        uint64_t m_header_error;
        uint64_t m_not_first_fragment;
        uint64_t m_next_header_check;
            archive(::cereal::make_nvp("header_error", m_header_error));
            archive(::cereal::make_nvp("not_first_fragment", m_not_first_fragment));
            archive(::cereal::make_nvp("next_header_check", m_next_header_check));
        m.header_error = m_header_error;
        m.not_first_fragment = m_not_first_fragment;
        m.next_header_check = m_next_header_check;
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



}

