
// This file has been automatically generated using nplc.py. Do not edit it manually.
// Version: 1.76.2_0.0.0.0 generated on devsrv15.leaba.local at 2021-05-12 16:04:51



#ifndef __NPL_TYPES_H__
#define __NPL_TYPES_H__

#include <stdint.h>

#include "nplapi/npl_enums.h"
#include "nplapi/npl_enum_to_string.h"
#include "common/bit_vector.h"
using silicon_one::bit_vector;
using silicon_one::bit_vector64_t;
using silicon_one::bit_vector128_t;
using silicon_one::bit_vector192_t;
using silicon_one::bit_vector384_t;

#pragma pack(push, 1)

struct field_structure;
typedef struct field_structure field_structure;
struct field_structure
{
    std::string field_type;
    std::string flat_value; //decimal value
    std::string to_string() const{
        return field_type + "= " + flat_value;
    }
    std::vector<std::pair<std::string, struct field_structure>> subfields;
    
};
std::string to_short_string(field_structure fs);
std::string to_hex_string(uint64_t value);
std::string to_string(field_structure fs);


struct npl_additional_mpls_labels_offset_t
{
    npl_ene_three_labels_jump_offset_e ene_three_labels_jump_offset;
    npl_ene_four_labels_jump_offset_e ene_four_labels_jump_offset;
    npl_ene_five_labels_jump_offset_e ene_five_labels_jump_offset;
    npl_ene_six_labels_jump_offset_e ene_six_labels_jump_offset;
    npl_ene_seven_labels_jump_offset_e ene_seven_labels_jump_offset;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_additional_mpls_labels_offset_t element);
std::string to_short_string(npl_additional_mpls_labels_offset_t element);


struct npl_all_reachable_vector_result_t
{
    npl_all_devices_reachable_e reachable[108];
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_all_reachable_vector_result_t element);
std::string to_short_string(npl_all_reachable_vector_result_t element);


struct npl_app_traps_t
{
    uint64_t sgacl_drop : 1;
    uint64_t sgacl_log : 1;
    uint64_t ip_inactivity : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_app_traps_t element);
std::string to_short_string(npl_app_traps_t element);


struct npl_aux_table_key_t
{
    uint64_t rd_address : 12;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_aux_table_key_t element);
std::string to_short_string(npl_aux_table_key_t element);


struct npl_aux_table_result_t
{
    uint64_t packet_header_type : 8;
    uint64_t count_phase : 8;
    uint64_t aux_data[3];
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_aux_table_result_t element);
std::string to_short_string(npl_aux_table_result_t element);


struct npl_base_voq_nr_t
{
    uint64_t val : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_base_voq_nr_t element);
std::string to_short_string(npl_base_voq_nr_t element);


struct npl_bd_attributes_t
{
    uint64_t sgacl_enforcement : 1;
    uint64_t l2_lpts_attributes : 6;
    uint64_t flush_all_macs : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bd_attributes_t element);
std::string to_short_string(npl_bd_attributes_t element);


struct npl_bfd_aux_ipv4_trans_payload_t
{
    uint64_t sip : 32;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_aux_ipv4_trans_payload_t element);
std::string to_short_string(npl_bfd_aux_ipv4_trans_payload_t element);


struct npl_bfd_aux_ipv6_trans_payload_t
{
    uint64_t ipv6_dip_b : 32;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_aux_ipv6_trans_payload_t element);
std::string to_short_string(npl_bfd_aux_ipv6_trans_payload_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_bfd_aux_transmit_payload_t_anonymous_union_prot_trans_t
{
    npl_bfd_aux_ipv4_trans_payload_t ipv4;
    npl_bfd_aux_ipv6_trans_payload_t ipv6;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_aux_transmit_payload_t_anonymous_union_prot_trans_t element);
std::string to_short_string(npl_bfd_aux_transmit_payload_t_anonymous_union_prot_trans_t element);


struct npl_bfd_em_t
{
    uint64_t rmep_id : 13;
    uint64_t mep_id : 13;
    uint64_t access_rmep : 1;
    uint64_t mp_data_select : 1;
    uint64_t access_mp : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_em_t element);
std::string to_short_string(npl_bfd_em_t element);


struct npl_bfd_flags_t
{
    uint64_t poll : 1;
    uint64_t final : 1;
    uint64_t ctrl_plane_independent : 1;
    uint64_t auth_present : 1;
    uint64_t demand : 1;
    uint64_t multipoint : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_flags_t element);
std::string to_short_string(npl_bfd_flags_t element);


struct npl_bfd_inject_ttl_t
{
    uint64_t ttl : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_inject_ttl_t element);
std::string to_short_string(npl_bfd_inject_ttl_t element);


struct npl_bfd_ipv4_prot_shared_t
{
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_ipv4_prot_shared_t element);
std::string to_short_string(npl_bfd_ipv4_prot_shared_t element);


struct npl_bfd_ipv6_prot_shared_t
{
    uint64_t ipv6_dip_c : 40;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_ipv6_prot_shared_t element);
std::string to_short_string(npl_bfd_ipv6_prot_shared_t element);


struct npl_bfd_ipv6_selector_t
{
    uint64_t data : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_ipv6_selector_t element);
std::string to_short_string(npl_bfd_ipv6_selector_t element);


struct npl_bfd_local_ipv6_sip_t
{
    uint64_t sip : 32;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_local_ipv6_sip_t element);
std::string to_short_string(npl_bfd_local_ipv6_sip_t element);


struct npl_bfd_mp_ipv4_transport_t
{
    uint64_t dip : 32;
    uint64_t checksum : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_mp_ipv4_transport_t element);
std::string to_short_string(npl_bfd_mp_ipv4_transport_t element);


struct npl_bfd_mp_ipv6_transport_t
{
    uint64_t ipv6_dip_a : 56;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_mp_ipv6_transport_t element);
std::string to_short_string(npl_bfd_mp_ipv6_transport_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_bfd_mp_table_shared_msb_t_anonymous_union_trans_data_t
{
    npl_bfd_mp_ipv4_transport_t ipv4;
    npl_bfd_mp_ipv6_transport_t ipv6;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_mp_table_shared_msb_t_anonymous_union_trans_data_t element);
std::string to_short_string(npl_bfd_mp_table_shared_msb_t_anonymous_union_trans_data_t element);


struct npl_bfd_mp_table_transmit_b_payload_t
{
    uint64_t local_state_and_flags : 8;
    uint64_t sip_selector : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_mp_table_transmit_b_payload_t element);
std::string to_short_string(npl_bfd_mp_table_transmit_b_payload_t element);


struct npl_bfd_transport_and_label_t
{
    npl_bfd_transport_e transport;
    uint64_t requires_label : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_transport_and_label_t element);
std::string to_short_string(npl_bfd_transport_and_label_t element);


struct npl_bool_t
{
    npl_bool_e val;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bool_t element);
std::string to_short_string(npl_bool_t element);


struct npl_burst_size_len_t
{
    uint64_t value : 18;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_burst_size_len_t element);
std::string to_short_string(npl_burst_size_len_t element);


struct npl_bvn_profile_t
{
    uint64_t lp_over_lag : 1;
    uint64_t tc_map_profile : 3;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bvn_profile_t element);
std::string to_short_string(npl_bvn_profile_t element);


struct npl_calc_checksum_enable_t
{
    uint64_t enable : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_calc_checksum_enable_t element);
std::string to_short_string(npl_calc_checksum_enable_t element);


struct npl_color_aware_mode_len_t
{
    uint64_t value : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_color_aware_mode_len_t element);
std::string to_short_string(npl_color_aware_mode_len_t element);


struct npl_color_len_t
{
    uint64_t value : 2;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_color_len_t element);
std::string to_short_string(npl_color_len_t element);


struct npl_common_cntr_5bits_offset_and_padding_t
{
    uint64_t offset : 5;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_common_cntr_5bits_offset_and_padding_t element);
std::string to_short_string(npl_common_cntr_5bits_offset_and_padding_t element);


struct npl_common_cntr_offset_t
{
    uint64_t base_cntr_offset : 3;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_common_cntr_offset_t element);
std::string to_short_string(npl_common_cntr_offset_t element);


struct npl_common_data_ecmp2_t
{
    uint64_t enc_type : 4;
    uint64_t te_tunnel14b_or_asbr : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_common_data_ecmp2_t element);
std::string to_short_string(npl_common_data_ecmp2_t element);


struct npl_common_data_prefix_t
{
    uint64_t te_tunnel16b : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_common_data_prefix_t element);
std::string to_short_string(npl_common_data_prefix_t element);


struct npl_compound_termination_control_t
{
    npl_append_relay_e append_relay;
    uint64_t attempt_termination : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_compound_termination_control_t element);
std::string to_short_string(npl_compound_termination_control_t element);


struct npl_compressed_counter_t
{
    uint64_t counter_idx : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_compressed_counter_t element);
std::string to_short_string(npl_compressed_counter_t element);


struct npl_counter_flag_t
{
    uint64_t num_labels_is_3 : 1;
    uint64_t pad : 19;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_counter_flag_t element);
std::string to_short_string(npl_counter_flag_t element);


struct npl_counter_offset_t
{
    uint64_t offset : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_counter_offset_t element);
std::string to_short_string(npl_counter_offset_t element);


struct npl_counter_ptr_t
{
    uint64_t update_or_read : 1;
    uint64_t cb_id : 6;
    uint64_t cb_set_base : 13;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_counter_ptr_t element);
std::string to_short_string(npl_counter_ptr_t element);


struct npl_counters_block_config_t
{
    uint64_t lm_count_and_read : 1;
    uint64_t reset_on_max_counter_read : 1;
    npl_counter_type_e bank_counter_type;
    uint64_t compensation : 7;
    uint64_t ignore_pd_compensation : 1;
    uint64_t wraparound : 1;
    uint64_t cpu_read_cc_wait_before_create_bubble : 6;
    uint64_t bank_pipe_client_allocation : 2;
    uint64_t bank_slice_allocation : 3;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_counters_block_config_t element);
std::string to_short_string(npl_counters_block_config_t element);


struct npl_counters_voq_block_map_result_t
{
    uint64_t map_groups_size : 2;
    uint64_t tc_profile : 1;
    uint64_t counter_offset : 14;
    uint64_t bank_id : 7;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_counters_voq_block_map_result_t element);
std::string to_short_string(npl_counters_voq_block_map_result_t element);


struct npl_curr_and_next_prot_type_t
{
    uint64_t current_proto_type : 4;
    uint64_t next_proto_type : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_curr_and_next_prot_type_t element);
std::string to_short_string(npl_curr_and_next_prot_type_t element);


struct npl_db_access_common_header_t
{
    uint64_t num_of_macros_to_perform : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_db_access_common_header_t element);
std::string to_short_string(npl_db_access_common_header_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_db_access_fwd_info_header_t_anonymous_union_macro_or_fwd_dest_t
{
    npl_db_access_common_header_t common_header;
    uint64_t fwd_dest : 20;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_db_access_fwd_info_header_t_anonymous_union_macro_or_fwd_dest_t element);
std::string to_short_string(npl_db_access_fwd_info_header_t_anonymous_union_macro_or_fwd_dest_t element);


struct npl_db_access_key_selectors_header_t
{
    uint64_t bucket_a_key_selector : 6;
    uint64_t bucket_b_key_selector : 6;
    uint64_t bucket_c_key_selector : 6;
    uint64_t bucket_d_key_selector : 6;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_db_access_key_selectors_header_t element);
std::string to_short_string(npl_db_access_key_selectors_header_t element);


struct npl_db_access_lu_data_t
{
    uint64_t check_result : 1;
    uint64_t expected_result : 8;
    uint64_t key : 20;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_db_access_lu_data_t element);
std::string to_short_string(npl_db_access_lu_data_t element);


struct npl_db_access_service_mapping_access_attr_t
{
    uint64_t key_lsbs : 6;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_db_access_service_mapping_access_attr_t element);
std::string to_short_string(npl_db_access_service_mapping_access_attr_t element);


struct npl_db_access_service_mapping_tcam_access_attr_t
{
    uint64_t key_lsbs : 6;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_db_access_service_mapping_tcam_access_attr_t element);
std::string to_short_string(npl_db_access_service_mapping_tcam_access_attr_t element);


struct npl_db_access_splitter_action_t
{
    uint64_t access_type : 2;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_db_access_splitter_action_t element);
std::string to_short_string(npl_db_access_splitter_action_t element);


struct npl_db_access_term_macro_dests_header_t
{
    npl_term_bucket_a_lu_dest_e bucket_a_lu_dest;
    npl_term_bucket_b_lu_dest_e bucket_b_lu_dest;
    npl_term_bucket_c_lu_dest_e bucket_c_lu_dest;
    npl_term_bucket_d_lu_dest_e bucket_d_lu_dest;
    npl_term_bucket_a_result_dest_e bucket_a_result_dest;
    npl_term_bucket_b_result_dest_e bucket_b_result_dest;
    npl_term_bucket_c_result_dest_e bucket_c_result_dest;
    npl_term_bucket_d_result_dest_e bucket_d_result_dest;
    npl_db_access_key_selectors_header_t db_access_key_selectors_header;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_db_access_term_macro_dests_header_t element);
std::string to_short_string(npl_db_access_term_macro_dests_header_t element);


struct npl_db_access_transmit_macro_dests_header_t
{
    npl_transmit_bucket_a_lu_dest_e bucket_a_lu_dest;
    npl_transmit_bucket_b_lu_dest_e bucket_b_lu_dest;
    npl_transmit_bucket_c_lu_dest_e bucket_c_lu_dest;
    npl_transmit_bucket_d_lu_dest_e bucket_d_lu_dest;
    npl_transmit_bucket_a_result_dest_e bucket_a_result_dest;
    npl_transmit_bucket_b_result_dest_e bucket_b_result_dest;
    npl_transmit_bucket_c_result_dest_e bucket_c_result_dest;
    npl_transmit_bucket_d_result_dest_e bucket_d_result_dest;
    npl_db_access_key_selectors_header_t db_access_key_selectors_header;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_db_access_transmit_macro_dests_header_t element);
std::string to_short_string(npl_db_access_transmit_macro_dests_header_t element);


struct npl_db_access_transmit_per_dest_port_npu_host_macro_stamping_t
{
    uint64_t npu_host_macro : 8;
    uint64_t stamp_npu_host_macro_on_packet : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_db_access_transmit_per_dest_port_npu_host_macro_stamping_t element);
std::string to_short_string(npl_db_access_transmit_per_dest_port_npu_host_macro_stamping_t element);


struct npl_db_access_tx_basic_header_t
{
    uint64_t num_of_macros_to_perform : 4;
    uint64_t num_of_ene_instructions_to_perform : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_db_access_tx_basic_header_t element);
std::string to_short_string(npl_db_access_tx_basic_header_t element);


struct npl_db_fc_tx_result_t
{
    uint64_t data : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_db_fc_tx_result_t element);
std::string to_short_string(npl_db_fc_tx_result_t element);


struct npl_dest_class_id_t
{
    uint64_t id : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_dest_class_id_t element);
std::string to_short_string(npl_dest_class_id_t element);


struct npl_dest_slice_voq_map_table_result_t
{
    uint64_t dest_slice_voq : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_dest_slice_voq_map_table_result_t element);
std::string to_short_string(npl_dest_slice_voq_map_table_result_t element);


struct npl_dest_with_class_id_t
{
    uint64_t dest_19_15 : 5;
    uint64_t has_class_id : 1;
    uint64_t dest_13_12 : 2;
    uint64_t class_id : 4;
    uint64_t dest_7_0 : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_dest_with_class_id_t element);
std::string to_short_string(npl_dest_with_class_id_t element);


struct npl_destination_t
{
    uint64_t val : 20;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_destination_t element);
std::string to_short_string(npl_destination_t element);


struct npl_device_mode_table_result_t
{
    uint64_t dev_mode : 2;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_device_mode_table_result_t element);
std::string to_short_string(npl_device_mode_table_result_t element);


struct npl_dip_index_t
{
    uint64_t dummy_index : 9;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_dip_index_t element);
std::string to_short_string(npl_dip_index_t element);


struct npl_dlp_profile_local_vars_t
{
    uint64_t dlp_type : 2;
    uint64_t dlp_mask : 4;
    uint64_t dlp_offset : 5;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_dlp_profile_local_vars_t element);
std::string to_short_string(npl_dlp_profile_local_vars_t element);


struct npl_dram_cgm_cgm_lut_results_t
{
    uint64_t dp1 : 1;
    uint64_t dp0 : 1;
    uint64_t mark1 : 1;
    uint64_t mark0 : 1;
    uint64_t set_aging : 1;
    uint64_t clr_aging : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_dram_cgm_cgm_lut_results_t element);
std::string to_short_string(npl_dram_cgm_cgm_lut_results_t element);


struct npl_drop_punt_or_permit_t
{
    uint64_t drop : 1;
    uint64_t force_punt : 1;
    uint64_t permit_count_enable : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_drop_punt_or_permit_t element);
std::string to_short_string(npl_drop_punt_or_permit_t element);


struct npl_dsp_group_policy_t
{
    uint64_t enable : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_dsp_group_policy_t element);
std::string to_short_string(npl_dsp_group_policy_t element);


struct npl_dsp_map_info_t
{
    uint64_t dsp_punt_rcy : 1;
    uint64_t dsp_is_scheduled_rcy : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_dsp_map_info_t element);
std::string to_short_string(npl_dsp_map_info_t element);


struct npl_egress_direct0_key_t
{
    uint64_t direct0_key : 12;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_egress_direct0_key_t element);
std::string to_short_string(npl_egress_direct0_key_t element);


struct npl_egress_direct1_key_t
{
    uint64_t direct1_key : 10;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_egress_direct1_key_t element);
std::string to_short_string(npl_egress_direct1_key_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_egress_qos_result_t_anonymous_union_remark_l3_t
{
    uint64_t enable_egress_remark : 1;
    uint64_t use_in_mpls_exp : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_egress_qos_result_t_anonymous_union_remark_l3_t element);
std::string to_short_string(npl_egress_qos_result_t_anonymous_union_remark_l3_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_egress_sec_acl_result_t_anonymous_union_drop_or_permit_t
{
    npl_counter_ptr_t drop_counter;
    npl_counter_ptr_t permit_ace_cntr;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_egress_sec_acl_result_t_anonymous_union_drop_or_permit_t element);
std::string to_short_string(npl_egress_sec_acl_result_t_anonymous_union_drop_or_permit_t element);


struct npl_em_common_data_raw_t
{
    uint64_t common_data : 20;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_em_common_data_raw_t element);
std::string to_short_string(npl_em_common_data_raw_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_em_common_data_t
{
    npl_common_data_ecmp2_t common_data_ecmp2;
    npl_common_data_prefix_t common_data_prefix;
    npl_em_common_data_raw_t raw;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_em_common_data_t element);
std::string to_short_string(npl_em_common_data_t element);


struct npl_em_result_dsp_host_t
{
    uint64_t dsp_or_dspa : 15;
    uint64_t host_mac : 48;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_em_result_dsp_host_t element);
std::string to_short_string(npl_em_result_dsp_host_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_em_result_dsp_host_w_class_t_anonymous_union_dest_type_or_has_class_t
{
    uint64_t dest_type : 3;
    uint64_t has_class : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_em_result_dsp_host_w_class_t_anonymous_union_dest_type_or_has_class_t element);
std::string to_short_string(npl_em_result_dsp_host_w_class_t_anonymous_union_dest_type_or_has_class_t element);


struct npl_em_result_dsp_host_wo_class_t
{
    uint64_t dest_type : 3;
    uint64_t dest : 12;
    uint64_t host_mac_msb : 7;
    uint64_t extra_dest_bit : 1;
    uint64_t host_mac_lsb : 40;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_em_result_dsp_host_wo_class_t element);
std::string to_short_string(npl_em_result_dsp_host_wo_class_t element);


struct npl_encap_mpls_exp_t
{
    uint64_t valid : 1;
    uint64_t exp : 3;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_encap_mpls_exp_t element);
std::string to_short_string(npl_encap_mpls_exp_t element);


struct npl_ene_macro_id_t
{
    npl_ene_macro_ids_e id;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ene_macro_id_t element);
std::string to_short_string(npl_ene_macro_id_t element);


struct npl_ene_no_bos_t
{
    uint64_t exp : 3;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ene_no_bos_t element);
std::string to_short_string(npl_ene_no_bos_t element);


struct npl_eth_mp_table_transmit_a_payload_t
{
    uint64_t tx_rdi : 1;
    npl_eth_oam_da_e ccm_da;
    uint64_t unicast_da : 48;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_eth_mp_table_transmit_a_payload_t element);
std::string to_short_string(npl_eth_mp_table_transmit_a_payload_t element);


struct npl_eth_mp_table_transmit_b_payload_t
{
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_eth_mp_table_transmit_b_payload_t element);
std::string to_short_string(npl_eth_mp_table_transmit_b_payload_t element);


struct npl_eth_rmep_app_t
{
    uint64_t rmep_rdi : 1;
    uint64_t rmep_loc : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_eth_rmep_app_t element);
std::string to_short_string(npl_eth_rmep_app_t element);


struct npl_eth_rmep_attributes_t
{
    npl_eth_rmep_app_t app;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_eth_rmep_attributes_t element);
std::string to_short_string(npl_eth_rmep_attributes_t element);


struct npl_eth_rtf_prop_over_fwd0_t
{
    npl_eth_table_index_e table_index;
    uint64_t acl_id : 7;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_eth_rtf_prop_over_fwd0_t element);
std::string to_short_string(npl_eth_rtf_prop_over_fwd0_t element);


struct npl_eth_rtf_prop_over_fwd1_t
{
    npl_eth_table_index_e table_index;
    uint64_t acl_id : 7;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_eth_rtf_prop_over_fwd1_t element);
std::string to_short_string(npl_eth_rtf_prop_over_fwd1_t element);


struct npl_ethernet_header_flags_t
{
    uint64_t da_is_bc : 1;
    uint64_t sa_is_mc : 1;
    uint64_t sa_eq_da : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ethernet_header_flags_t element);
std::string to_short_string(npl_ethernet_header_flags_t element);


struct npl_ethernet_oam_em_t
{
    uint64_t rmep_id : 13;
    uint64_t mep_id : 13;
    uint64_t access_rmep : 1;
    uint64_t mp_data_select : 1;
    uint64_t access_mp : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ethernet_oam_em_t element);
std::string to_short_string(npl_ethernet_oam_em_t element);


struct npl_ethernet_traps_t
{
    uint64_t acl_drop : 1;
    uint64_t acl_force_punt : 1;
    uint64_t vlan_membership : 1;
    uint64_t acceptable_format : 1;
    uint64_t no_service_mapping : 1;
    uint64_t no_termination_on_l3_port : 1;
    uint64_t no_sip_mapping : 1;
    uint64_t no_vni_mapping : 1;
    uint64_t no_vsid_mapping : 1;
    uint64_t arp : 1;
    uint64_t sa_da_error : 1;
    uint64_t sa_error : 1;
    uint64_t da_error : 1;
    uint64_t sa_multicast : 1;
    uint64_t dhcpv4_server : 1;
    uint64_t dhcpv4_client : 1;
    uint64_t dhcpv6_server : 1;
    uint64_t dhcpv6_client : 1;
    uint64_t ingress_stp_block : 1;
    uint64_t ptp_over_eth : 1;
    uint64_t isis_over_l2 : 1;
    uint64_t l2cp0 : 1;
    uint64_t l2cp1 : 1;
    uint64_t l2cp2 : 1;
    uint64_t l2cp3 : 1;
    uint64_t l2cp4 : 1;
    uint64_t l2cp5 : 1;
    uint64_t l2cp6 : 1;
    uint64_t l2cp7 : 1;
    uint64_t lacp : 1;
    uint64_t cisco_protocols : 1;
    uint64_t macsec : 1;
    uint64_t unknown_l3 : 1;
    uint64_t test_oam_ac_mep : 1;
    uint64_t test_oam_ac_mip : 1;
    uint64_t test_oam_cfm_link_mdl0 : 1;
    uint64_t system_mymac : 1;
    uint64_t unknown_bc : 1;
    uint64_t unknown_mc : 1;
    uint64_t unknown_uc : 1;
    uint64_t learn_punt : 1;
    uint64_t bcast_pkt : 1;
    uint64_t pfc_sample : 1;
    uint64_t hop_by_hop : 1;
    uint64_t l2_dlp_not_found : 1;
    uint64_t same_interface : 1;
    uint64_t dspa_mc_trim : 1;
    uint64_t egress_stp_block : 1;
    uint64_t split_horizon : 1;
    uint64_t disabled : 1;
    uint64_t incompatible_eve_cmd : 1;
    uint64_t padding_residue_in_second_line : 1;
    uint64_t pfc_direct_sample : 1;
    uint64_t svi_egress_dhcp : 1;
    uint64_t no_pwe_l3_dest : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ethernet_traps_t element);
std::string to_short_string(npl_ethernet_traps_t element);


struct npl_event_queue_address_t
{
    uint64_t address : 10;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_event_queue_address_t element);
std::string to_short_string(npl_event_queue_address_t element);


struct npl_event_to_send_t
{
    uint64_t rmep_last_time : 32;
    uint64_t rmep_id : 13;
    uint64_t rmep_state_table_data : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_event_to_send_t element);
std::string to_short_string(npl_event_to_send_t element);


struct npl_exact_bank_index_len_t
{
    uint64_t value : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_exact_bank_index_len_t element);
std::string to_short_string(npl_exact_bank_index_len_t element);


struct npl_exact_meter_index_len_t
{
    uint64_t value : 11;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_exact_meter_index_len_t element);
std::string to_short_string(npl_exact_meter_index_len_t element);


struct npl_exp_and_bos_t
{
    uint64_t exp : 3;
    uint64_t bos : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_exp_and_bos_t element);
std::string to_short_string(npl_exp_and_bos_t element);


struct npl_exp_bos_and_label_t
{
    npl_exp_and_bos_t label_exp_bos;
    uint64_t label : 20;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_exp_bos_and_label_t element);
std::string to_short_string(npl_exp_bos_and_label_t element);


struct npl_expanded_forward_response_t
{
    uint64_t dest : 20;
    uint64_t pad : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_expanded_forward_response_t element);
std::string to_short_string(npl_expanded_forward_response_t element);


struct npl_extended_encap_data2_t
{
    uint64_t ene_ipv6_dip_lsb : 48;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_extended_encap_data2_t element);
std::string to_short_string(npl_extended_encap_data2_t element);


struct npl_extended_encap_data_t
{
    uint64_t ene_ipv6_dip_msb[2];
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_extended_encap_data_t element);
std::string to_short_string(npl_extended_encap_data_t element);


struct npl_fabric_cfg_t
{
    uint64_t issu_codespace : 1;
    npl_plb_type_e plb_type;
    uint64_t device : 9;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fabric_cfg_t element);
std::string to_short_string(npl_fabric_cfg_t element);


struct npl_fabric_header_ctrl_sn_plb_t
{
    uint64_t link_fc : 1;
    uint64_t fcn : 1;
    uint64_t plb_ctxt : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fabric_header_ctrl_sn_plb_t element);
std::string to_short_string(npl_fabric_header_ctrl_sn_plb_t element);


struct npl_fabric_header_ctrl_ts_plb_t
{
    uint64_t link_fc : 1;
    uint64_t fcn : 1;
    npl_fabric_ts_plb_ctxt_e plb_ctxt;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fabric_header_ctrl_ts_plb_t element);
std::string to_short_string(npl_fabric_header_ctrl_ts_plb_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_fabric_header_start_template_t_anonymous_union_ctrl_t
{
    npl_fabric_header_ctrl_ts_plb_t ts_plb;
    npl_fabric_header_ctrl_sn_plb_t sn_plb;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fabric_header_start_template_t_anonymous_union_ctrl_t element);
std::string to_short_string(npl_fabric_header_start_template_t_anonymous_union_ctrl_t element);


struct npl_fabric_ibm_cmd_t
{
    uint64_t ibm_cmd_padding : 3;
    uint64_t ibm_cmd : 5;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fabric_ibm_cmd_t element);
std::string to_short_string(npl_fabric_ibm_cmd_t element);


struct npl_fabric_mc_ibm_cmd_t
{
    npl_npu_mirror_or_redirect_encap_type_e fabric_mc_encapsulation_type;
    uint64_t fabric_mc_ibm_cmd_padding : 3;
    uint64_t fabric_mc_ibm_cmd : 5;
    npl_punt_source_e fabric_mc_ibm_cmd_src;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fabric_mc_ibm_cmd_t element);
std::string to_short_string(npl_fabric_mc_ibm_cmd_t element);


struct npl_fabric_port_id_t
{
    uint64_t val : 7;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fabric_port_id_t element);
std::string to_short_string(npl_fabric_port_id_t element);


struct npl_fb_link_2_link_bundle_table_result_t
{
    uint64_t bundle_num : 6;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fb_link_2_link_bundle_table_result_t element);
std::string to_short_string(npl_fb_link_2_link_bundle_table_result_t element);


struct npl_fe_broadcast_bmp_table_result_t
{
    uint64_t links_bmp[2];
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fe_broadcast_bmp_table_result_t element);
std::string to_short_string(npl_fe_broadcast_bmp_table_result_t element);


struct npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_result_t
{
    uint64_t base_oq : 9;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_result_t element);
std::string to_short_string(npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_result_t element);


struct npl_fe_uc_bundle_selected_link_t
{
    uint64_t bundle_link : 7;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fe_uc_bundle_selected_link_t element);
std::string to_short_string(npl_fe_uc_bundle_selected_link_t element);


struct npl_fe_uc_link_bundle_desc_table_result_t
{
    uint64_t bundle_link_3_bc : 15;
    uint64_t bundle_link_3 : 7;
    uint64_t bundle_link_2_bc : 15;
    uint64_t bundle_link_2 : 7;
    uint64_t bundle_link_1_bc : 15;
    uint64_t bundle_link_1 : 7;
    uint64_t bundle_link_0_bc : 15;
    uint64_t bundle_link_0 : 7;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fe_uc_link_bundle_desc_table_result_t element);
std::string to_short_string(npl_fe_uc_link_bundle_desc_table_result_t element);


struct npl_fe_uc_random_fb_link_t
{
    uint64_t link_num : 7;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fe_uc_random_fb_link_t element);
std::string to_short_string(npl_fe_uc_random_fb_link_t element);


struct npl_fec_destination1_t
{
    uint64_t enc_type : 4;
    uint64_t destination : 20;
    npl_fec_entry_type_e type;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fec_destination1_t element);
std::string to_short_string(npl_fec_destination1_t element);


struct npl_fec_fec_destination_t
{
    uint64_t destination : 20;
    npl_fec_entry_type_e type;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fec_fec_destination_t element);
std::string to_short_string(npl_fec_fec_destination_t element);


struct npl_fec_raw_t
{
    uint64_t payload[2];
    npl_fec_entry_type_e type;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fec_raw_t element);
std::string to_short_string(npl_fec_raw_t element);


struct npl_fi_macro_config_data_t
{
    uint64_t tcam_key_inst1_offset : 5;
    uint64_t tcam_key_inst1_width : 6;
    uint64_t tcam_key_inst0_offset : 6;
    uint64_t tcam_key_inst0_width : 5;
    uint64_t alu_shift2 : 5;
    uint64_t alu_shift1 : 4;
    npl_fi_hardwired_logic_e hw_logic_select;
    uint64_t alu_mux2_select : 1;
    uint64_t alu_mux1_select : 1;
    uint64_t fs2_const : 8;
    uint64_t fs1_const : 8;
    uint64_t alu_fs2_valid_bits : 4;
    uint64_t alu_fs2_offset : 6;
    uint64_t alu_fs1_valid_bits : 4;
    uint64_t alu_fs1_offset : 6;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fi_macro_config_data_t element);
std::string to_short_string(npl_fi_macro_config_data_t element);


struct npl_fi_tcam_hardwired_result_t
{
    uint64_t start_new_layer : 1;
    uint64_t next_macro_id : 6;
    npl_protocol_type_e next_header_type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fi_tcam_hardwired_result_t element);
std::string to_short_string(npl_fi_tcam_hardwired_result_t element);


struct npl_filb_voq_mapping_result_t
{
    uint64_t packing_eligible : 1;
    uint64_t snr_plb_ss2dd : 4;
    uint64_t dest_oq : 9;
    uint64_t dest_slice : 3;
    uint64_t dest_dev : 9;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_filb_voq_mapping_result_t element);
std::string to_short_string(npl_filb_voq_mapping_result_t element);


struct npl_flc_header_types_array_key_t
{
    uint64_t source_port : 5;
    uint64_t ifg : 1;
    uint64_t recycle_code : 2;
    uint64_t fi_hdr_5to9 : 25;
    uint64_t fi_hdr_4to0 : 40;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_flc_header_types_array_key_t element);
std::string to_short_string(npl_flc_header_types_array_key_t element);


struct npl_flc_map_header_type_mask_id_data_t
{
    uint64_t mask_id : 5;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_flc_map_header_type_mask_id_data_t element);
std::string to_short_string(npl_flc_map_header_type_mask_id_data_t element);


struct npl_flc_map_header_type_mask_id_t
{
    uint64_t sel : 5;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_flc_map_header_type_mask_id_t element);
std::string to_short_string(npl_flc_map_header_type_mask_id_t element);


struct npl_flc_map_header_type_mask_l_data_t
{
    uint64_t cache_mask[5];
    uint64_t queue_mask[5];
    bit_vector pack(void) const;
    void unpack(bit_vector);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_flc_map_header_type_mask_l_data_t element);
std::string to_short_string(npl_flc_map_header_type_mask_l_data_t element);


struct npl_flc_map_header_type_mask_lm_key_t
{
    uint64_t sel : 3;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_flc_map_header_type_mask_lm_key_t element);
std::string to_short_string(npl_flc_map_header_type_mask_lm_key_t element);


struct npl_flc_map_header_type_mask_m_data_t
{
    uint64_t cache_mask[3];
    uint64_t queue_mask[3];
    bit_vector384_t pack(void) const;
    void unpack(bit_vector384_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_flc_map_header_type_mask_m_data_t element);
std::string to_short_string(npl_flc_map_header_type_mask_m_data_t element);


struct npl_flc_map_header_type_mask_s_data_t
{
    uint64_t cache_mask[2];
    uint64_t queue_mask[2];
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_flc_map_header_type_mask_s_data_t element);
std::string to_short_string(npl_flc_map_header_type_mask_s_data_t element);


struct npl_flc_map_header_type_mask_s_key_t
{
    uint64_t sel : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_flc_map_header_type_mask_s_key_t element);
std::string to_short_string(npl_flc_map_header_type_mask_s_key_t element);


struct npl_flc_range_comp_profile_data_t
{
    uint64_t range_set : 2;
    uint64_t src_size : 4;
    uint64_t src_offset : 6;
    uint64_t src_hdr : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_flc_range_comp_profile_data_t element);
std::string to_short_string(npl_flc_range_comp_profile_data_t element);


struct npl_flc_range_comp_profile_sel_t
{
    uint64_t profile_selector : 5;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_flc_range_comp_profile_sel_t element);
std::string to_short_string(npl_flc_range_comp_profile_sel_t element);


struct npl_flc_range_comp_ranges_data_t
{
    uint64_t q_lower_limit : 16;
    uint64_t q_upper_limit : 16;
    uint64_t cache_lower_limit : 16;
    uint64_t cache_upper_limit : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_flc_range_comp_ranges_data_t element);
std::string to_short_string(npl_flc_range_comp_ranges_data_t element);


struct npl_flc_range_comp_ranges_key_t
{
    uint64_t range_id_msb : 4;
    uint64_t range_id_lsb : 2;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_flc_range_comp_ranges_key_t element);
std::string to_short_string(npl_flc_range_comp_ranges_key_t element);


struct npl_frm_db_fabric_routing_table_result_t
{
    npl_fabric_port_can_reach_device_e fabric_routing_table_data[108];
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_frm_db_fabric_routing_table_result_t element);
std::string to_short_string(npl_frm_db_fabric_routing_table_result_t element);


struct npl_fwd_class_qos_group_t
{
    uint64_t fwd_class : 3;
    uint64_t qos_group : 5;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fwd_class_qos_group_t element);
std::string to_short_string(npl_fwd_class_qos_group_t element);


struct npl_fwd_layer_and_rtf_stage_compressed_fields_t
{
    npl_fwd_layer_e fwd_layer;
    npl_rtf_stage_e rtf_stage;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fwd_layer_and_rtf_stage_compressed_fields_t element);
std::string to_short_string(npl_fwd_layer_and_rtf_stage_compressed_fields_t element);


struct npl_fwd_qos_tag_dscp_t
{
    uint64_t dscp : 6;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fwd_qos_tag_dscp_t element);
std::string to_short_string(npl_fwd_qos_tag_dscp_t element);


struct npl_fwd_qos_tag_exp_or_qosgroup_t
{
    uint64_t exp_or_qos_group : 5;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fwd_qos_tag_exp_or_qosgroup_t element);
std::string to_short_string(npl_fwd_qos_tag_exp_or_qosgroup_t element);


struct npl_fwd_qos_tag_group_t
{
    uint64_t qos_group_id : 5;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fwd_qos_tag_group_t element);
std::string to_short_string(npl_fwd_qos_tag_group_t element);


struct npl_fwd_qos_tag_pcpdei_or_qosgroup_t
{
    uint64_t pcp_dei_or_qos_group : 5;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fwd_qos_tag_pcpdei_or_qosgroup_t element);
std::string to_short_string(npl_fwd_qos_tag_pcpdei_or_qosgroup_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_fwd_qos_tag_t
{
    npl_fwd_qos_tag_pcpdei_or_qosgroup_t l2;
    npl_fwd_qos_tag_dscp_t l3;
    npl_fwd_qos_tag_exp_or_qosgroup_t mpls;
    npl_fwd_qos_tag_group_t group;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fwd_qos_tag_t element);
std::string to_short_string(npl_fwd_qos_tag_t element);


struct npl_g_ifg_len_t
{
    uint64_t value : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_g_ifg_len_t element);
std::string to_short_string(npl_g_ifg_len_t element);


struct npl_gre_encap_data_t
{
    uint64_t flag_res_version : 16;
    uint64_t proto : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_gre_encap_data_t element);
std::string to_short_string(npl_gre_encap_data_t element);


struct npl_hw_mp_table_app_t
{
    uint64_t lm_count_phase_lsb : 2;
    uint64_t lm_period : 3;
    uint64_t ccm_count_phase_msb : 11;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_hw_mp_table_app_t element);
std::string to_short_string(npl_hw_mp_table_app_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_ibm_cmd_table_result_t_anonymous_union_voq_or_bitmap_t
{
    uint64_t base_voq : 16;
    uint64_t mc_bitmap : 6;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ibm_cmd_table_result_t_anonymous_union_voq_or_bitmap_t element);
std::string to_short_string(npl_ibm_cmd_table_result_t_anonymous_union_voq_or_bitmap_t element);


struct npl_ibm_enables_table_result_t
{
    uint64_t ibm_partial_mirror_packet_size : 14;
    uint64_t ibm_partial_mirror_en : 32;
    uint64_t ibm_enable_ive : 32;
    uint64_t ibm_enable_hw_termination : 32;
    uint64_t cud_ibm_offset : 40;
    uint64_t cud_has_ibm : 9;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ibm_enables_table_result_t element);
std::string to_short_string(npl_ibm_enables_table_result_t element);


struct npl_icmp_type_code_t
{
    uint64_t type : 8;
    uint64_t code : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_icmp_type_code_t element);
std::string to_short_string(npl_icmp_type_code_t element);


struct npl_ifg_len_t
{
    uint64_t value : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ifg_len_t element);
std::string to_short_string(npl_ifg_len_t element);


struct npl_ifg_t
{
    uint64_t index : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ifg_t element);
std::string to_short_string(npl_ifg_t element);


struct npl_ifgb_tc_lut_results_t
{
    uint64_t use_lut : 1;
    uint64_t data : 5;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ifgb_tc_lut_results_t element);
std::string to_short_string(npl_ifgb_tc_lut_results_t element);


struct npl_ingress_lpts_og_app_data_t
{
    uint64_t lpts_og_app_id : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ingress_lpts_og_app_data_t element);
std::string to_short_string(npl_ingress_lpts_og_app_data_t element);


struct npl_ingress_ptp_info_t
{
    npl_ptp_transport_type_e ptp_transport_type;
    uint64_t is_ptp_trans_sup : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ingress_ptp_info_t element);
std::string to_short_string(npl_ingress_ptp_info_t element);


struct npl_ingress_qos_mapping_remark_t
{
    uint64_t qos_group : 7;
    npl_encap_mpls_exp_t encap_mpls_exp;
    uint64_t enable_ingress_remark : 1;
    uint64_t fwd_qos_tag : 7;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ingress_qos_mapping_remark_t element);
std::string to_short_string(npl_ingress_qos_mapping_remark_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_ingress_qos_remark_t_anonymous_union_encap_qos_tag_u_t
{
    uint64_t encap_qos_tag : 7;
    uint64_t in_mpls_exp : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ingress_qos_remark_t_anonymous_union_encap_qos_tag_u_t element);
std::string to_short_string(npl_ingress_qos_remark_t_anonymous_union_encap_qos_tag_u_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_ingress_qos_result_t_anonymous_union_fwd_class_qos_group_u_t
{
    npl_fwd_class_qos_group_t fwd_class_qos_group;
    uint64_t qos_group_pd : 7;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ingress_qos_result_t_anonymous_union_fwd_class_qos_group_u_t element);
std::string to_short_string(npl_ingress_qos_result_t_anonymous_union_fwd_class_qos_group_u_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_initial_pd_nw_rx_data_t_anonymous_union_init_data_t
{
    uint64_t initial_npp_attributes_index : 8;
    uint64_t initial_slice_id : 3;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_initial_pd_nw_rx_data_t_anonymous_union_init_data_t element);
std::string to_short_string(npl_initial_pd_nw_rx_data_t_anonymous_union_init_data_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_initial_recycle_pd_nw_rx_data_t_anonymous_union_init_data_t
{
    uint64_t initial_npp_attributes_index : 8;
    uint64_t initial_slice_id : 3;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_initial_recycle_pd_nw_rx_data_t_anonymous_union_init_data_t element);
std::string to_short_string(npl_initial_recycle_pd_nw_rx_data_t_anonymous_union_init_data_t element);


struct npl_inject_header_type_t
{
    npl_inject_header_type_e inject_type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_header_type_t element);
std::string to_short_string(npl_inject_header_type_t element);


struct npl_inject_source_if_t
{
    uint64_t inject_ifg : 1;
    uint64_t inject_pif : 5;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_source_if_t element);
std::string to_short_string(npl_inject_source_if_t element);


struct npl_inject_up_destination_override_t
{
    npl_destination_t dest_override;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_up_destination_override_t element);
std::string to_short_string(npl_inject_up_destination_override_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_inject_up_eth_header_t_anonymous_union_from_port_t
{
    uint64_t up_ssp : 12;
    npl_inject_source_if_t up_source_if;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_up_eth_header_t_anonymous_union_from_port_t element);
std::string to_short_string(npl_inject_up_eth_header_t_anonymous_union_from_port_t element);


struct npl_inject_up_none_routable_mc_lpts_t
{
    uint64_t placeholder : 20;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_up_none_routable_mc_lpts_t element);
std::string to_short_string(npl_inject_up_none_routable_mc_lpts_t element);


struct npl_inject_up_vxlan_mc_t
{
    uint64_t placeholder : 28;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_up_vxlan_mc_t element);
std::string to_short_string(npl_inject_up_vxlan_mc_t element);


struct npl_internal_traps_t
{
    uint64_t l3_lpm_lpts : 1;
    uint64_t ipv4_non_routable_mc_routing : 1;
    uint64_t ipv4_non_routable_mc_bridging : 1;
    uint64_t ipv6_non_routable_mc_routing : 1;
    uint64_t ipv6_non_routable_mc_bridging : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_internal_traps_t element);
std::string to_short_string(npl_internal_traps_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_ip_lpm_result_t_anonymous_union_destination_or_default_t
{
    npl_destination_t destination;
    uint64_t is_default : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_lpm_result_t_anonymous_union_destination_or_default_t element);
std::string to_short_string(npl_ip_lpm_result_t_anonymous_union_destination_or_default_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_ip_lpm_result_t_anonymous_union_rtype_or_is_fec_t
{
    uint64_t rtype : 2;
    uint64_t is_fec : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_lpm_result_t_anonymous_union_rtype_or_is_fec_t element);
std::string to_short_string(npl_ip_lpm_result_t_anonymous_union_rtype_or_is_fec_t element);


struct npl_ip_prefix_destination_compound_results_t
{
    npl_destination_t ip_prefix_destination;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_prefix_destination_compound_results_t element);
std::string to_short_string(npl_ip_prefix_destination_compound_results_t element);


struct npl_ip_relay_egress_qos_key_pack_table_load_t
{
    npl_fwd_qos_tag_t muxed_qos_group;
    npl_fwd_qos_tag_t mapping_qos_fwd_qos_tag;
    npl_fwd_qos_tag_t mapping_qos_pd_tag;
    uint64_t zero_counter_ptr : 20;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_relay_egress_qos_key_pack_table_load_t element);
std::string to_short_string(npl_ip_relay_egress_qos_key_pack_table_load_t element);


struct npl_ip_rtf_iter_prop_over_fwd0_t
{
    npl_fwd0_table_index_e table_index;
    uint64_t acl_id : 7;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_rtf_iter_prop_over_fwd0_t element);
std::string to_short_string(npl_ip_rtf_iter_prop_over_fwd0_t element);


struct npl_ip_rtf_iter_prop_over_fwd1_t
{
    npl_fwd1_table_index_e table_index;
    uint64_t acl_id : 7;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_rtf_iter_prop_over_fwd1_t element);
std::string to_short_string(npl_ip_rtf_iter_prop_over_fwd1_t element);


struct npl_ip_rx_global_counter_t
{
    npl_counter_ptr_t tunnel_transit_counter_p;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_rx_global_counter_t element);
std::string to_short_string(npl_ip_rx_global_counter_t element);


struct npl_ip_sgt_result_t
{
    uint64_t valid_group : 1;
    uint64_t security_group_tag : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_sgt_result_t element);
std::string to_short_string(npl_ip_sgt_result_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_ip_tunnel_dip_t
{
    uint64_t ipv6_dip_index : 12;
    uint64_t ipv4_dip : 32;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_tunnel_dip_t element);
std::string to_short_string(npl_ip_tunnel_dip_t element);


struct npl_ip_ver_and_post_fwd_stage_t
{
    npl_ip_version_e ip_ver;
    npl_rtf_stage_and_type_e post_fwd_rtf_stage;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_ver_and_post_fwd_stage_t element);
std::string to_short_string(npl_ip_ver_and_post_fwd_stage_t element);


struct npl_ip_ver_mc_t
{
    npl_ip_version_e ip_version;
    npl_bool_t is_mc;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_ver_mc_t element);
std::string to_short_string(npl_ip_ver_mc_t element);


struct npl_ipv4_header_flags_t
{
    uint64_t header_error : 1;
    uint64_t fragmented : 1;
    uint64_t checksum_error : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ipv4_header_flags_t element);
std::string to_short_string(npl_ipv4_header_flags_t element);


struct npl_ipv4_ipv6_init_rtf_stage_t
{
    npl_init_rtf_stage_and_type_e ipv4_init_rtf_stage;
    npl_init_rtf_stage_and_type_e ipv6_init_rtf_stage;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ipv4_ipv6_init_rtf_stage_t element);
std::string to_short_string(npl_ipv4_ipv6_init_rtf_stage_t element);


struct npl_ipv4_sip_dip_t
{
    uint64_t sip : 32;
    uint64_t dip : 32;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ipv4_sip_dip_t element);
std::string to_short_string(npl_ipv4_sip_dip_t element);


struct npl_ipv4_traps_t
{
    uint64_t mc_forwarding_disabled : 1;
    uint64_t uc_forwarding_disabled : 1;
    uint64_t checksum : 1;
    uint64_t header_error : 1;
    uint64_t unknown_protocol : 1;
    uint64_t options_exist : 1;
    uint64_t non_comp_mc : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ipv4_traps_t element);
std::string to_short_string(npl_ipv4_traps_t element);


struct npl_ipv4_ttl_and_protocol_t
{
    uint64_t ttl : 8;
    uint64_t protocol : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ipv4_ttl_and_protocol_t element);
std::string to_short_string(npl_ipv4_ttl_and_protocol_t element);


struct npl_ipv6_header_flags_t
{
    uint64_t header_error : 1;
    uint64_t not_first_fragment : 1;
    uint64_t next_header_check : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ipv6_header_flags_t element);
std::string to_short_string(npl_ipv6_header_flags_t element);


struct npl_ipv6_next_header_and_hop_limit_t
{
    uint64_t next_header : 8;
    uint64_t hop_limit : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ipv6_next_header_and_hop_limit_t element);
std::string to_short_string(npl_ipv6_next_header_and_hop_limit_t element);


struct npl_ipv6_traps_t
{
    uint64_t mc_forwarding_disabled : 1;
    uint64_t uc_forwarding_disabled : 1;
    uint64_t hop_by_hop : 1;
    uint64_t header_error : 1;
    uint64_t illegal_sip : 1;
    uint64_t illegal_dip : 1;
    uint64_t zero_payload : 1;
    uint64_t next_header_check : 1;
    uint64_t non_comp_mc : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ipv6_traps_t element);
std::string to_short_string(npl_ipv6_traps_t element);


struct npl_is_inject_up_and_ip_first_fragment_t
{
    npl_bool_t is_inject_up_dest_override;
    npl_bool_t is_inject_up;
    npl_bool_t ip_first_fragment;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_is_inject_up_and_ip_first_fragment_t element);
std::string to_short_string(npl_is_inject_up_and_ip_first_fragment_t element);


struct npl_ive_enable_t
{
    uint64_t enable : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ive_enable_t element);
std::string to_short_string(npl_ive_enable_t element);


struct npl_l2_dlp_t
{
    uint64_t id : 18;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2_dlp_t element);
std::string to_short_string(npl_l2_dlp_t element);


struct npl_l2_global_slp_t
{
    uint64_t id : 18;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2_global_slp_t element);
std::string to_short_string(npl_l2_global_slp_t element);


struct npl_l2_lpts_attributes_t
{
    uint64_t mac_terminated : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2_lpts_attributes_t element);
std::string to_short_string(npl_l2_lpts_attributes_t element);


struct npl_l2_lpts_ip_fragment_t
{
    uint64_t v6_not_first_fragment : 1;
    uint64_t v4_not_first_fragment : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2_lpts_ip_fragment_t element);
std::string to_short_string(npl_l2_lpts_ip_fragment_t element);


struct npl_l2_lpts_next_macro_pack_fields_t
{
    uint64_t l2_lpts : 2;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2_lpts_next_macro_pack_fields_t element);
std::string to_short_string(npl_l2_lpts_next_macro_pack_fields_t element);


struct npl_l2_lpts_traps_t
{
    uint64_t trap0 : 1;
    uint64_t trap1 : 1;
    uint64_t trap2 : 1;
    uint64_t trap3 : 1;
    uint64_t trap4 : 1;
    uint64_t trap5 : 1;
    uint64_t trap6 : 1;
    uint64_t trap7 : 1;
    uint64_t trap8 : 1;
    uint64_t trap9 : 1;
    uint64_t trap10 : 1;
    uint64_t trap11 : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2_lpts_traps_t element);
std::string to_short_string(npl_l2_lpts_traps_t element);


struct npl_l2_relay_id_t
{
    uint64_t id : 14;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2_relay_id_t element);
std::string to_short_string(npl_l2_relay_id_t element);


struct npl_l2vpn_control_bits_t
{
    uint64_t enable_pwe_cntr : 1;
    uint64_t no_fat : 1;
    npl_l2vpn_cw_fat_exists_e cw_fat_exists;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2vpn_control_bits_t element);
std::string to_short_string(npl_l2vpn_control_bits_t element);


struct npl_l2vpn_label_encap_data_t
{
    npl_counter_ptr_t pwe_encap_cntr;
    uint64_t lp_profile : 2;
    npl_ene_macro_id_t first_ene_macro;
    uint64_t pwe_l2_dlp_id : 20;
    npl_l2vpn_control_bits_t l2vpn_control_bits;
    uint64_t label : 20;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2vpn_label_encap_data_t element);
std::string to_short_string(npl_l2vpn_label_encap_data_t element);


struct npl_l3_dlp_lsbs_t
{
    uint64_t l3_dlp_lsbs : 12;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_dlp_lsbs_t element);
std::string to_short_string(npl_l3_dlp_lsbs_t element);


struct npl_l3_dlp_msbs_t
{
    uint64_t l3_dlp_msbs : 2;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_dlp_msbs_t element);
std::string to_short_string(npl_l3_dlp_msbs_t element);


struct npl_l3_ecn_ctrl_t
{
    uint64_t count_cong_pkt : 1;
    uint64_t disable_ecn : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_ecn_ctrl_t element);
std::string to_short_string(npl_l3_ecn_ctrl_t element);


struct npl_l3_pfc_data_t
{
    uint64_t tc : 3;
    uint64_t dsp : 12;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_pfc_data_t element);
std::string to_short_string(npl_l3_pfc_data_t element);


struct npl_l3_relay_id_t
{
    uint64_t id : 12;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_relay_id_t element);
std::string to_short_string(npl_l3_relay_id_t element);


struct npl_l3_slp_lsbs_t
{
    uint64_t l3_slp_lsbs : 12;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_slp_lsbs_t element);
std::string to_short_string(npl_l3_slp_lsbs_t element);


struct npl_l3_slp_msbs_t
{
    uint64_t l3_slp_msbs : 2;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_slp_msbs_t element);
std::string to_short_string(npl_l3_slp_msbs_t element);


struct npl_l3_traps_t
{
    uint64_t ip_unicast_rpf : 1;
    uint64_t ip_multicast_rpf : 1;
    uint64_t ip_mc_drop : 1;
    uint64_t ip_mc_punt_dc_pass : 1;
    uint64_t ip_mc_snoop_dc_pass : 1;
    uint64_t ip_mc_snoop_rpf_fail : 1;
    uint64_t ip_mc_punt_rpf_fail : 1;
    uint64_t ip_mc_snoop_lookup_miss : 1;
    uint64_t ip_multicast_not_found : 1;
    uint64_t ip_mc_s_g_punt_member : 1;
    uint64_t ip_mc_g_punt_member : 1;
    uint64_t ip_mc_egress_punt : 1;
    uint64_t isis_over_l3 : 1;
    uint64_t isis_drain : 1;
    uint64_t no_hbm_access_dip : 1;
    uint64_t no_hbm_access_sip : 1;
    uint64_t lpm_error : 1;
    uint64_t lpm_drop : 1;
    uint64_t local_subnet : 1;
    uint64_t icmp_redirect : 1;
    uint64_t no_lp_over_lag_mapping : 1;
    uint64_t ingress_monitor : 1;
    uint64_t egress_monitor : 1;
    uint64_t acl_drop : 1;
    uint64_t acl_force_punt : 1;
    uint64_t acl_force_punt1 : 1;
    uint64_t acl_force_punt2 : 1;
    uint64_t acl_force_punt3 : 1;
    uint64_t acl_force_punt4 : 1;
    uint64_t acl_force_punt5 : 1;
    uint64_t acl_force_punt6 : 1;
    uint64_t acl_force_punt7 : 1;
    uint64_t glean_adj : 1;
    uint64_t drop_adj : 1;
    uint64_t drop_adj_non_inject : 1;
    uint64_t null_adj : 1;
    uint64_t user_trap1 : 1;
    uint64_t user_trap2 : 1;
    uint64_t lpm_default_drop : 1;
    uint64_t lpm_incomplete0 : 1;
    uint64_t lpm_incomplete2 : 1;
    uint64_t bfd_micro_ip_disabled : 1;
    uint64_t no_vni_mapping : 1;
    uint64_t no_hbm_access_og_sip : 1;
    uint64_t no_hbm_access_og_dip : 1;
    uint64_t no_l3_dlp_mapping : 1;
    uint64_t l3_dlp_disabled : 1;
    uint64_t split_horizon : 1;
    uint64_t mc_same_interface : 1;
    uint64_t no_vpn_label_found : 1;
    uint64_t ttl_or_hop_limit_is_one : 1;
    uint64_t tx_mtu_failure : 1;
    uint64_t tx_frr_drop : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_traps_t element);
std::string to_short_string(npl_l3_traps_t element);


struct npl_l4_ports_header_t
{
    uint64_t src_port : 16;
    uint64_t dst_port : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l4_ports_header_t element);
std::string to_short_string(npl_l4_ports_header_t element);


struct npl_large_em_label_encap_data_and_counter_ptr_t
{
    uint64_t num_labels : 1;
    npl_exp_bos_and_label_t label_encap;
    npl_counter_ptr_t counter_ptr;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_large_em_label_encap_data_and_counter_ptr_t element);
std::string to_short_string(npl_large_em_label_encap_data_and_counter_ptr_t element);


struct npl_lb_key_t
{
    uint64_t value : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lb_key_t element);
std::string to_short_string(npl_lb_key_t element);


struct npl_learn_manager_cfg_max_learn_type_t
{
    npl_system_local_learn_type_e lr_type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_learn_manager_cfg_max_learn_type_t element);
std::string to_short_string(npl_learn_manager_cfg_max_learn_type_t element);


struct npl_light_fi_stage_cfg_t
{
    uint64_t update_protocol_is_layer : 1;
    uint64_t update_current_header_info : 1;
    uint64_t size_width : 4;
    uint64_t size_offset : 6;
    uint64_t next_protocol_or_type_width : 3;
    uint64_t next_protocol_or_type_offset : 6;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_light_fi_stage_cfg_t element);
std::string to_short_string(npl_light_fi_stage_cfg_t element);


struct npl_link_up_vector_result_t
{
    npl_link_state_e link_up[108];
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_link_up_vector_result_t element);
std::string to_short_string(npl_link_up_vector_result_t element);


struct npl_lm_command_t
{
    uint64_t op : 4;
    uint64_t offset : 7;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lm_command_t element);
std::string to_short_string(npl_lm_command_t element);


struct npl_local_tx_ip_mapping_t
{
    uint64_t is_mpls_fwd : 1;
    uint64_t is_underlying_ip_proto : 1;
    uint64_t is_mapped_v4 : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_local_tx_ip_mapping_t element);
std::string to_short_string(npl_local_tx_ip_mapping_t element);


struct npl_lp_attr_update_raw_bits_t
{
    uint64_t update_12_bits : 12;
    uint64_t update_3_bits : 3;
    uint64_t update_65_bits[2];
    uint64_t update_q_m_counters : 40;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lp_attr_update_raw_bits_t element);
std::string to_short_string(npl_lp_attr_update_raw_bits_t element);


struct npl_lp_id_t
{
    uint64_t id : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lp_id_t element);
std::string to_short_string(npl_lp_id_t element);


struct npl_lp_rtf_conf_set_t
{
    uint64_t val : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lp_rtf_conf_set_t element);
std::string to_short_string(npl_lp_rtf_conf_set_t element);


struct npl_lpm_payload_t
{
    npl_dest_class_id_t class_id;
    npl_destination_t destination;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lpm_payload_t element);
std::string to_short_string(npl_lpm_payload_t element);


struct npl_lpm_prefix_fec_access_map_output_t
{
    uint64_t access_fec_table : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lpm_prefix_fec_access_map_output_t element);
std::string to_short_string(npl_lpm_prefix_fec_access_map_output_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_lpm_std_ip_em_lpm_result_destination_t_anonymous_union_union_for_padding_t
{
    npl_lpm_payload_t payload;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lpm_std_ip_em_lpm_result_destination_t_anonymous_union_union_for_padding_t element);
std::string to_short_string(npl_lpm_std_ip_em_lpm_result_destination_t_anonymous_union_union_for_padding_t element);


struct npl_lpts_cntr_and_lookup_index_t
{
    uint64_t meter_index_lsb : 7;
    uint64_t lpts_second_lookup_index : 5;
    npl_counter_ptr_t lpts_counter_ptr;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lpts_cntr_and_lookup_index_t element);
std::string to_short_string(npl_lpts_cntr_and_lookup_index_t element);


struct npl_lpts_flow_type_t
{
    uint64_t lpts_flow : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lpts_flow_type_t element);
std::string to_short_string(npl_lpts_flow_type_t element);


struct npl_lpts_packet_flags_t
{
    uint64_t established : 1;
    uint64_t skip_bfd_or_ttl_255 : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lpts_packet_flags_t element);
std::string to_short_string(npl_lpts_packet_flags_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_lpts_tcam_first_result_encap_data_msb_t_anonymous_union_encap_punt_code_t
{
    uint64_t mirror_or_redirect_code : 8;
    npl_fabric_ibm_cmd_t fabric_ibm_cmd;
    npl_lpts_reason_code_e lpts_reason;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lpts_tcam_first_result_encap_data_msb_t_anonymous_union_encap_punt_code_t element);
std::string to_short_string(npl_lpts_tcam_first_result_encap_data_msb_t_anonymous_union_encap_punt_code_t element);


struct npl_lr_fifo_register_t
{
    uint64_t address : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lr_fifo_register_t element);
std::string to_short_string(npl_lr_fifo_register_t element);


struct npl_lr_filter_fifo_register_t
{
    uint64_t address : 5;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lr_filter_fifo_register_t element);
std::string to_short_string(npl_lr_filter_fifo_register_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_lsp_encap_mapping_data_payload_t_anonymous_union_counter_and_flag_t
{
    npl_counter_flag_t counter_flag;
    npl_counter_ptr_t lsp_counter;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lsp_encap_mapping_data_payload_t_anonymous_union_counter_and_flag_t element);
std::string to_short_string(npl_lsp_encap_mapping_data_payload_t_anonymous_union_counter_and_flag_t element);


struct npl_lsp_impose_2_mpls_labels_ene_offset_t
{
    npl_lsp_two_labels_ene_jump_offset_e lsp_two_labels_ene_jump_offset;
    npl_lsp_one_label_ene_jump_offset_e lsp_one_label_ene_jump_offset;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lsp_impose_2_mpls_labels_ene_offset_t element);
std::string to_short_string(npl_lsp_impose_2_mpls_labels_ene_offset_t element);


struct npl_lsp_impose_mpls_labels_ene_offset_t
{
    npl_lsp_impose_2_mpls_labels_ene_offset_t lsp_impose_2_mpls_labels_ene_offset;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lsp_impose_mpls_labels_ene_offset_t element);
std::string to_short_string(npl_lsp_impose_mpls_labels_ene_offset_t element);


struct npl_lsp_labels_opt3_t
{
    uint64_t label_0 : 20;
    uint64_t label_1 : 20;
    uint64_t label_2 : 20;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lsp_labels_opt3_t element);
std::string to_short_string(npl_lsp_labels_opt3_t element);


struct npl_lsp_labels_t
{
    uint64_t label_0 : 20;
    uint64_t label_1 : 20;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lsp_labels_t element);
std::string to_short_string(npl_lsp_labels_t element);


struct npl_lsp_type_t
{
    uint64_t destination_encoding : 2;
    uint64_t vpn : 1;
    uint64_t inter_as : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lsp_type_t element);
std::string to_short_string(npl_lsp_type_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_lsr_encap_t_anonymous_union_lsp_t
{
    uint64_t swap_label : 20;
    uint64_t lsp_id : 20;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lsr_encap_t_anonymous_union_lsp_t element);
std::string to_short_string(npl_lsr_encap_t_anonymous_union_lsp_t element);


struct npl_mac_addr_t
{
    uint64_t mac_address : 48;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_addr_t element);
std::string to_short_string(npl_mac_addr_t element);


struct npl_mac_da_t
{
    uint64_t is_vrrp : 1;
    uint64_t mac_l2_lpts_lkup : 1;
    uint64_t use_l2_lpts : 1;
    uint64_t prefix : 5;
    npl_compound_termination_control_t compound_termination_control;
    uint64_t is_mc : 1;
    uint64_t is_ipv4_mc : 1;
    uint64_t is_ipv6_mc : 1;
    npl_mac_da_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_da_t element);
std::string to_short_string(npl_mac_da_t element);


struct npl_mac_da_tos_pack_payload_t
{
    uint64_t eth_type : 16;
    uint64_t mac_da : 48;
    uint64_t v4_ttl : 8;
    uint64_t v6_ttl : 8;
    uint64_t hln : 4;
    uint64_t tos : 8;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_da_tos_pack_payload_t element);
std::string to_short_string(npl_mac_da_tos_pack_payload_t element);


struct npl_mac_l2_relay_attributes_t
{
    npl_bd_attributes_t bd_attributes;
    npl_destination_t flood_destination;
    uint64_t drop_unknown_bc : 1;
    uint64_t drop_unknown_mc : 1;
    uint64_t drop_unknown_uc : 1;
    uint64_t mld_snooping : 1;
    uint64_t igmp_snooping : 1;
    uint64_t is_svi : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_l2_relay_attributes_t element);
std::string to_short_string(npl_mac_l2_relay_attributes_t element);


struct npl_mac_l3_remark_pack_payload_t
{
    uint64_t ipv6_tos : 8;
    uint64_t ipv4_tos : 8;
    uint64_t mpls_exp_bos : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_l3_remark_pack_payload_t element);
std::string to_short_string(npl_mac_l3_remark_pack_payload_t element);


struct npl_mac_metadata_em_pad_t
{
    uint64_t pad : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_metadata_em_pad_t element);
std::string to_short_string(npl_mac_metadata_em_pad_t element);


struct npl_mac_metadata_t
{
    npl_dest_class_id_t class_id;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_metadata_t element);
std::string to_short_string(npl_mac_metadata_t element);


struct npl_mac_relay_g_destination_pad_t
{
    npl_destination_t dest;
    uint64_t pad : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_relay_g_destination_pad_t element);
std::string to_short_string(npl_mac_relay_g_destination_pad_t element);


struct npl_mac_relay_g_destination_t
{
    npl_destination_t destination;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_relay_g_destination_t element);
std::string to_short_string(npl_mac_relay_g_destination_t element);


struct npl_mact_result_t
{
    uint64_t application_specific_fields : 12;
    npl_destination_t destination;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mact_result_t element);
std::string to_short_string(npl_mact_result_t element);


struct npl_mapping_qos_tag_packed_result_t
{
    uint64_t fwd_hdr_type_v6 : 1;
    uint64_t mapping_qos_tag : 7;
    npl_ene_macro_id_t eth_ene_macro_id;
    uint64_t el_label_exp_bos_inner_label_bos_1 : 8;
    uint64_t el_label_exp_bos_inner_label_bos_0 : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mapping_qos_tag_packed_result_t element);
std::string to_short_string(npl_mapping_qos_tag_packed_result_t element);


struct npl_mc_bitmap_base_voq_lookup_table_result_t
{
    uint64_t tc_map_profile : 2;
    uint64_t base_voq : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mc_bitmap_base_voq_lookup_table_result_t element);
std::string to_short_string(npl_mc_bitmap_base_voq_lookup_table_result_t element);


struct npl_mc_bitmap_t
{
    uint64_t bitmap_indicator : 5;
    uint64_t bitmap : 6;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mc_bitmap_t element);
std::string to_short_string(npl_mc_bitmap_t element);


struct npl_mc_copy_id_t
{
    uint64_t val : 18;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mc_copy_id_t element);
std::string to_short_string(npl_mc_copy_id_t element);


struct npl_mc_em_db__key_t
{
    uint64_t is_tx : 1;
    uint64_t slice_or_is_fabric : 3;
    uint64_t is_rcy : 1;
    uint64_t mcid : 16;
    uint64_t entry_index : 11;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mc_em_db__key_t element);
std::string to_short_string(npl_mc_em_db__key_t element);


struct npl_mc_em_db_result_tx_format_1_t
{
    uint64_t copy_bitmap : 48;
    uint64_t bmp_map_profile : 2;
    uint64_t tc_map_profile : 3;
    uint64_t mc_copy_id : 18;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mc_em_db_result_tx_format_1_t element);
std::string to_short_string(npl_mc_em_db_result_tx_format_1_t element);


struct npl_mc_fe_links_bmp_db_result_t
{
    uint64_t use_bitmap_directly : 1;
    uint64_t fe_links_bmp[2];
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mc_fe_links_bmp_db_result_t element);
std::string to_short_string(npl_mc_fe_links_bmp_db_result_t element);


struct npl_mc_macro_compressed_fields_t
{
    uint64_t is_inject_up : 1;
    uint64_t not_comp_single_src : 1;
    npl_protocol_type_e curr_proto_type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mc_macro_compressed_fields_t element);
std::string to_short_string(npl_mc_macro_compressed_fields_t element);


struct npl_mc_rx_tc_map_profile_t
{
    uint64_t val : 2;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mc_rx_tc_map_profile_t element);
std::string to_short_string(npl_mc_rx_tc_map_profile_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_mc_slice_bitmap_table_entry_t_anonymous_union_group_size_or_bitmap_t
{
    uint64_t group_size : 11;
    npl_mc_bitmap_t mc_bitmap;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mc_slice_bitmap_table_entry_t_anonymous_union_group_size_or_bitmap_t element);
std::string to_short_string(npl_mc_slice_bitmap_table_entry_t_anonymous_union_group_size_or_bitmap_t element);


struct npl_mc_tx_tc_map_profile_t
{
    uint64_t val : 3;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mc_tx_tc_map_profile_t element);
std::string to_short_string(npl_mc_tx_tc_map_profile_t element);


struct npl_mcid_t
{
    uint64_t id : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mcid_t element);
std::string to_short_string(npl_mcid_t element);


struct npl_meg_id_t
{
    uint64_t id[2];
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_meg_id_t element);
std::string to_short_string(npl_meg_id_t element);


struct npl_meter_action_profile_len_t
{
    uint64_t value : 2;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_meter_action_profile_len_t element);
std::string to_short_string(npl_meter_action_profile_len_t element);


struct npl_meter_count_mode_len_t
{
    uint64_t value : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_meter_count_mode_len_t element);
std::string to_short_string(npl_meter_count_mode_len_t element);


struct npl_meter_mode_len_t
{
    uint64_t value : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_meter_mode_len_t element);
std::string to_short_string(npl_meter_mode_len_t element);


struct npl_meter_profile_len_t
{
    uint64_t value : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_meter_profile_len_t element);
std::string to_short_string(npl_meter_profile_len_t element);


struct npl_meter_weight_t
{
    uint64_t weight_factor : 5;
    uint64_t weight : 5;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_meter_weight_t element);
std::string to_short_string(npl_meter_weight_t element);


struct npl_mii_loopback_data_t
{
    npl_loopback_mode_e mode;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mii_loopback_data_t element);
std::string to_short_string(npl_mii_loopback_data_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_minimal_l3_lp_attributes_t_anonymous_union_disable_mpls_or_mc_tunnel_t
{
    uint64_t disable_mpls : 1;
    uint64_t disable_mc_tunnel_decap : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_minimal_l3_lp_attributes_t_anonymous_union_disable_mpls_or_mc_tunnel_t element);
std::string to_short_string(npl_minimal_l3_lp_attributes_t_anonymous_union_disable_mpls_or_mc_tunnel_t element);


struct npl_mismatch_indications_t
{
    uint64_t issu_codespace : 1;
    uint64_t first_packet_size : 1;
    uint64_t is_single_fragment : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mismatch_indications_t element);
std::string to_short_string(npl_mismatch_indications_t element);


struct npl_mldp_protection_entry_t
{
    npl_bool_t drop_protect;
    npl_bool_t drop_primary;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mldp_protection_entry_t element);
std::string to_short_string(npl_mldp_protection_entry_t element);


struct npl_mldp_protection_id_t
{
    uint64_t id : 9;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mldp_protection_id_t element);
std::string to_short_string(npl_mldp_protection_id_t element);


struct npl_mldp_protection_t
{
    npl_mldp_protection_id_t id;
    npl_resolution_protection_selector_e sel;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mldp_protection_t element);
std::string to_short_string(npl_mldp_protection_t element);


struct npl_more_labels_index_t
{
    uint64_t more_labels_index : 12;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_more_labels_index_t element);
std::string to_short_string(npl_more_labels_index_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_mp_table_app_t_anonymous_union_mp2_data_union_t
{
    npl_eth_mp_table_transmit_b_payload_t transmit_b;
    npl_bfd_mp_table_transmit_b_payload_t bfd2;
    npl_hw_mp_table_app_t hw;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mp_table_app_t_anonymous_union_mp2_data_union_t element);
std::string to_short_string(npl_mp_table_app_t_anonymous_union_mp2_data_union_t element);


struct npl_mpls_encap_control_bits_t
{
    uint64_t is_midpoint : 1;
    uint64_t mpls_labels_lookup : 1;
    uint64_t is_asbr_or_ldpote : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mpls_encap_control_bits_t element);
std::string to_short_string(npl_mpls_encap_control_bits_t element);


struct npl_mpls_first_ene_macro_control_t
{
    uint64_t no_first_ene_macro : 1;
    uint64_t vpn_label_lookup : 1;
    npl_qos_first_macro_code_e qos_first_macro_code;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mpls_first_ene_macro_control_t element);
std::string to_short_string(npl_mpls_first_ene_macro_control_t element);


struct npl_mpls_header_flags_t
{
    uint64_t illegal_ipv4 : 1;
    uint64_t is_null_labels : 1;
    uint64_t is_bos : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mpls_header_flags_t element);
std::string to_short_string(npl_mpls_header_flags_t element);


struct npl_mpls_header_t
{
    uint64_t label : 20;
    uint64_t exp : 3;
    uint64_t bos : 1;
    uint64_t ttl : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mpls_header_t element);
std::string to_short_string(npl_mpls_header_t element);


struct npl_mpls_relay_packed_labels_t
{
    uint64_t adjust_next_hdr_offset : 8;
    npl_mpls_header_t label_above_null;
    uint64_t next_label_above_null : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mpls_relay_packed_labels_t element);
std::string to_short_string(npl_mpls_relay_packed_labels_t element);


struct npl_mpls_termination_mldp_t
{
    uint64_t rpf_id : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mpls_termination_mldp_t element);
std::string to_short_string(npl_mpls_termination_mldp_t element);


struct npl_mpls_tp_em_t
{
    uint64_t dummy : 40;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mpls_tp_em_t element);
std::string to_short_string(npl_mpls_tp_em_t element);


struct npl_mpls_traps_t
{
    uint64_t unknown_protocol_after_bos : 1;
    uint64_t ttl_is_zero : 1;
    uint64_t bfd_over_pwe_ttl : 1;
    uint64_t bfd_over_pwe_raw : 1;
    uint64_t bfd_over_pwe_ipv4 : 1;
    uint64_t bfd_over_pwe_ipv6 : 1;
    uint64_t unknown_bfd_g_ach_channel_type : 1;
    uint64_t bfd_over_pwe_ra : 1;
    uint64_t mpls_tp_over_pwe : 1;
    uint64_t unknown_g_ach : 1;
    uint64_t mpls_tp_over_lsp : 1;
    uint64_t oam_alert_label : 1;
    uint64_t extension_label : 1;
    uint64_t router_alert_label : 1;
    uint64_t unexpected_reserved_label : 1;
    uint64_t forwarding_disabled : 1;
    uint64_t ilm_miss : 1;
    uint64_t ipv4_over_ipv6_explicit_null : 1;
    uint64_t invalid_ttl : 1;
    uint64_t te_midpopint_ldp_labels_miss : 1;
    uint64_t asbr_label_miss : 1;
    uint64_t ilm_vrf_label_miss : 1;
    uint64_t pwe_pwach : 1;
    uint64_t vpn_ttl_one : 1;
    uint64_t missing_fwd_label_after_pop : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mpls_traps_t element);
std::string to_short_string(npl_mpls_traps_t element);


struct npl_ms_voq_fabric_context_offset_table_result_t
{
    uint64_t ms_voq_fabric_context_offset : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ms_voq_fabric_context_offset_table_result_t element);
std::string to_short_string(npl_ms_voq_fabric_context_offset_table_result_t element);


struct npl_my_dummy_result_t
{
    uint64_t val : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_my_dummy_result_t element);
std::string to_short_string(npl_my_dummy_result_t element);


struct npl_my_frag_max_result_128_t
{
    uint64_t val[2];
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_my_frag_max_result_128_t element);
std::string to_short_string(npl_my_frag_max_result_128_t element);


struct npl_my_one_bit_result_t
{
    uint64_t val : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_my_one_bit_result_t element);
std::string to_short_string(npl_my_one_bit_result_t element);


struct npl_next_header_and_hop_limit_t
{
    uint64_t next_header : 8;
    uint64_t hop_limit : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_next_header_and_hop_limit_t element);
std::string to_short_string(npl_next_header_and_hop_limit_t element);


struct npl_nhlfe_type_attributes_t
{
    npl_npu_encap_l3_header_type_e encap_type;
    npl_destination_t midpoint_nh_destination_encoding;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_nhlfe_type_attributes_t element);
std::string to_short_string(npl_nhlfe_type_attributes_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_npl_internal_info_t
{
    uint64_t tx_redirect_code : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npl_internal_info_t element);
std::string to_short_string(npl_npl_internal_info_t element);


struct npl_npp_sgt_map_header_t
{
    uint64_t security_group : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npp_sgt_map_header_t element);
std::string to_short_string(npl_npp_sgt_map_header_t element);


struct npl_npu_app_pack_fields_t
{
    uint64_t force_pipe_ttl : 1;
    npl_is_inject_up_and_ip_first_fragment_t is_inject_up_and_ip_first_fragment;
    uint64_t ttl : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npu_app_pack_fields_t element);
std::string to_short_string(npl_npu_app_pack_fields_t element);


struct npl_npu_encap_header_l2_dlp_t
{
    npl_l2_dlp_t l2_dlp;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npu_encap_header_l2_dlp_t element);
std::string to_short_string(npl_npu_encap_header_l2_dlp_t element);


struct npl_npu_host_data_result_count_phase_t
{
    uint64_t mp_data[3];
    uint64_t dm_count_phase : 12;
    uint64_t dm_period : 3;
    uint64_t lm_count_phase : 12;
    uint64_t lm_period : 3;
    uint64_t ccm_count_phase : 12;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npu_host_data_result_count_phase_t element);
std::string to_short_string(npl_npu_host_data_result_count_phase_t element);


struct npl_npu_l3_mc_accounting_encap_data_t
{
    npl_counter_ptr_t mcg_counter_ptr;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npu_l3_mc_accounting_encap_data_t element);
std::string to_short_string(npl_npu_l3_mc_accounting_encap_data_t element);


struct npl_num_labels_t
{
    uint64_t total_num_labels : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_num_labels_t element);
std::string to_short_string(npl_num_labels_t element);


struct npl_num_outer_transport_labels_t
{
    uint64_t total_num_labels : 4;
    uint64_t num_labels_is_3 : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_num_outer_transport_labels_t element);
std::string to_short_string(npl_num_outer_transport_labels_t element);


struct npl_oamp_traps_t
{
    uint64_t eth_unknown_punt_reason : 1;
    uint64_t eth_mep_mapping_failed : 1;
    uint64_t eth_mp_type_mismatch : 1;
    uint64_t eth_meg_level_mismatch : 1;
    uint64_t eth_bad_md_name_format : 1;
    uint64_t eth_unicast_da_no_match : 1;
    uint64_t eth_multicast_da_no_match : 1;
    uint64_t eth_wrong_meg_id_format : 1;
    uint64_t eth_meg_id_no_match : 1;
    uint64_t eth_ccm_period_no_match : 1;
    uint64_t eth_ccm_tlv_no_match : 1;
    uint64_t eth_lmm_tlv_no_match : 1;
    uint64_t eth_not_supported_oam_opcode : 1;
    uint64_t bfd_transport_not_supported : 1;
    uint64_t bfd_session_lookup_failed : 1;
    uint64_t bfd_incorrect_ttl : 1;
    uint64_t bfd_invalid_protocol : 1;
    uint64_t bfd_invalid_udp_port : 1;
    uint64_t bfd_incorrect_version : 1;
    uint64_t bfd_incorrect_address : 1;
    uint64_t bfd_mismatch_discr : 1;
    uint64_t bfd_state_flag_change : 1;
    uint64_t bfd_session_received : 1;
    uint64_t pfc_lookup_failed : 1;
    uint64_t pfc_drop_invalid_rx : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_oamp_traps_t element);
std::string to_short_string(npl_oamp_traps_t element);


struct npl_obm_to_inject_packed_vars_t
{
    uint64_t redirect_code : 8;
    uint64_t l2_slp : 20;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_obm_to_inject_packed_vars_t element);
std::string to_short_string(npl_obm_to_inject_packed_vars_t element);


struct npl_og_lpm_compression_code_t
{
    uint64_t bits_n_18 : 6;
    uint64_t zero : 1;
    uint64_t bits_17_0 : 18;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_og_lpm_compression_code_t element);
std::string to_short_string(npl_og_lpm_compression_code_t element);


struct npl_og_lpts_compression_code_t
{
    uint64_t id : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_og_lpts_compression_code_t element);
std::string to_short_string(npl_og_lpts_compression_code_t element);


struct npl_og_pcl_compress_t
{
    uint64_t src_compress : 1;
    uint64_t dest_compress : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_og_pcl_compress_t element);
std::string to_short_string(npl_og_pcl_compress_t element);


struct npl_og_pcl_id_t
{
    uint64_t val : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_og_pcl_id_t element);
std::string to_short_string(npl_og_pcl_id_t element);


struct npl_og_pcl_ids_t
{
    npl_og_pcl_id_t src_pcl_id;
    npl_og_pcl_id_t dest_pcl_id;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_og_pcl_ids_t element);
std::string to_short_string(npl_og_pcl_ids_t element);


struct npl_og_pd_compression_code_t
{
    uint64_t bits_n_18 : 6;
    uint64_t bits_17_0 : 18;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_og_pd_compression_code_t element);
std::string to_short_string(npl_og_pd_compression_code_t element);


struct npl_omd_txpp_parsed_t
{
    uint64_t oq_pair : 2;
    uint64_t pif : 5;
    uint64_t ifg : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_omd_txpp_parsed_t element);
std::string to_short_string(npl_omd_txpp_parsed_t element);


struct npl_oq_group_t
{
    uint64_t val : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_oq_group_t element);
std::string to_short_string(npl_oq_group_t element);


struct npl_oqse_pair_t
{
    uint64_t index : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_oqse_pair_t element);
std::string to_short_string(npl_oqse_pair_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_oqse_topology_4p_t
{
    npl_oqse_topology_4p_e lpse_tpse_4p;
    npl_oqse_topology_2p_e lpse_2p;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_oqse_topology_4p_t element);
std::string to_short_string(npl_oqse_topology_4p_t element);


struct npl_overlay_nh_data_t
{
    uint64_t mac_da : 48;
    uint64_t sa_prefix_index : 4;
    uint64_t sa_lsb : 16;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_overlay_nh_data_t element);
std::string to_short_string(npl_overlay_nh_data_t element);


struct npl_override_enable_ipv4_ipv6_uc_bits_t
{
    uint64_t override_enable_ipv4_uc : 1;
    uint64_t override_enable_ipv6_uc : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_override_enable_ipv4_ipv6_uc_bits_t element);
std::string to_short_string(npl_override_enable_ipv4_ipv6_uc_bits_t element);


struct npl_packed_ud_160_key_t
{
    uint64_t key[3];
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_packed_ud_160_key_t element);
std::string to_short_string(npl_packed_ud_160_key_t element);


struct npl_packed_ud_320_key_t
{
    npl_packed_ud_160_key_t key_part0;
    npl_packed_ud_160_key_t key_part1;
    bit_vector384_t pack(void) const;
    void unpack(bit_vector384_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_packed_ud_320_key_t element);
std::string to_short_string(npl_packed_ud_320_key_t element);


struct npl_padding_for_sm_tcam_t
{
    uint64_t junk[2];
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_padding_for_sm_tcam_t element);
std::string to_short_string(npl_padding_for_sm_tcam_t element);


struct npl_padding_or_ipv6_len_t
{
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_padding_or_ipv6_len_t element);
std::string to_short_string(npl_padding_or_ipv6_len_t element);


struct npl_pbts_map_result_t
{
    uint64_t pbts_offset : 3;
    uint64_t destination_shift : 2;
    uint64_t and_mask : 18;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pbts_map_result_t element);
std::string to_short_string(npl_pbts_map_result_t element);


struct npl_pcp_dei_t
{
    uint64_t pcp : 3;
    uint64_t dei : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pcp_dei_t element);
std::string to_short_string(npl_pcp_dei_t element);


struct npl_pd_lp_attributes_t
{
    npl_lp_attr_update_raw_bits_t update;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pd_lp_attributes_t element);
std::string to_short_string(npl_pd_lp_attributes_t element);


struct npl_pd_rx_slb_t
{
    uint64_t eos : 1;
    uint64_t close_prev_segment : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pd_rx_slb_t element);
std::string to_short_string(npl_pd_rx_slb_t element);


struct npl_pd_svl_attributes_t
{
    uint64_t svl_dsp_remote_flag : 1;
    uint64_t svl_encap_forward_flag : 1;
    uint64_t svl_bvn_flag : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pd_svl_attributes_t element);
std::string to_short_string(npl_pd_svl_attributes_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_pdoq_oq_ifc_mapping_result_t_anonymous_union_txpp_map_data_t
{
    npl_omd_txpp_parsed_t parsed;
    uint64_t raw : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pdoq_oq_ifc_mapping_result_t_anonymous_union_txpp_map_data_t element);
std::string to_short_string(npl_pdoq_oq_ifc_mapping_result_t_anonymous_union_txpp_map_data_t element);


struct npl_pdvoq_bank_pair_offset_t
{
    uint64_t value : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pdvoq_bank_pair_offset_t element);
std::string to_short_string(npl_pdvoq_bank_pair_offset_t element);


struct npl_per_rtf_step_og_pcl_compress_bits_t
{
    npl_og_pcl_compress_t ipv4_compress_bits;
    npl_og_pcl_compress_t ipv6_compress_bits;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_per_rtf_step_og_pcl_compress_bits_t element);
std::string to_short_string(npl_per_rtf_step_og_pcl_compress_bits_t element);


struct npl_per_rtf_step_og_pcl_ids_t
{
    npl_og_pcl_ids_t ipv4_og_pcl_ids;
    npl_og_pcl_ids_t ipv6_og_pcl_ids;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_per_rtf_step_og_pcl_ids_t element);
std::string to_short_string(npl_per_rtf_step_og_pcl_ids_t element);


struct npl_pfc_aux_payload_t
{
    npl_counter_ptr_t rx_counter;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pfc_aux_payload_t element);
std::string to_short_string(npl_pfc_aux_payload_t element);


struct npl_pfc_em_lookup_t
{
    uint64_t destination : 20;
    uint64_t some_padding : 20;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pfc_em_lookup_t element);
std::string to_short_string(npl_pfc_em_lookup_t element);


struct npl_pfc_em_t
{
    uint64_t rmep_id : 13;
    uint64_t mep_id : 13;
    uint64_t access_rmep : 1;
    uint64_t mp_data_select : 1;
    uint64_t access_mp : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pfc_em_t element);
std::string to_short_string(npl_pfc_em_t element);


struct npl_pfc_rx_counter_offset_t
{
    uint64_t value : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pfc_rx_counter_offset_t element);
std::string to_short_string(npl_pfc_rx_counter_offset_t element);


struct npl_pfc_ssp_info_table_t
{
    uint64_t slice : 3;
    uint64_t mp_id : 13;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pfc_ssp_info_table_t element);
std::string to_short_string(npl_pfc_ssp_info_table_t element);


struct npl_phb_t
{
    uint64_t tc : 3;
    uint64_t dp : 2;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_phb_t element);
std::string to_short_string(npl_phb_t element);


struct npl_pif_ifg_base_t
{
    uint64_t pif : 5;
    uint64_t ifg : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pif_ifg_base_t element);
std::string to_short_string(npl_pif_ifg_base_t element);


struct npl_pma_loopback_data_t
{
    npl_loopback_mode_e mode;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pma_loopback_data_t element);
std::string to_short_string(npl_pma_loopback_data_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_properties_t_anonymous_union_monitor_or_l3_dlp_ip_type_t
{
    npl_l3_dlp_ip_type_e l3_dlp_ip_type;
    npl_bool_t enable_monitor;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_properties_t_anonymous_union_monitor_or_l3_dlp_ip_type_t element);
std::string to_short_string(npl_properties_t_anonymous_union_monitor_or_l3_dlp_ip_type_t element);


struct npl_protocol_type_padded_t
{
    uint64_t protocol_type : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_protocol_type_padded_t element);
std::string to_short_string(npl_protocol_type_padded_t element);


struct npl_punt_controls_t
{
    npl_punt_header_format_type_e punt_format;
    uint64_t mirror_local_encap_format : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_controls_t element);
std::string to_short_string(npl_punt_controls_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_punt_encap_data_lsb_t_anonymous_union_extra_t
{
    uint64_t lpts_meter_index_msb : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_encap_data_lsb_t_anonymous_union_extra_t element);
std::string to_short_string(npl_punt_encap_data_lsb_t_anonymous_union_extra_t element);


struct npl_punt_eth_transport_update_t
{
    uint64_t update[2];
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_eth_transport_update_t element);
std::string to_short_string(npl_punt_eth_transport_update_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_punt_header_t_anonymous_union_pl_header_offset_t
{
    uint64_t ingress_next_pl_offset : 8;
    uint64_t egress_current_pl_offset : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_header_t_anonymous_union_pl_header_offset_t element);
std::string to_short_string(npl_punt_header_t_anonymous_union_pl_header_offset_t element);


struct npl_punt_l2_lp_t
{
    uint64_t id : 18;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_l2_lp_t element);
std::string to_short_string(npl_punt_l2_lp_t element);


struct npl_punt_npu_host_macro_data_t
{
    uint64_t first_fi_macro_id : 8;
    uint64_t first_npe_macro_id : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_npu_host_macro_data_t element);
std::string to_short_string(npl_punt_npu_host_macro_data_t element);


struct npl_punt_nw_encap_ptr_t
{
    uint64_t ptr : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_nw_encap_ptr_t element);
std::string to_short_string(npl_punt_nw_encap_ptr_t element);


struct npl_punt_rcy_pack_table_payload_t
{
    uint64_t ive_reset : 16;
    uint64_t redirect_code : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_rcy_pack_table_payload_t element);
std::string to_short_string(npl_punt_rcy_pack_table_payload_t element);


struct npl_punt_ssp_t
{
    uint64_t slice_id : 3;
    uint64_t ssp_12 : 12;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_ssp_t element);
std::string to_short_string(npl_punt_ssp_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_punt_sub_code_t_anonymous_union_sub_code_t
{
    npl_lpts_flow_type_t lpts_flow_type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_sub_code_t_anonymous_union_sub_code_t element);
std::string to_short_string(npl_punt_sub_code_t_anonymous_union_sub_code_t element);


struct npl_pwe_to_l3_lookup_result_t
{
    uint64_t destination : 20;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pwe_to_l3_lookup_result_t element);
std::string to_short_string(npl_pwe_to_l3_lookup_result_t element);


struct npl_qos_and_acl_ids_t
{
    uint64_t qos_id : 4;
    uint64_t acl_id : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_qos_and_acl_ids_t element);
std::string to_short_string(npl_qos_and_acl_ids_t element);


struct npl_qos_attributes_t
{
    uint64_t demux_count : 1;
    uint64_t is_group_qos : 1;
    npl_counter_ptr_t q_counter;
    npl_counter_ptr_t p_counter;
    uint64_t qos_id : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_qos_attributes_t element);
std::string to_short_string(npl_qos_attributes_t element);


struct npl_qos_encap_t
{
    uint64_t tos : 8;
    npl_ene_no_bos_t exp_no_bos;
    uint64_t pcp_dei : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_qos_encap_t element);
std::string to_short_string(npl_qos_encap_t element);


struct npl_qos_info_t
{
    uint64_t is_group_qos : 1;
    uint64_t qos_id : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_qos_info_t element);
std::string to_short_string(npl_qos_info_t element);


struct npl_qos_tag_t
{
    uint64_t val : 7;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_qos_tag_t element);
std::string to_short_string(npl_qos_tag_t element);


struct npl_qos_tags_t
{
    npl_qos_tag_t mapping_key;
    npl_qos_tag_t outer;
    npl_qos_tag_t inner;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_qos_tags_t element);
std::string to_short_string(npl_qos_tags_t element);


struct npl_quan_13b
{
    uint64_t value : 13;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_quan_13b element);
std::string to_short_string(npl_quan_13b element);


struct npl_quan_14b
{
    uint64_t value : 14;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_quan_14b element);
std::string to_short_string(npl_quan_14b element);


struct npl_quan_15b
{
    uint64_t value : 15;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_quan_15b element);
std::string to_short_string(npl_quan_15b element);


struct npl_quan_17b
{
    uint64_t value : 17;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_quan_17b element);
std::string to_short_string(npl_quan_17b element);


struct npl_quan_19b
{
    uint64_t value : 19;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_quan_19b element);
std::string to_short_string(npl_quan_19b element);


struct npl_quan_1b
{
    uint64_t value : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_quan_1b element);
std::string to_short_string(npl_quan_1b element);


struct npl_quan_2b
{
    uint64_t value : 2;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_quan_2b element);
std::string to_short_string(npl_quan_2b element);


struct npl_quan_3b
{
    uint64_t value : 3;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_quan_3b element);
std::string to_short_string(npl_quan_3b element);


struct npl_quan_4b
{
    uint64_t value : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_quan_4b element);
std::string to_short_string(npl_quan_4b element);


struct npl_quan_5b
{
    uint64_t value : 5;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_quan_5b element);
std::string to_short_string(npl_quan_5b element);


struct npl_quan_8b
{
    uint64_t value : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_quan_8b element);
std::string to_short_string(npl_quan_8b element);


struct npl_random_bc_bmp_entry_t
{
    uint64_t rnd_entry : 7;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_random_bc_bmp_entry_t element);
std::string to_short_string(npl_random_bc_bmp_entry_t element);


struct npl_rate_limiters_port_packet_type_index_len_t
{
    uint64_t value : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rate_limiters_port_packet_type_index_len_t element);
std::string to_short_string(npl_rate_limiters_port_packet_type_index_len_t element);


struct npl_raw_lp_over_lag_result_t
{
    uint64_t bvn_destination : 20;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_raw_lp_over_lag_result_t element);
std::string to_short_string(npl_raw_lp_over_lag_result_t element);


struct npl_rcy_sm_vlans_t
{
    uint64_t vid1 : 12;
    uint64_t vid2 : 12;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rcy_sm_vlans_t element);
std::string to_short_string(npl_rcy_sm_vlans_t element);


struct npl_reassembly_source_port_map_key_t
{
    uint64_t ifg : 1;
    uint64_t pif : 5;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_reassembly_source_port_map_key_t element);
std::string to_short_string(npl_reassembly_source_port_map_key_t element);


struct npl_reassembly_source_port_map_result_t
{
    uint64_t tm_ifc : 6;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_reassembly_source_port_map_result_t element);
std::string to_short_string(npl_reassembly_source_port_map_result_t element);


struct npl_redirect_code_t
{
    uint64_t val : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_redirect_code_t element);
std::string to_short_string(npl_redirect_code_t element);


struct npl_redirect_destination_reg_t
{
    npl_redirect_destination_e port_reg;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_redirect_destination_reg_t element);
std::string to_short_string(npl_redirect_destination_reg_t element);


struct npl_relay_id_t
{
    uint64_t id : 14;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_relay_id_t element);
std::string to_short_string(npl_relay_id_t element);


struct npl_resolution_dest_type_decoding_key_t
{
    uint64_t dest_type : 6;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_dest_type_decoding_key_t element);
std::string to_short_string(npl_resolution_dest_type_decoding_key_t element);


struct npl_resolution_dest_type_decoding_result_t
{
    npl_resolution_dest_src_to_encap_mode_e destination_source_for_enc_data;
    npl_resolution_pbts_mode_e is_pbts;
    npl_resolution_add_qos_mapping_mode_e add_qos_mapping;
    npl_resolution_em_selector_e dest_type;
    npl_resolution_table_e table_id;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_dest_type_decoding_result_t element);
std::string to_short_string(npl_resolution_dest_type_decoding_result_t element);


struct npl_resolution_dlp_attributes_t
{
    uint64_t pad : 2;
    uint64_t monitor : 1;
    npl_bvn_profile_t bvn_profile;
    uint64_t never_use_npu_header_pif_ifg : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_dlp_attributes_t element);
std::string to_short_string(npl_resolution_dlp_attributes_t element);


struct npl_resolution_entry_type_decoding_table_field_t
{
    uint64_t destination_in_nibbles : 5;
    uint64_t size_in_bits : 5;
    uint64_t offset_in_bits : 7;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_entry_type_decoding_table_field_t element);
std::string to_short_string(npl_resolution_entry_type_decoding_table_field_t element);


struct npl_resolution_entry_type_decoding_table_result_t
{
    uint64_t do_lp_queuing : 1;
    uint64_t dest_size_on_encap_data_in_bits : 5;
    uint64_t dest_offset_on_encap_data_in_nibbles : 5;
    npl_resolution_entry_type_decoding_table_field_t field_2;
    npl_resolution_entry_type_decoding_table_field_t field_1;
    npl_resolution_entry_type_decoding_table_field_t field_0;
    uint64_t encapsulation_type : 4;
    uint64_t encapsulation_start : 1;
    uint64_t next_destination_type : 6;
    uint64_t next_destination_size : 5;
    uint64_t next_destination_offset : 7;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_entry_type_decoding_table_result_t element);
std::string to_short_string(npl_resolution_entry_type_decoding_table_result_t element);


struct npl_resolution_fec_key_t
{
    uint64_t id : 13;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_fec_key_t element);
std::string to_short_string(npl_resolution_fec_key_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_resolution_fec_result_t
{
    npl_fec_fec_destination_t fec_dest;
    npl_fec_destination1_t fec_dest1;
    npl_fec_raw_t raw;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_fec_result_t element);
std::string to_short_string(npl_resolution_fec_result_t element);


struct npl_resolution_fwd_class_t
{
    uint64_t tag : 3;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_fwd_class_t element);
std::string to_short_string(npl_resolution_fwd_class_t element);


struct npl_resolution_lb_size_table_result_t
{
    uint64_t group_size : 9;
    npl_lb_consistency_mode_e consistency_mode;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_lb_size_table_result_t element);
std::string to_short_string(npl_resolution_lb_size_table_result_t element);


struct npl_resolution_protection_result_t
{
    npl_resolution_protection_selector_e sel;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_protection_result_t element);
std::string to_short_string(npl_resolution_protection_result_t element);


struct npl_resolution_result_dest_data_t
{
    npl_lb_key_t lb_key;
    uint64_t bvn_map_profile : 3;
    uint64_t destination : 20;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_result_dest_data_t element);
std::string to_short_string(npl_resolution_result_dest_data_t element);


struct npl_resolution_stage_assoc_data_narrow_protection_record_t
{
    uint64_t path : 1;
    uint64_t primary_payload : 26;
    uint64_t primary_entry_type : 6;
    uint64_t protect_payload : 26;
    uint64_t protect_entry_type : 6;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_stage_assoc_data_narrow_protection_record_t element);
std::string to_short_string(npl_resolution_stage_assoc_data_narrow_protection_record_t element);


struct npl_resolution_stage_assoc_data_raw_t
{
    uint64_t is_protection : 1;
    uint64_t payload[3];
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_stage_assoc_data_raw_t element);
std::string to_short_string(npl_resolution_stage_assoc_data_raw_t element);


struct npl_resolution_stage_em_table_dest_map_key_t
{
    npl_resolution_em_selector_e dest_or_lb;
    uint64_t padd : 3;
    uint64_t dest : 20;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_stage_em_table_dest_map_key_t element);
std::string to_short_string(npl_resolution_stage_em_table_dest_map_key_t element);


struct npl_resolution_stage_em_table_lb_key_t
{
    npl_resolution_em_selector_e dest_or_lb;
    uint64_t member_id : 9;
    uint64_t group_id : 14;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_stage_em_table_lb_key_t element);
std::string to_short_string(npl_resolution_stage_em_table_lb_key_t element);


struct npl_resolution_stage_em_table_raw_key_t
{
    npl_resolution_em_selector_e dest_or_lb;
    uint64_t key : 23;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_stage_em_table_raw_key_t element);
std::string to_short_string(npl_resolution_stage_em_table_raw_key_t element);


struct npl_rmep_data_t
{
    uint64_t rmep_data : 11;
    uint64_t rmep_profile : 4;
    uint64_t rmep_valid : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rmep_data_t element);
std::string to_short_string(npl_rmep_data_t element);


struct npl_rtf_compressed_fields_for_next_macro_t
{
    uint64_t acl_outer : 1;
    npl_fwd_layer_and_rtf_stage_compressed_fields_t fwd_layer_and_rtf_stage_compressed_fields;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rtf_compressed_fields_for_next_macro_t element);
std::string to_short_string(npl_rtf_compressed_fields_for_next_macro_t element);


struct npl_rtf_conf_set_and_stages_t
{
    npl_lp_rtf_conf_set_t rtf_conf_set;
    npl_ipv4_ipv6_init_rtf_stage_t ipv4_ipv6_init_rtf_stage;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rtf_conf_set_and_stages_t element);
std::string to_short_string(npl_rtf_conf_set_and_stages_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_rtf_iter_prop_over_fwd0_t
{
    npl_ip_rtf_iter_prop_over_fwd0_t ip_rtf;
    npl_eth_rtf_prop_over_fwd0_t eth_rtf;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rtf_iter_prop_over_fwd0_t element);
std::string to_short_string(npl_rtf_iter_prop_over_fwd0_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_rtf_iter_prop_over_fwd1_t
{
    npl_ip_rtf_iter_prop_over_fwd1_t ip_rtf;
    npl_eth_rtf_prop_over_fwd1_t eth_rtf;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rtf_iter_prop_over_fwd1_t element);
std::string to_short_string(npl_rtf_iter_prop_over_fwd1_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_rtf_result_profile_0_t_anonymous_union_force_t
{
    npl_destination_t destination;
    npl_counter_ptr_t drop_counter;
    npl_counter_ptr_t permit_ace_cntr;
    npl_counter_ptr_t meter_ptr;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rtf_result_profile_0_t_anonymous_union_force_t element);
std::string to_short_string(npl_rtf_result_profile_0_t_anonymous_union_force_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_rtf_result_profile_0_t_anonymous_union_mirror_cmd_or_offset_t
{
    uint64_t mirror_cmd : 5;
    uint64_t mirror_offset : 5;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rtf_result_profile_0_t_anonymous_union_mirror_cmd_or_offset_t element);
std::string to_short_string(npl_rtf_result_profile_0_t_anonymous_union_mirror_cmd_or_offset_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_rtf_result_profile_1_t_anonymous_union_meter_or_counter_t
{
    npl_counter_ptr_t meter_ptr;
    npl_counter_ptr_t counter_ptr;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rtf_result_profile_1_t_anonymous_union_meter_or_counter_t element);
std::string to_short_string(npl_rtf_result_profile_1_t_anonymous_union_meter_or_counter_t element);


struct npl_rtf_result_profile_2_t
{
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rtf_result_profile_2_t element);
std::string to_short_string(npl_rtf_result_profile_2_t element);


struct npl_rtf_result_profile_3_t
{
    
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rtf_result_profile_3_t element);
std::string to_short_string(npl_rtf_result_profile_3_t element);


struct npl_rtf_step_t
{
    uint64_t val : 2;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rtf_step_t element);
std::string to_short_string(npl_rtf_step_t element);


struct npl_rx_meter_block_meter_attribute_result_t
{
    npl_meter_action_profile_len_t meter_decision_mapping_profile;
    npl_meter_profile_len_t profile;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rx_meter_block_meter_attribute_result_t element);
std::string to_short_string(npl_rx_meter_block_meter_attribute_result_t element);


struct npl_rx_meter_block_meter_profile_result_t
{
    npl_burst_size_len_t ebs;
    npl_burst_size_len_t cbs;
    npl_color_aware_mode_len_t color_aware_mode;
    npl_meter_mode_len_t meter_mode;
    npl_meter_count_mode_len_t meter_count_mode;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rx_meter_block_meter_profile_result_t element);
std::string to_short_string(npl_rx_meter_block_meter_profile_result_t element);


struct npl_rx_meter_block_meter_shaper_configuration_result_t
{
    npl_meter_weight_t eir_weight;
    npl_meter_weight_t cir_weight;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rx_meter_block_meter_shaper_configuration_result_t element);
std::string to_short_string(npl_rx_meter_block_meter_shaper_configuration_result_t element);


struct npl_rx_meter_distributed_meter_profile_result_t
{
    uint64_t is_distributed_meter : 1;
    uint64_t excess_token_release_thr : 18;
    uint64_t excess_token_grant_thr : 18;
    uint64_t committed_token_release_thr : 18;
    uint64_t committed_token_grant_thr : 18;
    uint64_t is_cascade : 1;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rx_meter_distributed_meter_profile_result_t element);
std::string to_short_string(npl_rx_meter_distributed_meter_profile_result_t element);


struct npl_rx_meter_exact_meter_decision_mapping_result_t
{
    uint64_t congestion_experienced : 1;
    npl_color_len_t rx_counter_color;
    npl_color_len_t outgoing_color;
    uint64_t cgm_rx_dp : 1;
    uint64_t meter_drop : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rx_meter_exact_meter_decision_mapping_result_t element);
std::string to_short_string(npl_rx_meter_exact_meter_decision_mapping_result_t element);


struct npl_rx_meter_meter_profile_result_t
{
    npl_burst_size_len_t ebs;
    npl_burst_size_len_t cbs;
    npl_color_aware_mode_len_t color_aware_mode;
    npl_meter_mode_len_t meter_mode;
    npl_meter_count_mode_len_t meter_count_mode;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rx_meter_meter_profile_result_t element);
std::string to_short_string(npl_rx_meter_meter_profile_result_t element);


struct npl_rx_meter_meter_shaper_configuration_result_t
{
    npl_meter_weight_t eir_weight;
    npl_meter_weight_t cir_weight;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rx_meter_meter_shaper_configuration_result_t element);
std::string to_short_string(npl_rx_meter_meter_shaper_configuration_result_t element);


struct npl_rx_meter_meters_attribute_result_t
{
    npl_meter_action_profile_len_t meter_decision_mapping_profile;
    npl_meter_profile_len_t profile;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rx_meter_meters_attribute_result_t element);
std::string to_short_string(npl_rx_meter_meters_attribute_result_t element);


struct npl_rx_meter_rate_limiter_shaper_configuration_result_t
{
    npl_meter_weight_t cir_weight;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rx_meter_rate_limiter_shaper_configuration_result_t element);
std::string to_short_string(npl_rx_meter_rate_limiter_shaper_configuration_result_t element);


struct npl_rx_meter_stat_meter_decision_mapping_result_t
{
    uint64_t congestion_experienced : 1;
    npl_color_len_t rx_counter_color;
    npl_color_len_t outgoing_color;
    uint64_t cgm_rx_dp : 1;
    uint64_t meter_drop : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rx_meter_stat_meter_decision_mapping_result_t element);
std::string to_short_string(npl_rx_meter_stat_meter_decision_mapping_result_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_rx_nw_app_on_lb_key_t
{
    uint64_t nhlfe_mid_point_nh : 12;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rx_nw_app_on_lb_key_t element);
std::string to_short_string(npl_rx_nw_app_on_lb_key_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_rx_nw_app_or_lb_key_t
{
    uint64_t lb_key : 16;
    npl_rx_nw_app_on_lb_key_t rx_nw_app_on_lb_key;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rx_nw_app_or_lb_key_t element);
std::string to_short_string(npl_rx_nw_app_or_lb_key_t element);


struct npl_rx_obm_punt_src_and_code_data_t
{
    npl_phb_t phb;
    npl_counter_ptr_t meter_ptr;
    npl_counter_ptr_t cntr_ptr;
    npl_destination_t punt_bvn_dest;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rx_obm_punt_src_and_code_data_t element);
std::string to_short_string(npl_rx_obm_punt_src_and_code_data_t element);


struct npl_rxpdr_dsp_lookup_table_entry_t
{
    uint64_t tc_map_profile : 3;
    uint64_t base_voq_num : 16;
    uint64_t dest_device : 9;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rxpdr_dsp_lookup_table_entry_t element);
std::string to_short_string(npl_rxpdr_dsp_lookup_table_entry_t element);


struct npl_rxpdr_dsp_tc_map_result_t
{
    uint64_t is_flb : 1;
    uint64_t tc_offset : 3;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rxpdr_dsp_tc_map_result_t element);
std::string to_short_string(npl_rxpdr_dsp_tc_map_result_t element);


struct npl_rxpdr_ibm_tc_map_result_t
{
    uint64_t is_flb : 1;
    uint64_t tc_offset : 3;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rxpdr_ibm_tc_map_result_t element);
std::string to_short_string(npl_rxpdr_ibm_tc_map_result_t element);


struct npl_rxpp_pd_forward_destination_doq_ds_t
{
    uint64_t prefix : 7;
    uint64_t doq : 9;
    uint64_t ds : 3;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rxpp_pd_forward_destination_doq_ds_t element);
std::string to_short_string(npl_rxpp_pd_forward_destination_doq_ds_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_rxpp_pd_forward_destination_t
{
    uint64_t raw : 20;
    npl_rxpp_pd_forward_destination_doq_ds_t doq_ds;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rxpp_pd_forward_destination_t element);
std::string to_short_string(npl_rxpp_pd_forward_destination_t element);


struct npl_rxpp_pd_rxf_t
{
    uint64_t fabric_ts_sn : 24;
    npl_fabric_context_e vmd_fabric_ctxt;
    uint64_t first_packet_size_round_up_in_8_bytes_granularity : 6;
    uint64_t is_keepalive : 1;
    uint64_t plb_header_type : 1;
    uint64_t plb_ctxt_ts[2];
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rxpp_pd_rxf_t element);
std::string to_short_string(npl_rxpp_pd_rxf_t element);


struct npl_rxpp_pd_rxn_t
{
    uint64_t flow_sign : 36;
    uint64_t sch_compensation : 7;
    uint64_t in_mirror_cmd1 : 5;
    uint64_t in_mirror_cmd2 : 5;
    uint64_t counter_meter_ptr_1 : 19;
    uint64_t counter_meter_comp_1 : 7;
    uint64_t counter_lm_read_only_1 : 1;
    uint64_t counter_meter_ptr_2 : 19;
    uint64_t counter_meter_comp_2 : 7;
    uint64_t counter_lm_read_only_2 : 1;
    uint64_t counter_meter_ptr_3 : 19;
    uint64_t counter_meter_comp_3 : 7;
    uint64_t counter_lm_read_only_3 : 1;
    uint64_t fllb_control_code : 3;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rxpp_pd_rxn_t element);
std::string to_short_string(npl_rxpp_pd_rxn_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_rxpp_pd_t_anonymous_union_lb_or_slb_t
{
    uint64_t lb_key : 16;
    npl_pd_rx_slb_t slb;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rxpp_pd_t_anonymous_union_lb_or_slb_t element);
std::string to_short_string(npl_rxpp_pd_t_anonymous_union_lb_or_slb_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_rxpp_pd_t_anonymous_union_slice_mode_data_t
{
    npl_rxpp_pd_rxf_t rxf;
    npl_rxpp_pd_rxn_t rxn;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rxpp_pd_t_anonymous_union_slice_mode_data_t element);
std::string to_short_string(npl_rxpp_pd_t_anonymous_union_slice_mode_data_t element);


struct npl_sa_msb_t
{
    uint64_t msb : 32;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_sa_msb_t element);
std::string to_short_string(npl_sa_msb_t element);


struct npl_scanner_id_t
{
    uint64_t id : 13;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_scanner_id_t element);
std::string to_short_string(npl_scanner_id_t element);


struct npl_sda_fabric_feature_t
{
    uint64_t enable : 1;
    uint64_t l2_enforcement : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_sda_fabric_feature_t element);
std::string to_short_string(npl_sda_fabric_feature_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_sec_acl_attributes_t_anonymous_union_slp_dlp_t
{
    uint64_t global_dlp_id : 20;
    uint64_t global_slp_id : 20;
    uint64_t is_l2 : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_sec_acl_attributes_t_anonymous_union_slp_dlp_t element);
std::string to_short_string(npl_sec_acl_attributes_t_anonymous_union_slp_dlp_t element);


struct npl_sec_acl_ids_t
{
    uint64_t acl_v4_id : 4;
    uint64_t acl_v6_id : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_sec_acl_ids_t element);
std::string to_short_string(npl_sec_acl_ids_t element);


struct npl_select_macros_t
{
    uint64_t npe_macro_offset : 2;
    uint64_t fi_macro_offset : 2;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_select_macros_t element);
std::string to_short_string(npl_select_macros_t element);


struct npl_service_flags_t
{
    uint64_t push_entropy_label : 1;
    uint64_t add_ipv6_explicit_null : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_service_flags_t element);
std::string to_short_string(npl_service_flags_t element);


struct npl_sgacl_counter_metadata_t
{
    uint64_t sgacl_counter_lsb : 16;
    uint64_t sgacl_bank_idx : 3;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_sgacl_counter_metadata_t element);
std::string to_short_string(npl_sgacl_counter_metadata_t element);


struct npl_sgacl_payload_t
{
    uint64_t log : 1;
    uint64_t drop : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_sgacl_payload_t element);
std::string to_short_string(npl_sgacl_payload_t element);


struct npl_sgt_matrix_result_t
{
    uint64_t group_policy_allow_drop : 1;
    uint64_t group_policy_acl_id : 32;
    npl_sgacl_counter_metadata_t group_policy_counter_metadata;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_sgt_matrix_result_t element);
std::string to_short_string(npl_sgt_matrix_result_t element);


struct npl_sip_ip_tunnel_termination_attr_t
{
    uint64_t my_dip_index : 6;
    uint64_t vxlan_tunnel_loopback : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_sip_ip_tunnel_termination_attr_t element);
std::string to_short_string(npl_sip_ip_tunnel_termination_attr_t element);


struct npl_slp_based_fwd_and_per_vrf_mpls_fwd_t
{
    uint64_t slp_based_forwarding : 1;
    uint64_t per_vrf_mpls_fwd : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_slp_based_fwd_and_per_vrf_mpls_fwd_t element);
std::string to_short_string(npl_slp_based_fwd_and_per_vrf_mpls_fwd_t element);


struct npl_slp_fwd_result_t
{
    uint64_t mpls_label_present : 1;
    uint64_t mpls_label : 20;
    uint64_t destination : 20;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_slp_fwd_result_t element);
std::string to_short_string(npl_slp_fwd_result_t element);


struct npl_snoop_code_t
{
    uint64_t val : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_snoop_code_t element);
std::string to_short_string(npl_snoop_code_t element);


struct npl_soft_lb_wa_enable_t
{
    uint64_t is_next_header_gre : 1;
    uint64_t soft_lb_enable : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_soft_lb_wa_enable_t element);
std::string to_short_string(npl_soft_lb_wa_enable_t element);


struct npl_source_if_t
{
    uint64_t ifg : 1;
    uint64_t pif : 5;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_source_if_t element);
std::string to_short_string(npl_source_if_t element);


struct npl_split_voq_t
{
    uint64_t split_voq_enabled : 1;
    uint64_t source_group_offset : 10;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_split_voq_t element);
std::string to_short_string(npl_split_voq_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_sport_or_l4_protocol_t_anonymous_union_sport_or_l4_protocol_type_t
{
    uint64_t src_port : 16;
    uint64_t ipv4_protocol : 8;
    uint64_t ipv6_next_header : 8;
    npl_icmp_type_code_t icmp_type_code;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_sport_or_l4_protocol_t_anonymous_union_sport_or_l4_protocol_type_t element);
std::string to_short_string(npl_sport_or_l4_protocol_t_anonymous_union_sport_or_l4_protocol_type_t element);


struct npl_stage0_ce_ptr_destination_vpn_inter_as_ce_ptr_t
{
    uint64_t ce_ptr : 16;
    uint64_t vpn_inter_as : 2;
    uint64_t destination : 20;
    npl_stage0_entry_type_e type;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage0_ce_ptr_destination_vpn_inter_as_ce_ptr_t element);
std::string to_short_string(npl_stage0_ce_ptr_destination_vpn_inter_as_ce_ptr_t element);


struct npl_stage0_ce_ptr_l3_nh_ip_tunnel_t
{
    uint64_t ip_tunnel : 16;
    uint64_t l3_nh : 12;
    npl_stage0_entry_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage0_ce_ptr_l3_nh_ip_tunnel_t element);
std::string to_short_string(npl_stage0_ce_ptr_l3_nh_ip_tunnel_t element);


struct npl_stage0_ce_ptr_l3_nh_vpn_inter_as_ce_ptr_t
{
    uint64_t ce_ptr : 16;
    uint64_t vpn_inter_as : 2;
    uint64_t l3_nh : 12;
    npl_stage0_entry_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage0_ce_ptr_l3_nh_vpn_inter_as_ce_ptr_t element);
std::string to_short_string(npl_stage0_ce_ptr_l3_nh_vpn_inter_as_ce_ptr_t element);


struct npl_stage0_ce_ptr_l3_nh_vpn_inter_as_ce_ptr_with_common_data_t
{
    uint64_t ce_ptr : 16;
    uint64_t vpn_inter_as : 2;
    uint64_t l3_nh : 12;
    npl_stage0_entry_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage0_ce_ptr_l3_nh_vpn_inter_as_ce_ptr_with_common_data_t element);
std::string to_short_string(npl_stage0_ce_ptr_l3_nh_vpn_inter_as_ce_ptr_with_common_data_t element);


struct npl_stage0_ce_ptr_level2_ecmp_ip_tunnel_t
{
    uint64_t ip_tunnel : 16;
    uint64_t level2_ecmp : 13;
    npl_stage0_entry_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage0_ce_ptr_level2_ecmp_ip_tunnel_t element);
std::string to_short_string(npl_stage0_ce_ptr_level2_ecmp_ip_tunnel_t element);


struct npl_stage0_ce_ptr_p_l3_nh_vpn_inter_as_ce_ptr_t
{
    uint64_t ce_ptr : 16;
    uint64_t vpn_inter_as : 2;
    uint64_t p_l3_nh : 12;
    npl_stage0_entry_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage0_ce_ptr_p_l3_nh_vpn_inter_as_ce_ptr_t element);
std::string to_short_string(npl_stage0_ce_ptr_p_l3_nh_vpn_inter_as_ce_ptr_t element);


struct npl_stage0_ce_ptr_p_l3_nh_vpn_inter_as_ce_ptr_with_common_data_t
{
    uint64_t ce_ptr : 16;
    uint64_t vpn_inter_as : 2;
    uint64_t p_l3_nh : 12;
    npl_stage0_entry_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage0_ce_ptr_p_l3_nh_vpn_inter_as_ce_ptr_with_common_data_t element);
std::string to_short_string(npl_stage0_ce_ptr_p_l3_nh_vpn_inter_as_ce_ptr_with_common_data_t element);


struct npl_stage0_destination1_t
{
    uint64_t enc_type : 4;
    uint64_t destination : 20;
    npl_stage0_entry_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage0_destination1_t element);
std::string to_short_string(npl_stage0_destination1_t element);


struct npl_stage0_ecmp_destination_t
{
    uint64_t destination : 20;
    npl_stage0_entry_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage0_ecmp_destination_t element);
std::string to_short_string(npl_stage0_ecmp_destination_t element);


struct npl_stage0_l2_dlp_destination_l2_dlp_t
{
    uint64_t enc_type : 4;
    uint64_t l2_dlp : 18;
    uint64_t destination : 20;
    npl_stage0_entry_type_e type;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage0_l2_dlp_destination_l2_dlp_t element);
std::string to_short_string(npl_stage0_l2_dlp_destination_l2_dlp_t element);


struct npl_stage0_l2_dlp_destination_overlay_nh_t
{
    uint64_t overlay_nh : 10;
    uint64_t destination : 20;
    npl_stage0_entry_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage0_l2_dlp_destination_overlay_nh_t element);
std::string to_short_string(npl_stage0_l2_dlp_destination_overlay_nh_t element);


struct npl_stage0_l2_dlp_destination_t
{
    uint64_t enc_type : 4;
    uint64_t destination : 20;
    npl_stage0_entry_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage0_l2_dlp_destination_t element);
std::string to_short_string(npl_stage0_l2_dlp_destination_t element);


struct npl_stage0_l3_nh_vpn_inter_as_ce_ptr_with_common_data1_t
{
    uint64_t ce_ptr : 16;
    uint64_t vpn_inter_as : 2;
    uint64_t l3_nh : 12;
    npl_stage0_entry_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage0_l3_nh_vpn_inter_as_ce_ptr_with_common_data1_t element);
std::string to_short_string(npl_stage0_l3_nh_vpn_inter_as_ce_ptr_with_common_data1_t element);


struct npl_stage0_narrow_raw_t
{
    uint64_t payload : 30;
    npl_stage0_entry_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage0_narrow_raw_t element);
std::string to_short_string(npl_stage0_narrow_raw_t element);


struct npl_stage0_p_l3_nh_vpn_inter_as_ce_ptr_with_common_data1_t
{
    uint64_t ce_ptr : 16;
    uint64_t vpn_inter_as : 2;
    uint64_t p_l3_nh : 12;
    npl_stage0_entry_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage0_p_l3_nh_vpn_inter_as_ce_ptr_with_common_data1_t element);
std::string to_short_string(npl_stage0_p_l3_nh_vpn_inter_as_ce_ptr_with_common_data1_t element);


struct npl_stage1_destination1_t
{
    uint64_t enc_type : 4;
    uint64_t destination : 20;
    npl_stage1_entry_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage1_destination1_t element);
std::string to_short_string(npl_stage1_destination1_t element);


struct npl_stage1_l3_nh_te_tunnel14b_or_asbr1_t
{
    uint64_t te_tunnel14b_or_asbr : 16;
    uint64_t l3_nh : 12;
    npl_stage1_entry_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage1_l3_nh_te_tunnel14b_or_asbr1_t element);
std::string to_short_string(npl_stage1_l3_nh_te_tunnel14b_or_asbr1_t element);


struct npl_stage1_l3_nh_te_tunnel14b_or_asbr2_t
{
    uint64_t te_tunnel14b_or_asbr : 16;
    uint64_t l3_nh : 12;
    npl_stage1_entry_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage1_l3_nh_te_tunnel14b_or_asbr2_t element);
std::string to_short_string(npl_stage1_l3_nh_te_tunnel14b_or_asbr2_t element);


struct npl_stage1_l3_nh_te_tunnel16b1_t
{
    uint64_t enc_type : 4;
    uint64_t te_tunnel16b : 16;
    uint64_t l3_nh : 12;
    npl_stage1_entry_type_e type;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage1_l3_nh_te_tunnel16b1_t element);
std::string to_short_string(npl_stage1_l3_nh_te_tunnel16b1_t element);


struct npl_stage1_level2_ecmp_destination_t
{
    uint64_t destination : 20;
    npl_stage1_entry_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage1_level2_ecmp_destination_t element);
std::string to_short_string(npl_stage1_level2_ecmp_destination_t element);


struct npl_stage1_level2_ecmp_l3_nh_te_tunnel14b_or_asbr_t
{
    uint64_t te_tunnel14b_or_asbr : 16;
    uint64_t l3_nh : 12;
    npl_stage1_entry_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage1_level2_ecmp_l3_nh_te_tunnel14b_or_asbr_t element);
std::string to_short_string(npl_stage1_level2_ecmp_l3_nh_te_tunnel14b_or_asbr_t element);


struct npl_stage1_p_l3_nh_destination_with_common_data_t
{
    uint64_t destination : 20;
    npl_stage1_entry_type_e type;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage1_p_l3_nh_destination_with_common_data_t element);
std::string to_short_string(npl_stage1_p_l3_nh_destination_with_common_data_t element);


struct npl_stage1_protected_raw_t
{
    uint64_t payload : 59;
    npl_stage1_entry_type_e type;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage1_protected_raw_t element);
std::string to_short_string(npl_stage1_protected_raw_t element);


struct npl_stage2_l3_nh_destination_l3_dlp_dlp_attr_t
{
    uint64_t dlp_attr : 8;
    uint64_t l3_dlp : 16;
    uint64_t destination : 20;
    npl_stage2_entry_type_e type;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage2_l3_nh_destination_l3_dlp_dlp_attr_t element);
std::string to_short_string(npl_stage2_l3_nh_destination_l3_dlp_dlp_attr_t element);


struct npl_stage2_l3_nh_destination_l3_dlp_t
{
    uint64_t l3_dlp : 16;
    uint64_t destination : 20;
    npl_stage2_entry_type_e type;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage2_l3_nh_destination_l3_dlp_t element);
std::string to_short_string(npl_stage2_l3_nh_destination_l3_dlp_t element);


struct npl_stage2_wide_raw_t
{
    uint64_t payload[2];
    npl_stage2_entry_type_e type;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage2_wide_raw_t element);
std::string to_short_string(npl_stage2_wide_raw_t element);


struct npl_stage3_dspa_destination_t
{
    uint64_t destination : 20;
    npl_stage3_entry_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage3_dspa_destination_t element);
std::string to_short_string(npl_stage3_dspa_destination_t element);


struct npl_stage3_narrow_raw_t
{
    uint64_t payload : 30;
    npl_stage3_entry_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stage3_narrow_raw_t element);
std::string to_short_string(npl_stage3_narrow_raw_t element);


struct npl_stat_bank_index_len_t
{
    uint64_t value : 2;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stat_bank_index_len_t element);
std::string to_short_string(npl_stat_bank_index_len_t element);


struct npl_stat_meter_index_len_t
{
    uint64_t value : 11;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stat_meter_index_len_t element);
std::string to_short_string(npl_stat_meter_index_len_t element);


struct npl_std_ip_em_lpm_result_destination_with_default_t
{
    uint64_t is_default : 1;
    uint64_t destination : 19;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_std_ip_em_lpm_result_destination_with_default_t element);
std::string to_short_string(npl_std_ip_em_lpm_result_destination_with_default_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_std_ip_em_lpm_result_host_and_l3_dlp_t_anonymous_union_dest_or_dest_with_class_id_t
{
    npl_dest_with_class_id_t dest_with_class_id;
    npl_destination_t destination;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_std_ip_em_lpm_result_host_and_l3_dlp_t_anonymous_union_dest_or_dest_with_class_id_t element);
std::string to_short_string(npl_std_ip_em_lpm_result_host_and_l3_dlp_t_anonymous_union_dest_or_dest_with_class_id_t element);


struct npl_stop_on_step_and_next_stage_compressed_fields_t
{
    npl_rtf_stage_and_type_e next_rtf_stage;
    uint64_t stop_on_step : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_stop_on_step_and_next_stage_compressed_fields_t element);
std::string to_short_string(npl_stop_on_step_and_next_stage_compressed_fields_t element);


struct npl_svi_eve_sub_type_plus_prf_t
{
    npl_vlan_edit_command_secondary_type_e sub_type;
    uint64_t prf : 2;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_svi_eve_sub_type_plus_prf_t element);
std::string to_short_string(npl_svi_eve_sub_type_plus_prf_t element);


struct npl_svi_eve_vid2_plus_prf_t
{
    uint64_t vid2 : 12;
    uint64_t prf : 2;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_svi_eve_vid2_plus_prf_t element);
std::string to_short_string(npl_svi_eve_vid2_plus_prf_t element);


struct npl_svl_mc_data_t
{
    uint64_t mcid : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_svl_mc_data_t element);
std::string to_short_string(npl_svl_mc_data_t element);


struct npl_svl_mirror_remote_dsp_t
{
    uint64_t dsp : 11;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_svl_mirror_remote_dsp_t element);
std::string to_short_string(npl_svl_mirror_remote_dsp_t element);


struct npl_svl_traps_t
{
    uint64_t control_protocol : 1;
    uint64_t control_ipc : 1;
    uint64_t svl_mc_prune : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_svl_traps_t element);
std::string to_short_string(npl_svl_traps_t element);


struct npl_svl_uc_data_t
{
    npl_fwd_header_type_e fwd_hdr_type;
    uint64_t dsp : 11;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_svl_uc_data_t element);
std::string to_short_string(npl_svl_uc_data_t element);


struct npl_system_mcid_t
{
    uint64_t id : 18;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_system_mcid_t element);
std::string to_short_string(npl_system_mcid_t element);


struct npl_te_headend_nhlfe_t
{
    npl_destination_t lsp_destination;
    npl_compressed_counter_t counter_offset;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_te_headend_nhlfe_t element);
std::string to_short_string(npl_te_headend_nhlfe_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_te_midpoint_nhlfe_t_anonymous_union_lsp_t
{
    uint64_t swap_label : 20;
    uint64_t lsp_id : 20;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_te_midpoint_nhlfe_t_anonymous_union_lsp_t element);
std::string to_short_string(npl_te_midpoint_nhlfe_t_anonymous_union_lsp_t element);


struct npl_tm_header_base_t
{
    npl_tm_header_type_e hdr_type;
    uint64_t vce : 1;
    uint64_t tc : 3;
    uint64_t dp : 2;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_tm_header_base_t element);
std::string to_short_string(npl_tm_header_base_t element);


struct npl_tos_t
{
    uint64_t dscp : 6;
    uint64_t ecn : 2;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_tos_t element);
std::string to_short_string(npl_tos_t element);


struct npl_tpid_sa_lsb_t
{
    uint64_t sa_lsb : 16;
    uint64_t tpid : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_tpid_sa_lsb_t element);
std::string to_short_string(npl_tpid_sa_lsb_t element);


struct npl_trap_conditions_t
{
    uint64_t non_inject_up : 1;
    uint64_t skip_p2p : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_trap_conditions_t element);
std::string to_short_string(npl_trap_conditions_t element);


struct npl_traps_t
{
    npl_ethernet_traps_t ethernet;
    npl_ipv4_traps_t ipv4;
    npl_ipv6_traps_t ipv6;
    npl_mpls_traps_t mpls;
    npl_l3_traps_t l3;
    npl_oamp_traps_t oamp;
    npl_app_traps_t app;
    npl_svl_traps_t svl;
    npl_l2_lpts_traps_t l2_lpts;
    npl_internal_traps_t internal;
    bit_vector384_t pack(void) const;
    void unpack(bit_vector384_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_traps_t element);
std::string to_short_string(npl_traps_t element);


struct npl_ts_cmd_trans_t
{
    npl_txpp_ts_cmd_e op;
    uint64_t udp_offset_sel : 1;
    uint64_t update_udp_cs : 1;
    uint64_t reset_udp_cs : 1;
    npl_ifg_ts_cmd_e ifg_ts_cmd;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ts_cmd_trans_t element);
std::string to_short_string(npl_ts_cmd_trans_t element);


struct npl_ts_command_t
{
    uint64_t op : 4;
    uint64_t offset : 7;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ts_command_t element);
std::string to_short_string(npl_ts_command_t element);


struct npl_ttl_and_protocol_t
{
    uint64_t ttl : 8;
    uint64_t protocol : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ttl_and_protocol_t element);
std::string to_short_string(npl_ttl_and_protocol_t element);


struct npl_tunnel_control_t
{
    uint64_t decrement_inner_ttl : 1;
    npl_ttl_mode_e ttl_mode;
    uint64_t is_tos_from_tunnel : 1;
    uint64_t lp_set : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_tunnel_control_t element);
std::string to_short_string(npl_tunnel_control_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_tunnel_headend_encap_t_anonymous_union_te_asbr_t
{
    uint64_t te_tunnel : 16;
    uint64_t asbr : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_tunnel_headend_encap_t_anonymous_union_te_asbr_t element);
std::string to_short_string(npl_tunnel_headend_encap_t_anonymous_union_te_asbr_t element);


struct npl_tunnel_type_q_counter_t
{
    npl_ip_tunnel_encap_type_e tunnel_type;
    uint64_t q_counter : 19;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_tunnel_type_q_counter_t element);
std::string to_short_string(npl_tunnel_type_q_counter_t element);


struct npl_tunnel_underlay_mc_da_qos_payload_t
{
    uint64_t nh_encap_da : 48;
    npl_fwd_qos_tag_t muxed_qos_group;
    npl_fwd_qos_tag_t local_mapping_qos_tag;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_tunnel_underlay_mc_da_qos_payload_t element);
std::string to_short_string(npl_tunnel_underlay_mc_da_qos_payload_t element);


struct npl_tx_punt_nw_encap_ptr_t
{
    npl_punt_nw_encap_type_e punt_nw_encap_type;
    npl_punt_nw_encap_ptr_t punt_nw_encap_ptr;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_tx_punt_nw_encap_ptr_t element);
std::string to_short_string(npl_tx_punt_nw_encap_ptr_t element);


struct npl_txpp_em_dlp_profile_mapping_key_t
{
    uint64_t dlp_type : 2;
    uint64_t dlp_id : 18;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_txpp_em_dlp_profile_mapping_key_t element);
std::string to_short_string(npl_txpp_em_dlp_profile_mapping_key_t element);


struct npl_txpp_first_macro_table_key_t
{
    uint64_t is_mc : 1;
    uint64_t fwd_type : 4;
    uint64_t encap_type : 4;
    uint64_t field_a : 8;
    uint64_t field_b : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_txpp_first_macro_table_key_t element);
std::string to_short_string(npl_txpp_first_macro_table_key_t element);


struct npl_udf_t
{
    uint64_t value[2];
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_udf_t element);
std::string to_short_string(npl_udf_t element);


struct npl_udp_encap_data_t
{
    uint64_t sport : 16;
    uint64_t dport : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_udp_encap_data_t element);
std::string to_short_string(npl_udp_encap_data_t element);


struct npl_unicast_flb_tm_header_t
{
    npl_tm_header_base_t base;
    uint64_t reserved : 3;
    uint64_t dsp : 13;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_unicast_flb_tm_header_t element);
std::string to_short_string(npl_unicast_flb_tm_header_t element);


struct npl_unicast_plb_tm_header_t
{
    npl_tm_header_base_t base;
    uint64_t reserved : 3;
    uint64_t destination_device : 9;
    uint64_t destination_slice : 3;
    uint64_t destination_oq : 9;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_unicast_plb_tm_header_t element);
std::string to_short_string(npl_unicast_plb_tm_header_t element);


struct npl_unscheduled_recycle_code_t
{
    uint64_t recycle_pkt : 1;
    uint64_t unscheduled_recycle_code_lsb : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_unscheduled_recycle_code_t element);
std::string to_short_string(npl_unscheduled_recycle_code_t element);


struct npl_use_metedata_table_per_packet_format_t
{
    npl_bool_t use_metadata_table_for_ip_packet;
    npl_bool_t use_metadata_table_for_non_ip_packet;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_use_metedata_table_per_packet_format_t element);
std::string to_short_string(npl_use_metedata_table_per_packet_format_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_vid2_or_flood_rcy_sm_vlans_t
{
    uint64_t vid2 : 12;
    npl_rcy_sm_vlans_t flood_rcy_sm_vlans;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_vid2_or_flood_rcy_sm_vlans_t element);
std::string to_short_string(npl_vid2_or_flood_rcy_sm_vlans_t element);


struct npl_vlan_and_sa_lsb_encap_t
{
    uint64_t vlan_id : 12;
    npl_tpid_sa_lsb_t tpid_sa_lsb;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_vlan_and_sa_lsb_encap_t element);
std::string to_short_string(npl_vlan_and_sa_lsb_encap_t element);


struct npl_vlan_edit_secondary_type_with_padding_t
{
    npl_vlan_edit_command_secondary_type_e secondary_type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_vlan_edit_secondary_type_with_padding_t element);
std::string to_short_string(npl_vlan_edit_secondary_type_with_padding_t element);


struct npl_vlan_header_flags_t
{
    uint64_t is_priority : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_vlan_header_flags_t element);
std::string to_short_string(npl_vlan_header_flags_t element);


struct npl_vlan_id_t
{
    uint64_t id : 12;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_vlan_id_t element);
std::string to_short_string(npl_vlan_id_t element);


struct npl_vlan_profile_and_lp_type_t
{
    npl_l2_lp_type_e l2_lp_type;
    uint64_t vlan_profile : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_vlan_profile_and_lp_type_t element);
std::string to_short_string(npl_vlan_profile_and_lp_type_t element);


struct npl_vlan_tag_tci_t
{
    npl_pcp_dei_t pcp_dei;
    npl_vlan_id_t vid;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_vlan_tag_tci_t element);
std::string to_short_string(npl_vlan_tag_tci_t element);


struct npl_vni_table_result_t
{
    uint64_t vlan_profile : 4;
    npl_l2_relay_id_t l2_relay_attributes_id;
    npl_counter_ptr_t vni_counter;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_vni_table_result_t element);
std::string to_short_string(npl_vni_table_result_t element);


struct npl_voq_cgm_slice_buffers_consumption_lut_for_deq_results_t
{
    npl_quan_4b congestion_level[16];
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_voq_cgm_slice_buffers_consumption_lut_for_deq_results_t element);
std::string to_short_string(npl_voq_cgm_slice_buffers_consumption_lut_for_deq_results_t element);


struct npl_voq_cgm_slice_dram_consumption_lut_for_deq_results_t
{
    npl_quan_4b congestion_level[8];
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_voq_cgm_slice_dram_consumption_lut_for_deq_results_t element);
std::string to_short_string(npl_voq_cgm_slice_dram_consumption_lut_for_deq_results_t element);


struct npl_voq_cgm_slice_drop_color_probability_selector_results_t
{
    npl_quan_5b drop_prob[6];
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_voq_cgm_slice_drop_color_probability_selector_results_t element);
std::string to_short_string(npl_voq_cgm_slice_drop_color_probability_selector_results_t element);


struct npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_result_t
{
    uint64_t drop_yellow : 1;
    uint64_t drop_green : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_result_t element);
std::string to_short_string(npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_result_t element);


struct npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_results_t
{
    uint64_t drop_on_eviction : 1;
    uint64_t eviction_ok : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_results_t element);
std::string to_short_string(npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_results_t element);


struct npl_voq_cgm_slice_mark_color_probability_selector_results_t
{
    npl_quan_5b mark_yellow_prob[3];
    npl_quan_5b mark_green_prob[3];
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_voq_cgm_slice_mark_color_probability_selector_results_t element);
std::string to_short_string(npl_voq_cgm_slice_mark_color_probability_selector_results_t element);


struct npl_voq_cgm_slice_pd_consumption_lut_for_deq_results_t
{
    npl_quan_4b congestion_level[16];
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_voq_cgm_slice_pd_consumption_lut_for_deq_results_t element);
std::string to_short_string(npl_voq_cgm_slice_pd_consumption_lut_for_deq_results_t element);


struct npl_voq_cgm_slice_pd_consumption_lut_for_enq_results_t
{
    npl_quan_1b mark_yellow[16];
    npl_quan_1b mark_green[16];
    npl_quan_1b evict_to_dram[16];
    npl_quan_1b drop_yellow[16];
    npl_quan_1b drop_green[16];
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_voq_cgm_slice_pd_consumption_lut_for_enq_results_t element);
std::string to_short_string(npl_voq_cgm_slice_pd_consumption_lut_for_enq_results_t element);


struct npl_voq_cgm_slice_profile_buff_region_thresholds_results_t
{
    npl_quan_14b q_size_buff_region[15];
    bit_vector384_t pack(void) const;
    void unpack(bit_vector384_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_voq_cgm_slice_profile_buff_region_thresholds_results_t element);
std::string to_short_string(npl_voq_cgm_slice_profile_buff_region_thresholds_results_t element);


struct npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results_t
{
    npl_quan_8b pkt_enq_time_region[15];
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results_t element);
std::string to_short_string(npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results_t element);


struct npl_voq_cgm_slice_profile_pkt_region_thresholds_results_t
{
    npl_quan_14b q_size_pkt_region[7];
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_voq_cgm_slice_profile_pkt_region_thresholds_results_t element);
std::string to_short_string(npl_voq_cgm_slice_profile_pkt_region_thresholds_results_t element);


struct npl_voq_cgm_slice_slice_cgm_profile_result_t
{
    npl_voq_cgm_pd_counter_e counter_id;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_voq_cgm_slice_slice_cgm_profile_result_t element);
std::string to_short_string(npl_voq_cgm_slice_slice_cgm_profile_result_t element);


struct npl_voq_cgm_wred_probability_region_id_t
{
    uint64_t region_id : 5;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_voq_cgm_wred_probability_region_id_t element);
std::string to_short_string(npl_voq_cgm_wred_probability_region_id_t element);


struct npl_voq_cgm_wred_probability_results_t
{
    npl_quan_17b probability;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_voq_cgm_wred_probability_results_t element);
std::string to_short_string(npl_voq_cgm_wred_probability_results_t element);


struct npl_voq_profile_len
{
    uint64_t value : 5;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_voq_profile_len element);
std::string to_short_string(npl_voq_profile_len element);


struct npl_vpl_label_and_valid_t
{
    uint64_t v6_label_vld : 1;
    uint64_t v4_label_vld : 1;
    npl_exp_bos_and_label_t label_encap;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_vpl_label_and_valid_t element);
std::string to_short_string(npl_vpl_label_and_valid_t element);


struct npl_vxlan_dlp_specific_t
{
    uint64_t group_policy_encap : 1;
    uint64_t stp_state_is_block : 1;
    uint64_t lp_profile : 2;
    npl_ttl_mode_e ttl_mode;
    uint64_t disabled : 1;
    uint64_t lp_set : 1;
    npl_qos_info_t qos_info;
    npl_counter_ptr_t p_counter;
    uint64_t sip_index : 4;
    npl_ip_tunnel_dip_t dip;
    uint64_t ttl : 8;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_vxlan_dlp_specific_t element);
std::string to_short_string(npl_vxlan_dlp_specific_t element);


struct npl_vxlan_encap_data_t
{
    uint64_t group_policy_id : 16;
    uint64_t vni : 24;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_vxlan_encap_data_t element);
std::string to_short_string(npl_vxlan_encap_data_t element);


struct npl_vxlan_relay_encap_data_t
{
    uint64_t vni : 24;
    npl_counter_ptr_t vni_counter;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_vxlan_relay_encap_data_t element);
std::string to_short_string(npl_vxlan_relay_encap_data_t element);


struct npl_wfq_priority_weight_t
{
    uint64_t weight : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_wfq_priority_weight_t element);
std::string to_short_string(npl_wfq_priority_weight_t element);


struct npl_wfq_weight_4p_entry_t
{
    npl_wfq_priority_weight_t priority[4];
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_wfq_weight_4p_entry_t element);
std::string to_short_string(npl_wfq_weight_4p_entry_t element);


struct npl_wfq_weight_8p_t
{
    npl_wfq_priority_weight_t priority[8];
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_wfq_weight_8p_t element);
std::string to_short_string(npl_wfq_weight_8p_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_wide_protection_entry_t
{
    npl_stage0_l2_dlp_destination_l2_dlp_t stage0_l2_dlp_dest_l2_dlp;
    npl_stage1_p_l3_nh_destination_with_common_data_t stage1_nh_dest;
    npl_stage1_l3_nh_te_tunnel16b1_t stage1_te_tunnel;
    npl_stage1_protected_raw_t stage1_raw;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_wide_protection_entry_t element);
std::string to_short_string(npl_wide_protection_entry_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_app_relay_id_t
{
    npl_l2_relay_id_t l2_relay_id;
    npl_l3_relay_id_t l3_relay_id;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_app_relay_id_t element);
std::string to_short_string(npl_app_relay_id_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_base_l3_lp_attributes_t_anonymous_union_rtf_conf_set_and_stages_or_post_fwd_stage_t
{
    npl_rtf_conf_set_and_stages_t rtf_conf_set_and_stages;
    npl_ip_ver_and_post_fwd_stage_t ip_ver_and_post_fwd_stage;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_base_l3_lp_attributes_t_anonymous_union_rtf_conf_set_and_stages_or_post_fwd_stage_t element);
std::string to_short_string(npl_base_l3_lp_attributes_t_anonymous_union_rtf_conf_set_and_stages_or_post_fwd_stage_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_bfd_aux_shared_payload_t_anonymous_union_prot_shared_t
{
    npl_bfd_ipv6_prot_shared_t ipv6;
    npl_bfd_ipv4_prot_shared_t ipv4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_aux_shared_payload_t_anonymous_union_prot_shared_t element);
std::string to_short_string(npl_bfd_aux_shared_payload_t_anonymous_union_prot_shared_t element);


struct npl_bfd_aux_transmit_payload_t
{
    // This is an NPL anonymous union.
    npl_bfd_aux_transmit_payload_t_anonymous_union_prot_trans_t prot_trans;
    uint64_t interval_selector : 3;
    uint64_t echo_mode_enabled : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_aux_transmit_payload_t element);
std::string to_short_string(npl_bfd_aux_transmit_payload_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_bfd_flags_state_t_anonymous_union_bfd_flags_t
{
    npl_bfd_flags_t indiv_flags;
    uint64_t flags : 6;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_flags_state_t_anonymous_union_bfd_flags_t element);
std::string to_short_string(npl_bfd_flags_state_t_anonymous_union_bfd_flags_t element);


struct npl_bfd_mp_table_extra_payload_t
{
    npl_mpls_header_t mpls_label;
    npl_bfd_mp_table_transmit_b_payload_t extra_tx_b;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_mp_table_extra_payload_t element);
std::string to_short_string(npl_bfd_mp_table_extra_payload_t element);


struct npl_bfd_mp_table_shared_msb_t
{
    // This is an NPL anonymous union.
    npl_bfd_mp_table_shared_msb_t_anonymous_union_trans_data_t trans_data;
    npl_bfd_transport_and_label_t transport_label;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_mp_table_shared_msb_t element);
std::string to_short_string(npl_bfd_mp_table_shared_msb_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_common_cntr_offset_and_padding_t_anonymous_union_cntr_offset_t
{
    npl_common_cntr_offset_t offset;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_common_cntr_offset_and_padding_t_anonymous_union_cntr_offset_t element);
std::string to_short_string(npl_common_cntr_offset_and_padding_t_anonymous_union_cntr_offset_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_common_cntr_offset_packed_t_anonymous_union_cntr_offset_t
{
    npl_common_cntr_offset_t offset;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_common_cntr_offset_packed_t_anonymous_union_cntr_offset_t element);
std::string to_short_string(npl_common_cntr_offset_packed_t_anonymous_union_cntr_offset_t element);


struct npl_db_access_fwd_info_header_t
{
    // This is an NPL anonymous union.
    npl_db_access_fwd_info_header_t_anonymous_union_macro_or_fwd_dest_t macro_or_fwd_dest;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_db_access_fwd_info_header_t element);
std::string to_short_string(npl_db_access_fwd_info_header_t element);


struct npl_db_access_fwd_macro_dests_header_t
{
    npl_fwd_bucket_a_lu_dest_e bucket_a_lu_dest;
    npl_fwd_bucket_b_lu_dest_e bucket_b_lu_dest;
    npl_fwd_bucket_c_lu_dest_e bucket_c_lu_dest;
    npl_fwd_bucket_d_lu_dest_e bucket_d_lu_dest;
    npl_fwd_bucket_a_result_dest_e bucket_a_result_dest;
    npl_fwd_bucket_b_result_dest_e bucket_b_result_dest;
    npl_fwd_bucket_c_result_dest_e bucket_c_result_dest;
    npl_fwd_bucket_d_result_dest_e bucket_d_result_dest;
    npl_db_access_key_selectors_header_t db_access_key_selectors_header;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_db_access_fwd_macro_dests_header_t element);
std::string to_short_string(npl_db_access_fwd_macro_dests_header_t element);


struct npl_demux_pif_ifg_t
{
    uint64_t pad : 1;
    npl_pif_ifg_base_t pif_ifg;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_demux_pif_ifg_t element);
std::string to_short_string(npl_demux_pif_ifg_t element);


struct npl_destination_prefix_lp_t
{
    uint64_t prefix : 4;
    npl_l3_dlp_lsbs_t lsbs;
    npl_l3_dlp_msbs_t msbs;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_destination_prefix_lp_t element);
std::string to_short_string(npl_destination_prefix_lp_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_dlp_profile_t
{
    npl_qos_and_acl_ids_t l2;
    npl_sec_acl_ids_t l3_sec;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_dlp_profile_t element);
std::string to_short_string(npl_dlp_profile_t element);


struct npl_drop_color_t
{
    npl_quan_3b drop_color[16];
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_drop_color_t element);
std::string to_short_string(npl_drop_color_t element);


struct npl_dsp_attr_common_t
{
    uint64_t dsp_is_dma : 1;
    npl_dsp_map_info_t dsp_map_info;
    uint64_t mask_egress_vlan_edit : 1;
    uint64_t dsp : 16;
    uint64_t svl_vpc_prune_port : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_dsp_attr_common_t element);
std::string to_short_string(npl_dsp_attr_common_t element);


struct npl_dsp_l2_attributes_t
{
    uint64_t mc_pruning_low : 16;
    uint64_t mc_pruning_high : 16;
    npl_dsp_attr_common_t dsp_attr_common;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_dsp_l2_attributes_t element);
std::string to_short_string(npl_dsp_l2_attributes_t element);


struct npl_dsp_l3_attributes_t
{
    uint64_t mtu : 14;
    uint64_t no_decrement_ttl : 1;
    npl_ttl_mode_e mpls_ip_ttl_propagation;
    npl_dsp_attr_common_t dsp_attr_common;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_dsp_l3_attributes_t element);
std::string to_short_string(npl_dsp_l3_attributes_t element);


struct npl_egress_sec_acl_result_t
{
    npl_drop_punt_or_permit_t drop_punt_or_permit;
    uint64_t mirror_valid : 1;
    // This is an NPL anonymous union.
    npl_egress_sec_acl_result_t_anonymous_union_drop_or_permit_t drop_or_permit;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_egress_sec_acl_result_t element);
std::string to_short_string(npl_egress_sec_acl_result_t element);


struct npl_em_destination_t
{
    npl_destination_prefix_lp_t em_rpf_src;
    npl_dest_class_id_t class_id;
    npl_destination_t dest;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_em_destination_t element);
std::string to_short_string(npl_em_destination_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_em_payload_t
{
    npl_ethernet_oam_em_t ethernet_oam;
    npl_bfd_em_t bfd;
    npl_mpls_tp_em_t mpls_tp;
    npl_pfc_em_t pfc;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_em_payload_t element);
std::string to_short_string(npl_em_payload_t element);


struct npl_em_result_dsp_host_w_class_t
{
    // This is an NPL anonymous union.
    npl_em_result_dsp_host_w_class_t_anonymous_union_dest_type_or_has_class_t dest_type_or_has_class;
    uint64_t class_id : 4;
    uint64_t dest : 8;
    uint64_t host_mac_msb : 7;
    uint64_t extra_dest_bit : 1;
    uint64_t host_mac_lsb : 40;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_em_result_dsp_host_w_class_t element);
std::string to_short_string(npl_em_result_dsp_host_w_class_t element);


struct npl_ene_inject_down_payload_t
{
    npl_inject_down_encap_type_e ene_inject_down_encap_type;
    npl_phb_t ene_inject_phb;
    npl_destination_t ene_inject_destination;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ene_inject_down_payload_t element);
std::string to_short_string(npl_ene_inject_down_payload_t element);


struct npl_ene_punt_dsp_and_ssp_t
{
    npl_punt_ssp_t ssp;
    uint64_t dsp : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ene_punt_dsp_and_ssp_t element);
std::string to_short_string(npl_ene_punt_dsp_and_ssp_t element);


struct npl_eth_oam_aux_shared_payload_t
{
    npl_meg_id_t meg_id;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_eth_oam_aux_shared_payload_t element);
std::string to_short_string(npl_eth_oam_aux_shared_payload_t element);


struct npl_eth_rtf_iteration_properties_t
{
    npl_eth_rtf_prop_over_fwd0_t f0_rtf_prop;
    npl_stop_on_step_and_next_stage_compressed_fields_t stop_on_step_and_next_stage_compressed_fields;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_eth_rtf_iteration_properties_t element);
std::string to_short_string(npl_eth_rtf_iteration_properties_t element);


struct npl_ethernet_mac_t
{
    npl_mac_addr_t da;
    npl_mac_addr_t sa;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ethernet_mac_t element);
std::string to_short_string(npl_ethernet_mac_t element);


struct npl_flc_header_types_array_data_t
{
    npl_flc_range_comp_profile_sel_t range_comp_sel_3;
    npl_flc_range_comp_profile_sel_t range_comp_sel_2;
    npl_flc_range_comp_profile_sel_t range_comp_sel_1;
    npl_flc_range_comp_profile_sel_t range_comp_sel_0;
    uint64_t range_comp_vld_3 : 1;
    uint64_t range_comp_vld_2 : 1;
    uint64_t range_comp_vld_1 : 1;
    uint64_t range_comp_vld_0 : 1;
    uint64_t use_cache : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_flc_header_types_array_data_t element);
std::string to_short_string(npl_flc_header_types_array_data_t element);


struct npl_force_pipe_ttl_ingress_ptp_info_t
{
    npl_ingress_ptp_info_t ingress_ptp_info;
    uint64_t force_pipe_ttl : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_force_pipe_ttl_ingress_ptp_info_t element);
std::string to_short_string(npl_force_pipe_ttl_ingress_ptp_info_t element);


struct npl_gb_std_ip_em_lpm_result_destination_with_default_t
{
    npl_std_ip_em_lpm_result_destination_with_default_t destination_with_default;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_gb_std_ip_em_lpm_result_destination_with_default_t element);
std::string to_short_string(npl_gb_std_ip_em_lpm_result_destination_with_default_t element);


struct npl_gre_tunnel_attributes_t
{
    uint64_t demux_count : 1;
    npl_gre_dip_entropy_e dip_entropy;
    npl_qos_encap_t tunnel_qos_encap;
    npl_tunnel_control_t tunnel_control;
    npl_qos_info_t qos_info;
    npl_counter_ptr_t p_counter;
    npl_tunnel_type_q_counter_t tunnel_type_q_counter;
    uint64_t sip_index : 4;
    uint64_t dip : 32;
    uint64_t gre_flags : 8;
    uint64_t ttl : 8;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_gre_tunnel_attributes_t element);
std::string to_short_string(npl_gre_tunnel_attributes_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_header_flags_t
{
    uint64_t all_header_flags : 3;
    npl_ipv4_header_flags_t ipv4_header_flags;
    npl_ipv6_header_flags_t ipv6_header_flags;
    npl_vlan_header_flags_t vlan_header_flags;
    npl_ethernet_header_flags_t ethernet_header_flags;
    npl_mpls_header_flags_t mpls_header_flags;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_header_flags_t element);
std::string to_short_string(npl_header_flags_t element);


struct npl_header_format_t
{
    npl_header_flags_t flags;
    npl_protocol_type_e type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_header_format_t element);
std::string to_short_string(npl_header_format_t element);


struct npl_hmc_cgm_profile_global_results_t
{
    uint64_t wred_ema_weight : 4;
    npl_quan_13b wred_fcn_probability_region[16];
    npl_quan_19b wred_region_borders[15];
    uint64_t wred_fcn_enable : 1;
    npl_quan_5b alpha_dpo1;
    npl_quan_15b shared_resource_threshold_dp1;
    npl_quan_5b alpha_dpo0;
    npl_quan_15b shared_resource_threshold_dp0;
    uint64_t shared_resource_threshold_mode : 1;
    uint64_t shared_pool_id : 1;
    bit_vector pack(void) const;
    void unpack(bit_vector);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_hmc_cgm_profile_global_results_t element);
std::string to_short_string(npl_hmc_cgm_profile_global_results_t element);


struct npl_ibm_cmd_table_result_t
{
    uint64_t sampling_probability : 18;
    uint64_t is_mc : 1;
    uint64_t ignore_in_rxrq_sel : 1;
    uint64_t mirror_to_dest : 1;
    uint64_t tc_map_profile : 3;
    uint64_t destination_device : 9;
    // This is an NPL anonymous union.
    npl_ibm_cmd_table_result_t_anonymous_union_voq_or_bitmap_t voq_or_bitmap;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ibm_cmd_table_result_t element);
std::string to_short_string(npl_ibm_cmd_table_result_t element);


struct npl_ingress_ptp_info_and_is_slp_dm_cmpressed_fields_t
{
    uint64_t is_slp_dm : 1;
    npl_ingress_ptp_info_t ingress_ptp_info;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ingress_ptp_info_and_is_slp_dm_cmpressed_fields_t element);
std::string to_short_string(npl_ingress_ptp_info_and_is_slp_dm_cmpressed_fields_t element);


struct npl_ingress_qos_remark_t
{
    // This is an NPL anonymous union.
    npl_ingress_qos_remark_t_anonymous_union_encap_qos_tag_u_t encap_qos_tag_u;
    uint64_t qos_group : 7;
    uint64_t fwd_qos_tag : 7;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ingress_qos_remark_t element);
std::string to_short_string(npl_ingress_qos_remark_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_initial_pd_nw_rx_data_t_anonymous_union_mapping_key_t
{
    npl_lp_id_t initial_lp_id;
    uint64_t mpls_label_placeholder : 20;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_initial_pd_nw_rx_data_t_anonymous_union_mapping_key_t element);
std::string to_short_string(npl_initial_pd_nw_rx_data_t_anonymous_union_mapping_key_t element);


struct npl_initial_recycle_pd_nw_rx_data_t
{
    // This is an NPL anonymous union.
    npl_initial_recycle_pd_nw_rx_data_t_anonymous_union_init_data_t init_data;
    npl_mac_mapping_type_e initial_mapping_type;
    uint64_t initial_is_rcy_if : 1;
    npl_mac_lp_type_e initial_mac_lp_type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_initial_recycle_pd_nw_rx_data_t element);
std::string to_short_string(npl_initial_recycle_pd_nw_rx_data_t element);


struct npl_inject_down_header_t
{
    npl_inject_down_encap_type_e inject_down_encap_type;
    npl_phb_t inject_phb;
    npl_destination_t inject_destination;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_down_header_t element);
std::string to_short_string(npl_inject_down_header_t element);


struct npl_inject_ts_and_lm_cmd_t
{
    npl_ts_command_t time_stamp_cmd;
    npl_lm_command_t counter_stamp_cmd;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_ts_and_lm_cmd_t element);
std::string to_short_string(npl_inject_ts_and_lm_cmd_t element);


struct npl_inject_up_eth_qos_t
{
    npl_inject_up_hdr_phb_src_e inject_up_hdr_phb_src;
    npl_phb_t inject_up_phb;
    uint64_t inject_up_qos_group : 7;
    uint64_t inject_up_fwd_qos_tag : 7;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_up_eth_qos_t element);
std::string to_short_string(npl_inject_up_eth_qos_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_ip_encap_data_t_anonymous_union_upper_layer_t
{
    npl_vxlan_encap_data_t vxlan_data;
    npl_gre_encap_data_t gre_data;
    npl_udp_encap_data_t udp_data;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_encap_data_t_anonymous_union_upper_layer_t element);
std::string to_short_string(npl_ip_encap_data_t_anonymous_union_upper_layer_t element);


struct npl_ip_lpm_result_t
{
    npl_dest_class_id_t class_id;
    // This is an NPL anonymous union.
    npl_ip_lpm_result_t_anonymous_union_destination_or_default_t destination_or_default;
    // This is an NPL anonymous union.
    npl_ip_lpm_result_t_anonymous_union_rtype_or_is_fec_t rtype_or_is_fec;
    uint64_t no_hbm_access : 1;
    uint64_t is_default_unused : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_lpm_result_t element);
std::string to_short_string(npl_ip_lpm_result_t element);


struct npl_ip_muxed_fields_t
{
    npl_soft_lb_wa_enable_t muxed_soft_lb_wa_enable;
    uint64_t muxed_is_bfd_and_udp : 1;
    uint64_t muxed_is_bfd : 1;
    uint64_t muxed_is_hop_by_hop : 1;
    uint64_t muxed_is_udp : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_muxed_fields_t element);
std::string to_short_string(npl_ip_muxed_fields_t element);


struct npl_ip_rtf_iteration_properties_t
{
    npl_rtf_iter_prop_over_fwd0_t f0_rtf_prop;
    npl_rtf_iter_prop_over_fwd1_t f1_rtf_prop;
    npl_stop_on_step_and_next_stage_compressed_fields_t stop_on_step_and_next_stage_compressed_fields;
    uint64_t use_fwd1_interface : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_rtf_iteration_properties_t element);
std::string to_short_string(npl_ip_rtf_iteration_properties_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_ip_sgt_em_result_t_anonymous_union_result_t
{
    npl_ip_sgt_result_t sgt_data;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_sgt_em_result_t_anonymous_union_result_t element);
std::string to_short_string(npl_ip_sgt_em_result_t_anonymous_union_result_t element);


struct npl_ip_sgt_lpm_result_t
{
    npl_ip_sgt_result_t sgt_data;
    uint64_t rtype : 2;
    uint64_t no_hbm_access : 1;
    uint64_t is_default_unused : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_sgt_lpm_result_t element);
std::string to_short_string(npl_ip_sgt_lpm_result_t element);


struct npl_ipv4_encap_data_t
{
    npl_ttl_and_protocol_t ene_ttl_and_protocol;
    npl_ipv4_sip_dip_t ene_ipv4_sip_dip;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ipv4_encap_data_t element);
std::string to_short_string(npl_ipv4_encap_data_t element);


struct npl_ipv4_ipv6_eth_init_rtf_stages_t
{
    npl_ipv4_ipv6_init_rtf_stage_t ipv4_ipv6_init_rtf_stage;
    npl_rtf_stage_and_type_e eth_init_rtf_stage;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ipv4_ipv6_eth_init_rtf_stages_t element);
std::string to_short_string(npl_ipv4_ipv6_eth_init_rtf_stages_t element);


struct npl_ipv6_encap_data_t
{
    npl_next_header_and_hop_limit_t ene_nh_and_hl;
    uint64_t ene_ipv6_sip_msb : 64;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ipv6_encap_data_t element);
std::string to_short_string(npl_ipv6_encap_data_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_ive_profile_and_data_t_anonymous_union_secondary_type_or_vid_2_t
{
    npl_vlan_edit_secondary_type_with_padding_t secondary_type_with_padding;
    uint64_t vid2 : 12;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ive_profile_and_data_t_anonymous_union_secondary_type_or_vid_2_t element);
std::string to_short_string(npl_ive_profile_and_data_t_anonymous_union_secondary_type_or_vid_2_t element);


struct npl_l2_ac_encap_t
{
    npl_npu_encap_header_l2_dlp_t l2_dlp;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2_ac_encap_t element);
std::string to_short_string(npl_l2_ac_encap_t element);


struct npl_l2_dlp_attr_on_nh_t
{
    npl_nh_ene_macro_code_e nh_ene_macro_code;
    uint64_t l2_tpid_prof : 2;
    npl_qos_attributes_t l2_dlp_qos_and_attr;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2_dlp_attr_on_nh_t element);
std::string to_short_string(npl_l2_dlp_attr_on_nh_t element);


struct npl_l2_lp_with_padding_t
{
    npl_punt_l2_lp_t l2_lp;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2_lp_with_padding_t element);
std::string to_short_string(npl_l2_lp_with_padding_t element);


struct npl_l2_lpts_payload_t
{
    uint64_t lacp : 1;
    uint64_t l2cp0 : 1;
    uint64_t l2cp1 : 1;
    uint64_t l2cp2 : 1;
    uint64_t l2cp3 : 1;
    uint64_t l2cp4 : 1;
    uint64_t l2cp5 : 1;
    uint64_t l2cp6 : 1;
    uint64_t l2cp7 : 1;
    uint64_t cisco_protocols : 1;
    uint64_t isis_over_l2 : 1;
    uint64_t isis_drain : 1;
    uint64_t isis_over_l3 : 1;
    uint64_t arp : 1;
    uint64_t ptp_over_eth : 1;
    uint64_t macsec : 1;
    uint64_t dhcpv4_server : 1;
    uint64_t dhcpv4_client : 1;
    uint64_t dhcpv6_server : 1;
    uint64_t dhcpv6_client : 1;
    npl_l2_lpts_traps_t rsvd;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2_lpts_payload_t element);
std::string to_short_string(npl_l2_lpts_payload_t element);


struct npl_l2_mc_cud_narrow_t
{
    npl_npu_encap_l2_header_type_e l2_encapsulation_type;
    npl_l2_ac_encap_t l2_ac_encdap;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2_mc_cud_narrow_t element);
std::string to_short_string(npl_l2_mc_cud_narrow_t element);


struct npl_l2_rtf_conf_set_and_init_stages_t
{
    npl_rtf_conf_set_and_stages_t rtf_conf_set_and_stages;
    npl_rtf_stage_and_type_e eth_rtf_stage;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2_rtf_conf_set_and_init_stages_t element);
std::string to_short_string(npl_l2_rtf_conf_set_and_init_stages_t element);


struct npl_l3_dlp_encap_t
{
    uint64_t sa_prefix_index : 4;
    npl_vlan_and_sa_lsb_encap_t vlan_and_sa_lsb_encap;
    npl_vid2_or_flood_rcy_sm_vlans_t vid2_or_flood_rcy_sm_vlans;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_dlp_encap_t element);
std::string to_short_string(npl_l3_dlp_encap_t element);


struct npl_l3_dlp_id_t
{
    npl_l3_dlp_msbs_t msbs;
    npl_l3_dlp_lsbs_t lsbs;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_dlp_id_t element);
std::string to_short_string(npl_l3_dlp_id_t element);


struct npl_l3_dlp_t
{
    npl_l3_dlp_id_t id;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_dlp_t element);
std::string to_short_string(npl_l3_dlp_t element);


struct npl_l3_lp_additional_attributes_t
{
    uint64_t lp_profile : 2;
    npl_lb_profile_enum_e load_balance_profile;
    uint64_t enable_monitor : 1;
    npl_slp_based_fwd_and_per_vrf_mpls_fwd_t slp_based_fwd_and_per_vrf_mpls_fwd;
    uint64_t qos_id : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_lp_additional_attributes_t element);
std::string to_short_string(npl_l3_lp_additional_attributes_t element);


struct npl_l3_sa_lsb_on_nh_t
{
    uint64_t sa_prefix_index : 4;
    npl_tpid_sa_lsb_t tpid_sa_lsb;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_sa_lsb_on_nh_t element);
std::string to_short_string(npl_l3_sa_lsb_on_nh_t element);


struct npl_l3_slp_id_t
{
    npl_l3_slp_msbs_t msbs;
    npl_l3_slp_lsbs_t lsbs;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_slp_id_t element);
std::string to_short_string(npl_l3_slp_id_t element);


struct npl_l3_vxlan_encap_t
{
    npl_npu_encap_header_l2_dlp_t tunnel_dlp;
    uint64_t overlay_nh : 10;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_vxlan_encap_t element);
std::string to_short_string(npl_l3_vxlan_encap_t element);


struct npl_l3_vxlan_relay_encap_data_t
{
    npl_overlay_nh_data_t overlay_nh_data;
    uint64_t vni : 24;
    npl_counter_ptr_t vni_counter;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_vxlan_relay_encap_data_t element);
std::string to_short_string(npl_l3_vxlan_relay_encap_data_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_label_or_num_labels_t
{
    uint64_t label : 20;
    npl_num_labels_t num_labels;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_label_or_num_labels_t element);
std::string to_short_string(npl_label_or_num_labels_t element);


struct npl_ldp_over_te_tunnel_data_t
{
    uint64_t num_labels : 2;
    npl_lsp_labels_t lsp_labels;
    npl_counter_ptr_t te_counter;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ldp_over_te_tunnel_data_t element);
std::string to_short_string(npl_ldp_over_te_tunnel_data_t element);


struct npl_lpm_std_ip_em_lpm_result_destination_t
{
    // This is an NPL anonymous union.
    npl_lpm_std_ip_em_lpm_result_destination_t_anonymous_union_union_for_padding_t union_for_padding;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lpm_std_ip_em_lpm_result_destination_t element);
std::string to_short_string(npl_lpm_std_ip_em_lpm_result_destination_t element);


struct npl_lpts_object_groups_t
{
    npl_og_lpts_compression_code_t src_code;
    npl_og_lpts_compression_code_t dest_code;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lpts_object_groups_t element);
std::string to_short_string(npl_lpts_object_groups_t element);


struct npl_lpts_payload_t
{
    npl_phb_t phb;
    uint64_t destination : 20;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lpts_payload_t element);
std::string to_short_string(npl_lpts_payload_t element);


struct npl_lsp_destination_t
{
    npl_lsp_type_t lsp_type;
    uint64_t lsp_dest_prefix : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lsp_destination_t element);
std::string to_short_string(npl_lsp_destination_t element);


struct npl_lsp_encap_fields_t
{
    npl_service_flags_t service_flags;
    npl_num_outer_transport_labels_t num_outer_transport_labels;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lsp_encap_fields_t element);
std::string to_short_string(npl_lsp_encap_fields_t element);


struct npl_lsp_labels_opt2_t
{
    uint64_t label_0 : 20;
    npl_lsp_labels_t labels_1_2;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lsp_labels_opt2_t element);
std::string to_short_string(npl_lsp_labels_opt2_t element);


struct npl_lsr_encap_t
{
    // This is an NPL anonymous union.
    npl_lsr_encap_t_anonymous_union_lsp_t lsp;
    uint64_t backup_te_tunnel : 16;
    npl_mldp_protection_t mldp_protection;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lsr_encap_t element);
std::string to_short_string(npl_lsr_encap_t element);


struct npl_mac_af_npp_attributes_t
{
    uint64_t enable_sr_dm_accounting : 1;
    uint64_t npp_attributes : 8;
    npl_mac_mapping_type_e mapping_type;
    npl_vlan_tag_tci_t port_vlan_tag;
    uint64_t mac_relay_id : 12;
    uint64_t enable_vlan_membership : 1;
    uint64_t enable_vrf_for_l2 : 1;
    uint64_t vlan_membership_index : 5;
    uint64_t enable_transparent_ptp : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_af_npp_attributes_t element);
std::string to_short_string(npl_mac_af_npp_attributes_t element);


struct npl_mac_forwarding_key_t
{
    npl_relay_id_t relay_id;
    npl_mac_addr_t mac_address;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_forwarding_key_t element);
std::string to_short_string(npl_mac_forwarding_key_t element);


struct npl_mac_lp_attr_t
{
    npl_vlan_profile_and_lp_type_t vlan_profile_and_lp_type;
    npl_lp_id_t local_slp_id;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_lp_attr_t element);
std::string to_short_string(npl_mac_lp_attr_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_mac_relay_attributes_inf_payload_t_anonymous_union_l2_relay_id_or_l3_attr_u_t
{
    uint64_t id : 14;
    npl_l3_lp_additional_attributes_t l3_lp_additional_attributes;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_relay_attributes_inf_payload_t_anonymous_union_l2_relay_id_or_l3_attr_u_t element);
std::string to_short_string(npl_mac_relay_attributes_inf_payload_t_anonymous_union_l2_relay_id_or_l3_attr_u_t element);


struct npl_mac_relay_attributes_payload_t
{
    npl_l3_lp_additional_attributes_t l3_lp_additional_attributes;
    npl_mac_l2_relay_attributes_t mac_l2_relay_attributes;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_relay_attributes_payload_t element);
std::string to_short_string(npl_mac_relay_attributes_payload_t element);


struct npl_mark_color_t
{
    npl_quan_2b mark_color[16];
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mark_color_t element);
std::string to_short_string(npl_mark_color_t element);


struct npl_mc_em_db_result_rx_single_t
{
    npl_mc_rx_tc_map_profile_t tc_map_profile;
    npl_base_voq_nr_t base_voq_nr;
    npl_mc_copy_id_t mc_copy_id;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mc_em_db_result_rx_single_t element);
std::string to_short_string(npl_mc_em_db_result_rx_single_t element);


struct npl_mc_em_db_result_rx_t
{
    npl_mc_em_db_result_rx_single_t result_1;
    npl_mc_em_db_result_rx_single_t result_0;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mc_em_db_result_rx_t element);
std::string to_short_string(npl_mc_em_db_result_rx_t element);


struct npl_mc_em_db_result_tx_format_0_t
{
    npl_mc_tx_tc_map_profile_t tc_map_profile_1;
    npl_mc_tx_tc_map_profile_t tc_map_profile_0;
    npl_oq_group_t oq_group_1;
    npl_oq_group_t oq_group_0;
    npl_mc_copy_id_t mc_copy_id_1;
    npl_mc_copy_id_t mc_copy_id_0;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mc_em_db_result_tx_format_0_t element);
std::string to_short_string(npl_mc_em_db_result_tx_format_0_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_mc_em_db_result_tx_t_anonymous_union_format_0_or_1_t
{
    npl_mc_em_db_result_tx_format_0_t format_0;
    npl_mc_em_db_result_tx_format_1_t format_1;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mc_em_db_result_tx_t_anonymous_union_format_0_or_1_t element);
std::string to_short_string(npl_mc_em_db_result_tx_t_anonymous_union_format_0_or_1_t element);


struct npl_mc_slice_bitmap_table_entry_t
{
    uint64_t counterA_inc_enable : 1;
    // This is an NPL anonymous union.
    npl_mc_slice_bitmap_table_entry_t_anonymous_union_group_size_or_bitmap_t group_size_or_bitmap;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mc_slice_bitmap_table_entry_t element);
std::string to_short_string(npl_mc_slice_bitmap_table_entry_t element);


struct npl_mcid_array_t
{
    npl_mcid_t mcid[8];
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mcid_array_t element);
std::string to_short_string(npl_mcid_array_t element);


struct npl_mcid_array_wrapper_t
{
    npl_mcid_array_t payload;
    uint64_t key : 16;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mcid_array_wrapper_t element);
std::string to_short_string(npl_mcid_array_wrapper_t element);


struct npl_mmm_tm_header_t
{
    npl_tm_header_base_t base;
    uint64_t multicast_id : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mmm_tm_header_t element);
std::string to_short_string(npl_mmm_tm_header_t element);


struct npl_more_labels_and_flags_t
{
    npl_more_labels_index_t more_labels;
    uint64_t enable_sr_dm_accounting : 1;
    uint64_t multi_counter_enable : 1;
    npl_service_flags_t service_flags;
    uint64_t total_num_labels : 4;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_more_labels_and_flags_t element);
std::string to_short_string(npl_more_labels_and_flags_t element);


struct npl_mpls_termination_l3vpn_uc_t
{
    npl_override_enable_ipv4_ipv6_uc_bits_t allow_ipv4_ipv6_fwd_bits;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mpls_termination_l3vpn_uc_t element);
std::string to_short_string(npl_mpls_termination_l3vpn_uc_t element);


struct npl_mpls_termination_pwe_t
{
    uint64_t is_pwe_raw : 1;
    uint64_t enable_mpls_tp_oam : 1;
    uint64_t fat_exists : 1;
    uint64_t cw_exists : 1;
    npl_bfd_channel_e bfd_channel;
    npl_l2_relay_id_t l2_relay_id;
    npl_mac_lp_attr_t mac_lp_attr;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mpls_termination_pwe_t element);
std::string to_short_string(npl_mpls_termination_pwe_t element);


struct npl_mum_tm_header_t
{
    npl_tm_header_base_t base;
    uint64_t reserved : 3;
    uint64_t destination_device : 9;
    uint64_t destination_slice : 3;
    uint64_t destination_txrq : 1;
    uint64_t multicast_id : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mum_tm_header_t element);
std::string to_short_string(npl_mum_tm_header_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_my_ipv4_table_payload_t_anonymous_union_ip_tunnel_termination_attr_or_slp_t
{
    npl_sip_ip_tunnel_termination_attr_t sip_ip_tunnel_termination_attr;
    npl_lp_id_t tunnel_slp_id;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_my_ipv4_table_payload_t_anonymous_union_ip_tunnel_termination_attr_or_slp_t element);
std::string to_short_string(npl_my_ipv4_table_payload_t_anonymous_union_ip_tunnel_termination_attr_or_slp_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_nh_payload_t_anonymous_union_l3_sa_vlan_or_l2_dlp_attr_t
{
    npl_l2_dlp_attr_on_nh_t l2_dlp_attr;
    npl_l3_sa_lsb_on_nh_t l3_sa_lsb;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_nh_payload_t_anonymous_union_l3_sa_vlan_or_l2_dlp_attr_t element);
std::string to_short_string(npl_nh_payload_t_anonymous_union_l3_sa_vlan_or_l2_dlp_attr_t element);


struct npl_npu_base_header_leaba_t
{
    npl_rx_nw_app_or_lb_key_t rx_nw_app_or_lb_key;
    uint64_t slp_qos_id : 4;
    uint64_t issu_codespace : 1;
    uint64_t fwd_offset : 7;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npu_base_header_leaba_t element);
std::string to_short_string(npl_npu_base_header_leaba_t element);


struct npl_npu_base_leaba_dont_overwrite_t
{
    uint64_t base_type : 4;
    uint64_t receive_time : 32;
    uint64_t meter_color : 2;
    uint64_t l2_flood_mc_pruning : 1;
    npl_ingress_qos_remark_t ingress_qos_remark;
    npl_fwd_header_type_e fwd_header_type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npu_base_leaba_dont_overwrite_t element);
std::string to_short_string(npl_npu_base_leaba_dont_overwrite_t element);


struct npl_npu_dsp_pif_ifg_t
{
    npl_demux_pif_ifg_t padded_pif_ifg;
    uint64_t use_npu_header_pif_ifg : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npu_dsp_pif_ifg_t element);
std::string to_short_string(npl_npu_dsp_pif_ifg_t element);


struct npl_object_groups_t
{
    npl_og_pd_compression_code_t src_code;
    npl_og_pd_compression_code_t dest_code;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_object_groups_t element);
std::string to_short_string(npl_object_groups_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_og_lpm_code_or_destination_t
{
    npl_og_lpm_compression_code_t lpm_code;
    npl_og_lpts_compression_code_t lpts_code;
    npl_destination_t destination;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_og_lpm_code_or_destination_t element);
std::string to_short_string(npl_og_lpm_code_or_destination_t element);


struct npl_og_lpm_result_t
{
    npl_og_lpm_code_or_destination_t lpm_code_or_dest;
    uint64_t rtype : 2;
    uint64_t no_hbm_access : 1;
    uint64_t is_default_unused : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_og_lpm_result_t element);
std::string to_short_string(npl_og_lpm_result_t element);


struct npl_og_pcl_config_t
{
    uint64_t compress : 1;
    npl_og_pcl_id_t pcl_id;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_og_pcl_config_t element);
std::string to_short_string(npl_og_pcl_config_t element);


struct npl_output_learn_info_t
{
    uint64_t slp : 20;
    npl_relay_id_t relay_id;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_output_learn_info_t element);
std::string to_short_string(npl_output_learn_info_t element);


struct npl_output_learn_record_t
{
    npl_learn_record_result_e result;
    npl_output_learn_info_t learn_info;
    uint64_t ethernet_address : 48;
    uint64_t mact_ldb : 4;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_output_learn_record_t element);
std::string to_short_string(npl_output_learn_record_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_overload_union_dlp_profile_union_t_user_app_data_defined_t
{
    npl_dlp_profile_t user_app_dlp_profile;
    uint64_t user_app_data_defined : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_overload_union_dlp_profile_union_t_user_app_data_defined_t element);
std::string to_short_string(npl_overload_union_dlp_profile_union_t_user_app_data_defined_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_pd_rx_nw_app_t_anonymous_union_init_recycle_fields_union_t
{
    npl_initial_recycle_pd_nw_rx_data_t init_recycle_fields;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pd_rx_nw_app_t_anonymous_union_init_recycle_fields_union_t element);
std::string to_short_string(npl_pd_rx_nw_app_t_anonymous_union_init_recycle_fields_union_t element);


struct npl_pdoq_oq_ifc_mapping_result_t
{
    uint64_t fcn_profile : 2;
    // This is an NPL anonymous union.
    npl_pdoq_oq_ifc_mapping_result_t_anonymous_union_txpp_map_data_t txpp_map_data;
    uint64_t dest_pif : 5;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pdoq_oq_ifc_mapping_result_t element);
std::string to_short_string(npl_pdoq_oq_ifc_mapping_result_t element);


struct npl_pdvoq_bank_pair_offset_result_t
{
    npl_pdvoq_bank_pair_offset_t array[108];
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pdvoq_bank_pair_offset_result_t element);
std::string to_short_string(npl_pdvoq_bank_pair_offset_result_t element);


struct npl_pdvoq_slice_dram_wred_lut_result_t
{
    npl_voq_cgm_wred_probability_region_id_t mark_y;
    npl_voq_cgm_wred_probability_region_id_t mark_g;
    npl_voq_cgm_wred_probability_region_id_t drop_y;
    npl_voq_cgm_wred_probability_region_id_t drop_g;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pdvoq_slice_dram_wred_lut_result_t element);
std::string to_short_string(npl_pdvoq_slice_dram_wred_lut_result_t element);


struct npl_pdvoq_slice_voq_properties_result_t
{
    uint64_t type : 3;
    npl_voq_profile_len profile;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pdvoq_slice_voq_properties_result_t element);
std::string to_short_string(npl_pdvoq_slice_voq_properties_result_t element);


struct npl_pfc_em_compound_results_t
{
    npl_pfc_em_lookup_t payload;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pfc_em_compound_results_t element);
std::string to_short_string(npl_pfc_em_compound_results_t element);


struct npl_post_fwd_params_t
{
    npl_use_metedata_table_per_packet_format_t use_metedata_table_per_packet_format;
    npl_ip_ver_and_post_fwd_stage_t ip_ver_and_post_fwd_stage;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_post_fwd_params_t element);
std::string to_short_string(npl_post_fwd_params_t element);


struct npl_properties_t
{
    npl_l3_dlp_msbs_t l3_dlp_id_ext;
    // This is an NPL anonymous union.
    npl_properties_t_anonymous_union_monitor_or_l3_dlp_ip_type_t monitor_or_l3_dlp_ip_type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_properties_t element);
std::string to_short_string(npl_properties_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_punt_code_t
{
    npl_redirect_code_t punt_redirect_code;
    npl_snoop_code_t snoop_code;
    uint64_t punt_mirror_code : 8;
    npl_lpts_reason_code_e lpts_reason;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_code_t element);
std::string to_short_string(npl_punt_code_t element);


struct npl_punt_encap_data_lsb_t
{
    npl_punt_nw_encap_ptr_t punt_nw_encap_ptr;
    npl_punt_nw_encap_type_e punt_nw_encap_type;
    // This is an NPL anonymous union.
    npl_punt_encap_data_lsb_t_anonymous_union_extra_t extra;
    npl_punt_controls_t punt_controls;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_encap_data_lsb_t element);
std::string to_short_string(npl_punt_encap_data_lsb_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_punt_if_sa_or_npu_host_data_t
{
    uint64_t punt_if_sa_lsb : 16;
    npl_punt_npu_host_macro_data_t punt_npu_host_data;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_if_sa_or_npu_host_data_t element);
std::string to_short_string(npl_punt_if_sa_or_npu_host_data_t element);


struct npl_punt_npu_host_data_t
{
    npl_punt_npu_host_macro_data_t npu_host_macro_data;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_npu_host_data_t element);
std::string to_short_string(npl_punt_npu_host_data_t element);


struct npl_punt_padding_id_t
{
    npl_l3_dlp_id_t id;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_padding_id_t element);
std::string to_short_string(npl_punt_padding_id_t element);


struct npl_punt_shared_lsb_encap_t
{
    npl_ts_command_t punt_ts_cmd;
    npl_punt_encap_data_lsb_t punt_encap_data_lsb;
    npl_punt_cud_type_e punt_cud_type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_shared_lsb_encap_t element);
std::string to_short_string(npl_punt_shared_lsb_encap_t element);


struct npl_punt_src_and_code_t
{
    npl_punt_source_e punt_source;
    npl_punt_code_t punt_code;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_src_and_code_t element);
std::string to_short_string(npl_punt_src_and_code_t element);


struct npl_punt_ssp_attributes_t
{
    npl_split_voq_t split_voq;
    npl_punt_ssp_t ssp;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_ssp_attributes_t element);
std::string to_short_string(npl_punt_ssp_attributes_t element);


struct npl_punt_sub_code_t
{
    // This is an NPL anonymous union.
    npl_punt_sub_code_t_anonymous_union_sub_code_t sub_code;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_sub_code_t element);
std::string to_short_string(npl_punt_sub_code_t element);


struct npl_punt_sub_code_with_padding_t
{
    npl_punt_sub_code_t ene_punt_sub_code;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_sub_code_with_padding_t element);
std::string to_short_string(npl_punt_sub_code_with_padding_t element);


struct npl_pwe_to_l3_compound_lookup_result_t
{
    npl_pwe_to_l3_lookup_result_t payload;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pwe_to_l3_compound_lookup_result_t element);
std::string to_short_string(npl_pwe_to_l3_compound_lookup_result_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_qos_mapping_key_t_anonymous_union_key_union_t
{
    npl_qos_tag_t key;
    uint64_t mpls_exp : 3;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_qos_mapping_key_t_anonymous_union_key_union_t element);
std::string to_short_string(npl_qos_mapping_key_t_anonymous_union_key_union_t element);


struct npl_redirect_stage_og_key_t
{
    uint64_t lpts_is_mc : 1;
    uint64_t lpts_og_app_id : 4;
    npl_lpts_packet_flags_t lpts_packet_flags;
    npl_lpts_object_groups_t lpts_object_groups;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_redirect_stage_og_key_t element);
std::string to_short_string(npl_redirect_stage_og_key_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_relay_attr_table_payload_t
{
    npl_mac_relay_attributes_payload_t relay_attr;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_relay_attr_table_payload_t element);
std::string to_short_string(npl_relay_attr_table_payload_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_resolution_stage_assoc_data_narrow_entry_t
{
    npl_stage0_ce_ptr_l3_nh_ip_tunnel_t stage0_ce_ptr_l3_nh_ip_tunnel;
    npl_stage0_ce_ptr_level2_ecmp_ip_tunnel_t stage0_ce_ptr_level2_ecmp_ip_tunnel;
    npl_stage0_l2_dlp_destination_t stage0_l2_dlp_dest;
    npl_stage0_ce_ptr_l3_nh_vpn_inter_as_ce_ptr_t stage0_ce_ptr_nh_no_tunnel;
    npl_stage0_ce_ptr_l3_nh_vpn_inter_as_ce_ptr_with_common_data_t stage0_ce_ptr_nh_te_he;
    npl_stage0_l3_nh_vpn_inter_as_ce_ptr_with_common_data1_t stage0_ce_ptr_nh_ldp_over_te;
    npl_stage0_ce_ptr_p_l3_nh_vpn_inter_as_ce_ptr_t stage0_ce_ptr_p_nh_no_tunnel;
    npl_stage0_ce_ptr_p_l3_nh_vpn_inter_as_ce_ptr_with_common_data_t stage0_ce_ptr_p_nh_te_he;
    npl_stage0_p_l3_nh_vpn_inter_as_ce_ptr_with_common_data1_t stage0_ce_ptr_p_nh_ldp_over_te;
    npl_stage0_ecmp_destination_t stage0_ecmp_dest;
    npl_stage0_l2_dlp_destination_overlay_nh_t stage0_destination_overlay_nh;
    npl_stage0_destination1_t stage0_dest1;
    npl_stage0_narrow_raw_t stage0_raw;
    npl_stage1_destination1_t stage1_ecmp_dest;
    npl_stage1_level2_ecmp_destination_t stage1_ecmp_dest1;
    npl_stage1_level2_ecmp_l3_nh_te_tunnel14b_or_asbr_t stage1_ecmp_tunnel_or_asbr_he_with_tunnel_id;
    npl_stage1_l3_nh_te_tunnel14b_or_asbr1_t stage1_ecmp_tunnel_or_asbr_ldp_over_te;
    npl_stage1_l3_nh_te_tunnel14b_or_asbr2_t stage1_ecmp_lsp_asbr_nh;
    npl_stage3_dspa_destination_t stage3_dspa_dest;
    npl_stage3_narrow_raw_t stage3_raw;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_stage_assoc_data_narrow_entry_t element);
std::string to_short_string(npl_resolution_stage_assoc_data_narrow_entry_t element);


struct npl_resolution_stage_assoc_data_narrow_line_t
{
    npl_resolution_state_assoc_data_entry_type_e type;
    npl_resolution_stage_assoc_data_narrow_entry_t entry[4];
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_stage_assoc_data_narrow_line_t element);
std::string to_short_string(npl_resolution_stage_assoc_data_narrow_line_t element);


struct npl_resolution_stage_assoc_data_narrow_protection_line_t
{
    npl_resolution_state_assoc_data_entry_type_e type;
    uint64_t id : 13;
    uint64_t const1 : 1;
    npl_resolution_stage_assoc_data_narrow_protection_record_t record[2];
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_stage_assoc_data_narrow_protection_line_t element);
std::string to_short_string(npl_resolution_stage_assoc_data_narrow_protection_line_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_resolution_stage_assoc_data_wide_entry_t
{
    npl_stage0_ce_ptr_destination_vpn_inter_as_ce_ptr_t stage0_ce_ptr_ecmp2;
    npl_stage2_l3_nh_destination_l3_dlp_dlp_attr_t stage2_l3_nh_dlp_bvn_profile;
    npl_stage2_l3_nh_destination_l3_dlp_t stage2_l3_nh_dlp;
    npl_stage2_wide_raw_t stage2_raw;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_stage_assoc_data_wide_entry_t element);
std::string to_short_string(npl_resolution_stage_assoc_data_wide_entry_t element);


struct npl_resolution_stage_assoc_data_wide_line_t
{
    npl_resolution_state_assoc_data_entry_type_e type;
    npl_resolution_stage_assoc_data_wide_entry_t entry[2];
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_stage_assoc_data_wide_line_t element);
std::string to_short_string(npl_resolution_stage_assoc_data_wide_line_t element);


struct npl_resolution_stage_assoc_data_wide_protection_record_t
{
    uint64_t id : 13;
    npl_resolution_protection_selector_e path;
    npl_wide_protection_entry_t primary_entry;
    npl_wide_protection_entry_t protect_entry;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_stage_assoc_data_wide_protection_record_t element);
std::string to_short_string(npl_resolution_stage_assoc_data_wide_protection_record_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_resolution_stage_em_table_key_t
{
    npl_resolution_stage_em_table_dest_map_key_t dest_map_key;
    npl_resolution_stage_em_table_lb_key_t lb_key;
    npl_resolution_stage_em_table_raw_key_t raw_key;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_stage_em_table_key_t element);
std::string to_short_string(npl_resolution_stage_em_table_key_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_rpf_compressed_destination_t_anonymous_union_rpf_id_or_lp_id_t
{
    uint64_t rpf_id : 16;
    npl_l3_dlp_t lp;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rpf_compressed_destination_t_anonymous_union_rpf_id_or_lp_id_t element);
std::string to_short_string(npl_rpf_compressed_destination_t_anonymous_union_rpf_id_or_lp_id_t element);


struct npl_rtf_next_macro_pack_fields_t
{
    npl_curr_and_next_prot_type_t curr_and_next_prot_type;
    npl_stop_on_step_and_next_stage_compressed_fields_t stop_on_step_and_next_stage_compressed_fields;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rtf_next_macro_pack_fields_t element);
std::string to_short_string(npl_rtf_next_macro_pack_fields_t element);


struct npl_rtf_result_profile_0_t
{
    npl_mirror_action_e mirror_action;
    npl_phb_t phb;
    uint64_t q_m_offset_5bits : 5;
    npl_counter_action_type_e counter_action_type;
    // This is an NPL anonymous union.
    npl_rtf_result_profile_0_t_anonymous_union_mirror_cmd_or_offset_t mirror_cmd_or_offset;
    uint64_t override_phb : 1;
    npl_rtf_sec_action_e rtf_sec_action;
    uint64_t override_qos_group : 1;
    npl_ingress_qos_mapping_remark_t ingress_qos_remark;
    // This is an NPL anonymous union.
    npl_rtf_result_profile_0_t_anonymous_union_force_t force;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rtf_result_profile_0_t element);
std::string to_short_string(npl_rtf_result_profile_0_t element);


struct npl_rtf_result_profile_1_t
{
    npl_rtf_res_profile_1_action_e rtf_res_profile_1_action;
    // This is an NPL anonymous union.
    npl_rtf_result_profile_1_t_anonymous_union_meter_or_counter_t meter_or_counter;
    uint64_t override_qos_group : 1;
    npl_ingress_qos_mapping_remark_t ingress_qos_remark;
    npl_destination_t destination;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rtf_result_profile_1_t element);
std::string to_short_string(npl_rtf_result_profile_1_t element);


struct npl_rxpp_pd_t
{
    uint64_t source_if : 8;
    uint64_t drop_flag : 1;
    npl_rxpp_pd_forward_destination_t fwd_destination;
    uint64_t in_mirror_cmd0 : 5;
    uint64_t tc : 3;
    uint64_t in_color : 2;
    uint64_t counter_meter_ptr_0 : 19;
    uint64_t counter_meter_comp_0 : 7;
    uint64_t counter_lm_read_only_0 : 1;
    uint64_t ethernet_rate_limiter_type : 3;
    uint64_t packet_learn_enable : 1;
    uint64_t snr_context : 13;
    uint64_t snr_psn : 20;
    uint64_t snr_out_slice : 2;
    // This is an NPL anonymous union.
    npl_rxpp_pd_t_anonymous_union_lb_or_slb_t lb_or_slb;
    // This is an NPL anonymous union.
    npl_rxpp_pd_t_anonymous_union_slice_mode_data_t slice_mode_data;
    bit_vector384_t pack(void) const;
    void unpack(bit_vector384_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rxpp_pd_t element);
std::string to_short_string(npl_rxpp_pd_t element);


struct npl_sch_oqse_cfg_result_4p_t
{
    npl_oqse_logical_port_map_4p_e logical_port_map[2];
    npl_oqse_topology_4p_t oqse_topology[2];
    npl_wfq_weight_4p_entry_t oqse_wfq_weight[2];
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_sch_oqse_cfg_result_4p_t element);
std::string to_short_string(npl_sch_oqse_cfg_result_4p_t element);


struct npl_sch_oqse_cfg_result_8p_t
{
    npl_oqse_logical_port_map_8p_e logical_port_map;
    npl_oqse_topology_8p_e oqse_topology;
    npl_wfq_weight_8p_t oqse_wfq_weight;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_sch_oqse_cfg_result_8p_t element);
std::string to_short_string(npl_sch_oqse_cfg_result_8p_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_sch_oqse_cfg_result_t
{
    npl_sch_oqse_cfg_result_8p_t single_8p;
    npl_sch_oqse_cfg_result_4p_t pair_4p;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_sch_oqse_cfg_result_t element);
std::string to_short_string(npl_sch_oqse_cfg_result_t element);


struct npl_sec_acl_attributes_t
{
    uint64_t rtf_conf_set_ptr : 8;
    npl_counter_ptr_t p_counter;
    // This is an NPL anonymous union.
    npl_sec_acl_attributes_t_anonymous_union_slp_dlp_t slp_dlp;
    uint64_t per_pkt_type_count : 1;
    npl_port_mirror_type_e port_mirror_type;
    uint64_t l2_lpts_slp_attributes : 2;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_sec_acl_attributes_t element);
std::string to_short_string(npl_sec_acl_attributes_t element);


struct npl_sgt_matrix_padded_result_t
{
    npl_sgt_matrix_result_t sgt_matrix_em_result;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_sgt_matrix_padded_result_t element);
std::string to_short_string(npl_sgt_matrix_padded_result_t element);


struct npl_shared_l2_lp_attributes_t
{
    uint64_t p2p : 1;
    uint64_t qos_id : 4;
    uint64_t lp_profile : 2;
    uint64_t stp_state_block : 1;
    uint64_t mirror_cmd : 5;
    npl_sec_acl_attributes_t sec_acl_attributes;
    npl_counter_ptr_t q_counter;
    npl_counter_ptr_t m_counter;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_shared_l2_lp_attributes_t element);
std::string to_short_string(npl_shared_l2_lp_attributes_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_single_label_encap_data_t_anonymous_union_udat_t
{
    uint64_t gre_key : 32;
    npl_vpl_label_and_valid_t label_and_valid;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_single_label_encap_data_t_anonymous_union_udat_t element);
std::string to_short_string(npl_single_label_encap_data_t_anonymous_union_udat_t element);


struct npl_slice_and_source_if_t
{
    uint64_t slice_id_on_npu : 3;
    npl_source_if_t source_if_on_npu;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_slice_and_source_if_t element);
std::string to_short_string(npl_slice_and_source_if_t element);


struct npl_sport_or_l4_protocol_t
{
    // This is an NPL anonymous union.
    npl_sport_or_l4_protocol_t_anonymous_union_sport_or_l4_protocol_type_t sport_or_l4_protocol_type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_sport_or_l4_protocol_t element);
std::string to_short_string(npl_sport_or_l4_protocol_t element);


struct npl_svi_eve_sub_type_plus_pad_plus_prf_t
{
    npl_svi_eve_sub_type_plus_prf_t sub_type_plus_prf;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_svi_eve_sub_type_plus_pad_plus_prf_t element);
std::string to_short_string(npl_svi_eve_sub_type_plus_pad_plus_prf_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_svl_data_t_anonymous_union_svl_uc_mc_data_t
{
    npl_svl_uc_data_t svl_uc_data;
    npl_svl_mc_data_t svl_mc_data;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_svl_data_t_anonymous_union_svl_uc_mc_data_t element);
std::string to_short_string(npl_svl_data_t_anonymous_union_svl_uc_mc_data_t element);


struct npl_te_midpoint_nhlfe_t
{
    uint64_t mp_label : 20;
    // This is an NPL anonymous union.
    npl_te_midpoint_nhlfe_t_anonymous_union_lsp_t lsp;
    uint64_t midpoint_nh : 12;
    npl_compressed_counter_t counter_offset;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_te_midpoint_nhlfe_t element);
std::string to_short_string(npl_te_midpoint_nhlfe_t element);


struct npl_tunnel_headend_encap_t
{
    npl_lsp_destination_t lsp_destination;
    // This is an NPL anonymous union.
    npl_tunnel_headend_encap_t_anonymous_union_te_asbr_t te_asbr;
    npl_mldp_protection_t mldp_protection;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_tunnel_headend_encap_t element);
std::string to_short_string(npl_tunnel_headend_encap_t element);


struct npl_tunnel_type_and_force_pipe_ttl_ingress_ptp_info_t
{
    npl_force_pipe_ttl_ingress_ptp_info_t force_pipe_ttl_ingress_ptp_null;
    npl_force_pipe_ttl_ingress_ptp_info_t force_pipe_ttl_ingress_ptp_info;
    npl_tunnel_type_e tunnel_type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_tunnel_type_and_force_pipe_ttl_ingress_ptp_info_t element);
std::string to_short_string(npl_tunnel_type_and_force_pipe_ttl_ingress_ptp_info_t element);


struct npl_tx_to_rx_rcy_data_t
{
    npl_unscheduled_recycle_code_t unscheduled_recycle_code;
    uint64_t unscheduled_recycle_data : 6;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_tx_to_rx_rcy_data_t element);
std::string to_short_string(npl_tx_to_rx_rcy_data_t element);


struct npl_ud_key_t
{
    npl_udf_t udfs[32];
    bit_vector pack(void) const;
    void unpack(bit_vector);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ud_key_t element);
std::string to_short_string(npl_ud_key_t element);


struct npl_unicast_flb_tm_header_padded_t
{
    npl_unicast_flb_tm_header_t unicast_flb_tm_header;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_unicast_flb_tm_header_padded_t element);
std::string to_short_string(npl_unicast_flb_tm_header_padded_t element);


struct npl_unicast_plb_tm_header_padded_t
{
    npl_unicast_plb_tm_header_t unicast_plb_tm_header;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_unicast_plb_tm_header_padded_t element);
std::string to_short_string(npl_unicast_plb_tm_header_padded_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_g_t
{
    npl_drop_color_t drop_green;
    uint64_t drop_green_u : 48;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_g_t element);
std::string to_short_string(npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_g_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_y_t
{
    npl_drop_color_t drop_yellow;
    uint64_t drop_yellow_u : 48;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_y_t element);
std::string to_short_string(npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_y_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_mark_g_t
{
    npl_mark_color_t mark_green;
    uint64_t mark_green_u : 32;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_mark_g_t element);
std::string to_short_string(npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_mark_g_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_mark_y_t
{
    npl_mark_color_t mark_yellow;
    uint64_t mark_yellow_u : 32;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_mark_y_t element);
std::string to_short_string(npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_mark_y_t element);


struct npl_additional_labels_t
{
    uint64_t label_3 : 20;
    uint64_t label_4 : 20;
    uint64_t label_5 : 20;
    uint64_t label_6 : 20;
    uint64_t label_7 : 20;
    npl_label_or_num_labels_t label_8_or_num_labels;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_additional_labels_t element);
std::string to_short_string(npl_additional_labels_t element);


struct npl_bfd_aux_shared_payload_t
{
    uint64_t local_discriminator : 32;
    uint64_t remote_discriminator : 32;
    uint64_t tos : 8;
    uint64_t local_diag_code : 5;
    uint64_t requires_inject_up : 1;
    npl_bfd_session_type_e session_type;
    // This is an NPL anonymous union.
    npl_bfd_aux_shared_payload_t_anonymous_union_prot_shared_t prot_shared;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_aux_shared_payload_t element);
std::string to_short_string(npl_bfd_aux_shared_payload_t element);


struct npl_bfd_em_lookup_t
{
    uint64_t encap_result : 1;
    uint64_t meter : 4;
    uint64_t destination : 20;
    npl_punt_encap_data_lsb_t punt_encap_data;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_em_lookup_t element);
std::string to_short_string(npl_bfd_em_lookup_t element);


struct npl_bfd_flags_state_t
{
    uint64_t state : 2;
    // This is an NPL anonymous union.
    npl_bfd_flags_state_t_anonymous_union_bfd_flags_t bfd_flags;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_flags_state_t element);
std::string to_short_string(npl_bfd_flags_state_t element);


struct npl_bfd_remote_session_attributes_t
{
    uint64_t last_time : 32;
    npl_bfd_flags_state_t remote_info;
    uint64_t rmep_profile : 4;
    uint64_t rmep_valid : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_remote_session_attributes_t element);
std::string to_short_string(npl_bfd_remote_session_attributes_t element);


struct npl_common_cntr_offset_and_padding_t
{
    // This is an NPL anonymous union.
    npl_common_cntr_offset_and_padding_t_anonymous_union_cntr_offset_t cntr_offset;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_common_cntr_offset_and_padding_t element);
std::string to_short_string(npl_common_cntr_offset_and_padding_t element);


struct npl_common_cntr_offset_packed_t
{
    // This is an NPL anonymous union.
    npl_common_cntr_offset_packed_t_anonymous_union_cntr_offset_t cntr_offset;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_common_cntr_offset_packed_t element);
std::string to_short_string(npl_common_cntr_offset_packed_t element);


struct npl_dlp_attributes_t
{
    npl_common_cntr_offset_packed_t acl_drop_offset;
    uint64_t lp_profile : 2;
    npl_port_mirror_type_e port_mirror_type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_dlp_attributes_t element);
std::string to_short_string(npl_dlp_attributes_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_dlp_profile_union_t
{
    uint64_t data : 8;
    npl_overload_union_dlp_profile_union_t_user_app_data_defined_t overload_union_user_app_data_defined;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_dlp_profile_union_t element);
std::string to_short_string(npl_dlp_profile_union_t element);


struct npl_egress_ipv6_acl_result_t
{
    npl_egress_sec_acl_result_t sec;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_egress_ipv6_acl_result_t element);
std::string to_short_string(npl_egress_ipv6_acl_result_t element);


struct npl_egress_qos_result_t
{
    uint64_t fwd_remark_exp : 3;
    uint64_t remark_l2 : 1;
    // This is an NPL anonymous union.
    npl_egress_qos_result_t_anonymous_union_remark_l3_t remark_l3;
    npl_common_cntr_offset_and_padding_t q_offset;
    uint64_t fwd_remark_dscp : 6;
    npl_qos_encap_t encap;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_egress_qos_result_t element);
std::string to_short_string(npl_egress_qos_result_t element);


struct npl_ene_inject_down_header_t
{
    npl_ene_inject_down_payload_t ene_inject_down_payload;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ene_inject_down_header_t element);
std::string to_short_string(npl_ene_inject_down_header_t element);


struct npl_ene_punt_sub_code_and_dsp_and_ssp_t
{
    npl_punt_sub_code_t ene_punt_sub_code;
    npl_ene_punt_dsp_and_ssp_t ene_punt_dsp_and_ssp;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ene_punt_sub_code_and_dsp_and_ssp_t element);
std::string to_short_string(npl_ene_punt_sub_code_and_dsp_and_ssp_t element);


struct npl_ethernet_header_t
{
    npl_ethernet_mac_t mac_addr;
    uint64_t ether_type_or_tpid : 16;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ethernet_header_t element);
std::string to_short_string(npl_ethernet_header_t element);


struct npl_fi_core_tcam_assoc_data_t
{
    uint64_t next_macro : 6;
    uint64_t last_macro : 1;
    uint64_t start_new_header : 1;
    uint64_t start_new_layer : 1;
    uint64_t advance_data : 1;
    npl_header_format_t tcam_mask_alu_header_format;
    uint64_t tcam_mask_alu_header_size : 6;
    uint64_t tcam_mask_hw_logic_advance_data : 1;
    uint64_t tcam_mask_hw_logic_last_macro : 1;
    npl_header_format_t tcam_mask_hw_logic_header_format;
    uint64_t tcam_mask_hw_logic_header_size : 6;
    npl_header_format_t header_format;
    uint64_t header_size : 6;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_fi_core_tcam_assoc_data_t element);
std::string to_short_string(npl_fi_core_tcam_assoc_data_t element);


struct npl_flc_payload_t
{
    uint64_t npu_header[6];
    npl_rxpp_pd_t rxpp_pd;
    bit_vector pack(void) const;
    void unpack(bit_vector);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_flc_payload_t element);
std::string to_short_string(npl_flc_payload_t element);


struct npl_ingress_lpts_og_app_config_t
{
    npl_ingress_lpts_og_app_data_t app_data;
    npl_og_pcl_config_t src;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ingress_lpts_og_app_config_t element);
std::string to_short_string(npl_ingress_lpts_og_app_config_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_ingress_qos_acl_result_t_anonymous_union_ctr_offest_union_t
{
    npl_common_cntr_5bits_offset_and_padding_t q_m_offset_5bits;
    npl_common_cntr_offset_packed_t q_m_offset;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ingress_qos_acl_result_t_anonymous_union_ctr_offest_union_t element);
std::string to_short_string(npl_ingress_qos_acl_result_t_anonymous_union_ctr_offest_union_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_ingress_qos_result_t_anonymous_union_ctr_offest_union_t
{
    npl_common_cntr_5bits_offset_and_padding_t q_m_offset_5bits;
    npl_common_cntr_offset_packed_t q_m_offset;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ingress_qos_result_t_anonymous_union_ctr_offest_union_t element);
std::string to_short_string(npl_ingress_qos_result_t_anonymous_union_ctr_offest_union_t element);


struct npl_initial_pd_nw_rx_data_t
{
    // This is an NPL anonymous union.
    npl_initial_pd_nw_rx_data_t_anonymous_union_init_data_t init_data;
    npl_mac_mapping_type_e initial_mapping_type;
    uint64_t initial_is_rcy_if : 1;
    uint64_t pfc_enable : 1;
    npl_mac_lp_type_e initial_mac_lp_type;
    npl_l2_lp_type_e initial_lp_type;
    uint64_t initial_vlan_profile : 4;
    // This is an NPL anonymous union.
    npl_initial_pd_nw_rx_data_t_anonymous_union_mapping_key_t mapping_key;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_initial_pd_nw_rx_data_t element);
std::string to_short_string(npl_initial_pd_nw_rx_data_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_inject_header_t_anonymous_union_ts_and_cntr_stamp_cmd_t
{
    npl_inject_ts_and_lm_cmd_t time_and_cntr_stamp_cmd;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_header_t_anonymous_union_ts_and_cntr_stamp_cmd_t element);
std::string to_short_string(npl_inject_header_t_anonymous_union_ts_and_cntr_stamp_cmd_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_inject_specific_data_t_anonymous_union_inject_data_t_anonymous_union_inject_down_u_t
{
    npl_inject_down_header_t inject_down;
    npl_ene_inject_down_header_t ene_inject_down;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_specific_data_t_anonymous_union_inject_data_t_anonymous_union_inject_down_u_t element);
std::string to_short_string(npl_inject_specific_data_t_anonymous_union_inject_data_t_anonymous_union_inject_down_u_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_inject_up_eth_header_t_anonymous_union_qos_or_dest_t
{
    npl_inject_up_eth_qos_t inject_up_qos;
    npl_inject_up_destination_override_t inject_up_dest;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_up_eth_header_t_anonymous_union_qos_or_dest_t element);
std::string to_short_string(npl_inject_up_eth_header_t_anonymous_union_qos_or_dest_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_ip_encap_data_t_anonymous_union_ip_t
{
    npl_ipv4_encap_data_t v4;
    npl_ipv6_encap_data_t v6;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_encap_data_t_anonymous_union_ip_t element);
std::string to_short_string(npl_ip_encap_data_t_anonymous_union_ip_t element);


struct npl_ip_sgt_em_result_t
{
    npl_ip_uc_em_result_type_e result_type;
    // This is an NPL anonymous union.
    npl_ip_sgt_em_result_t_anonymous_union_result_t result;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_sgt_em_result_t element);
std::string to_short_string(npl_ip_sgt_em_result_t element);


struct npl_ive_profile_and_data_t
{
    npl_vlan_edit_command_main_type_e main_type;
    // This is an NPL anonymous union.
    npl_ive_profile_and_data_t_anonymous_union_secondary_type_or_vid_2_t secondary_type_or_vid_2;
    uint64_t prf : 2;
    uint64_t vid1 : 12;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ive_profile_and_data_t element);
std::string to_short_string(npl_ive_profile_and_data_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_l2_relay_id_or_l3_attr_t
{
    npl_l2_relay_id_t relay_id;
    npl_l3_lp_additional_attributes_t l3_lp_additional_attributes;
    uint64_t l2_vpn_pwe_id : 14;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2_relay_id_or_l3_attr_t element);
std::string to_short_string(npl_l2_relay_id_or_l3_attr_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_l3_dlp_attributes_t_anonymous_union_l3_dlp_encap_or_te_labels_t
{
    npl_l3_dlp_encap_t l3_dlp_encap;
    npl_ldp_over_te_tunnel_data_t ldp_over_te_tunnel_data;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_dlp_attributes_t_anonymous_union_l3_dlp_encap_or_te_labels_t element);
std::string to_short_string(npl_l3_dlp_attributes_t_anonymous_union_l3_dlp_encap_or_te_labels_t element);


struct npl_l3_dlp_info_t
{
    npl_l3_ecn_ctrl_t l3_ecn_ctrl;
    npl_dlp_attributes_t dlp_attributes;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_dlp_info_t element);
std::string to_short_string(npl_l3_dlp_info_t element);


struct npl_l3_dlp_qos_and_attributes_t
{
    npl_l3_dlp_info_t l3_dlp_info;
    npl_tx_counter_compensation_e qos_counter_comp;
    npl_qos_attributes_t qos_attributes;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_dlp_qos_and_attributes_t element);
std::string to_short_string(npl_l3_dlp_qos_and_attributes_t element);


struct npl_l3_global_slp_t
{
    npl_l3_slp_id_t id;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_global_slp_t element);
std::string to_short_string(npl_l3_global_slp_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_label_or_more_t
{
    uint64_t label : 20;
    npl_more_labels_and_flags_t more;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_label_or_more_t element);
std::string to_short_string(npl_label_or_more_t element);


struct npl_lpts_tcam_first_result_encap_data_msb_t
{
    // This is an NPL anonymous union.
    npl_lpts_tcam_first_result_encap_data_msb_t_anonymous_union_encap_punt_code_t encap_punt_code;
    npl_punt_source_e ingress_punt_src;
    npl_punt_sub_code_t punt_sub_code;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lpts_tcam_first_result_encap_data_msb_t element);
std::string to_short_string(npl_lpts_tcam_first_result_encap_data_msb_t element);


struct npl_lsp_labels_opt1_t
{
    npl_lsp_labels_t labels_0_1;
    npl_label_or_more_t label_2_or_more;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lsp_labels_opt1_t element);
std::string to_short_string(npl_lsp_labels_opt1_t element);


struct npl_mac_relay_attributes_inf_payload_t
{
    npl_l3_lp_additional_attributes_t l3_lp_additional_attributes;
    npl_mac_l2_relay_attributes_t mac_l2_relay_attributes;
    // This is an NPL anonymous union.
    npl_mac_relay_attributes_inf_payload_t_anonymous_union_l2_relay_id_or_l3_attr_u_t l2_relay_id_or_l3_attr_u;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_relay_attributes_inf_payload_t element);
std::string to_short_string(npl_mac_relay_attributes_inf_payload_t element);


struct npl_mac_relay_attributes_t
{
    npl_mac_l2_relay_attributes_t payload;
    npl_l2_relay_id_or_l3_attr_t l2_relay_id_or_l3_attr_u;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_relay_attributes_t element);
std::string to_short_string(npl_mac_relay_attributes_t element);


struct npl_mc_em_db_result_tx_t
{
    // This is an NPL anonymous union.
    npl_mc_em_db_result_tx_t_anonymous_union_format_0_or_1_t format_0_or_1;
    uint64_t format : 1;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mc_em_db_result_tx_t element);
std::string to_short_string(npl_mc_em_db_result_tx_t element);


struct npl_minimal_l3_lp_attributes_t
{
    npl_l3_relay_id_t l3_relay_id;
    npl_counter_ptr_t p_counter;
    npl_l3_global_slp_t global_slp_id;
    uint64_t disable_ipv4_uc : 1;
    npl_ttl_mode_e ttl_mode;
    uint64_t per_protocol_count : 1;
    uint64_t lp_set : 1;
    uint64_t disable_ipv6_mc : 1;
    uint64_t disable_ipv4_mc : 1;
    // This is an NPL anonymous union.
    npl_minimal_l3_lp_attributes_t_anonymous_union_disable_mpls_or_mc_tunnel_t disable_mpls_or_mc_tunnel;
    uint64_t disable_ipv6_uc : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_minimal_l3_lp_attributes_t element);
std::string to_short_string(npl_minimal_l3_lp_attributes_t element);


struct npl_mmm_tm_header_padded_t
{
    npl_mmm_tm_header_t mmm_tm_header;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mmm_tm_header_padded_t element);
std::string to_short_string(npl_mmm_tm_header_padded_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_mpls_termination_l3vpn_t_anonymous_union_vpn_mldp_info_t
{
    npl_mpls_termination_mldp_t mldp_info;
    npl_mpls_termination_l3vpn_uc_t vpn_info;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mpls_termination_l3vpn_t_anonymous_union_vpn_mldp_info_t element);
std::string to_short_string(npl_mpls_termination_l3vpn_t_anonymous_union_vpn_mldp_info_t element);


struct npl_my_ipv4_table_payload_t
{
    npl_termination_logical_db_e ip_termination_type;
    // This is an NPL anonymous union.
    npl_my_ipv4_table_payload_t_anonymous_union_ip_tunnel_termination_attr_or_slp_t ip_tunnel_termination_attr_or_slp;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_my_ipv4_table_payload_t element);
std::string to_short_string(npl_my_ipv4_table_payload_t element);


struct npl_nh_payload_t
{
    uint64_t eve_vid1 : 12;
    uint64_t l2_port : 1;
    uint64_t l2_flood : 1;
    uint64_t eve_vid2 : 12;
    // This is an NPL anonymous union.
    npl_nh_payload_t_anonymous_union_l3_sa_vlan_or_l2_dlp_attr_t l3_sa_vlan_or_l2_dlp_attr;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_nh_payload_t element);
std::string to_short_string(npl_nh_payload_t element);


struct npl_npu_encap_header_l3_dlp_t
{
    npl_l3_dlp_lsbs_t l3_dlp_id;
    npl_properties_t properties;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npu_encap_header_l3_dlp_t element);
std::string to_short_string(npl_npu_encap_header_l3_dlp_t element);


struct npl_npu_ip_collapsed_mc_encap_header_t
{
    npl_npu_encap_l3_header_type_e collapsed_mc_encap_type;
    npl_npu_encap_header_l3_dlp_t l3_dlp;
    npl_bool_t punt;
    npl_bool_t resolve_local_mcid;
    npl_l2_dlp_t l2_dlp;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npu_ip_collapsed_mc_encap_header_t element);
std::string to_short_string(npl_npu_ip_collapsed_mc_encap_header_t element);


struct npl_npu_l3_common_dlp_nh_encap_t
{
    npl_npu_encap_header_l3_dlp_t l3_dlp;
    uint64_t nh : 12;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npu_l3_common_dlp_nh_encap_t element);
std::string to_short_string(npl_npu_l3_common_dlp_nh_encap_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_npu_l3_encap_header_t_anonymous_union_encap_ext_t
{
    npl_tunnel_headend_encap_t tunnel_headend;
    npl_lsr_encap_t lsr;
    npl_l3_vxlan_encap_t vxlan;
    uint64_t gre_tunnel_dlp : 16;
    npl_npu_dsp_pif_ifg_t npu_pif_ifg;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npu_l3_encap_header_t_anonymous_union_encap_ext_t element);
std::string to_short_string(npl_npu_l3_encap_header_t_anonymous_union_encap_ext_t element);


struct npl_npu_l3_mc_host_gb_dlp_encap_t
{
    npl_npu_encap_header_l3_dlp_t mc_host_gb_l3_dlp;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npu_l3_mc_host_gb_dlp_encap_t element);
std::string to_short_string(npl_npu_l3_mc_host_gb_dlp_encap_t element);


struct npl_og_em_lpm_result_t
{
    npl_og_lpm_code_or_destination_t lpm_code_or_dest;
    uint64_t is_default_unused : 1;
    npl_ip_em_lpm_result_type_e result_type;
    uint64_t no_hbm_access : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_og_em_lpm_result_t element);
std::string to_short_string(npl_og_em_lpm_result_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_og_em_result_t_anonymous_union_result_t
{
    npl_og_lpm_code_or_destination_t lpm_code_or_dest;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_og_em_result_t_anonymous_union_result_t element);
std::string to_short_string(npl_og_em_result_t_anonymous_union_result_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_pd_rx_nw_app_t_anonymous_union_init_fields_union_t
{
    npl_initial_pd_nw_rx_data_t init_fields;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pd_rx_nw_app_t_anonymous_union_init_fields_union_t element);
std::string to_short_string(npl_pd_rx_nw_app_t_anonymous_union_init_fields_union_t element);


struct npl_punt_eth_nw_common_encap_data_t
{
    npl_mac_addr_t punt_host_da;
    npl_padding_or_ipv6_len_t padding_or_ipv6_len;
    npl_punt_if_sa_or_npu_host_data_t sa_or_npuh;
    uint64_t punt_if_sa_rewrite_idx : 4;
    npl_vlan_id_t punt_eth_vid;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_eth_nw_common_encap_data_t element);
std::string to_short_string(npl_punt_eth_nw_common_encap_data_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_punt_l3_lp_t_anonymous_union_id_or_pfc_t
{
    npl_punt_padding_id_t punt_padding_id;
    npl_l3_pfc_data_t sw_pfc;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_l3_lp_t_anonymous_union_id_or_pfc_t element);
std::string to_short_string(npl_punt_l3_lp_t_anonymous_union_id_or_pfc_t element);


struct npl_punt_lsb_encap_t
{
    npl_fwd_header_type_e packet_fwd_header_type;
    npl_punt_shared_lsb_encap_t punt_shared_lsb_encap;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_lsb_encap_t element);
std::string to_short_string(npl_punt_lsb_encap_t element);


struct npl_pwe_dlp_specific_t
{
    npl_ive_profile_and_data_t eve;
    uint64_t pwe_label : 20;
    uint64_t lp_set : 1;
    uint64_t pwe_fat : 1;
    uint64_t pwe_cw : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pwe_dlp_specific_t element);
std::string to_short_string(npl_pwe_dlp_specific_t element);


struct npl_qos_mapping_key_t
{
    // This is an NPL anonymous union.
    npl_qos_mapping_key_t_anonymous_union_key_union_t key_union;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_qos_mapping_key_t element);
std::string to_short_string(npl_qos_mapping_key_t element);


struct npl_resolution_stage_assoc_data_wide_protection_line_t
{
    npl_resolution_state_assoc_data_entry_type_e type;
    npl_resolution_stage_assoc_data_wide_protection_record_t record;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_stage_assoc_data_wide_protection_line_t element);
std::string to_short_string(npl_resolution_stage_assoc_data_wide_protection_line_t element);


struct npl_rpf_compressed_destination_t
{
    uint64_t enable_mc_rpf : 1;
    // This is an NPL anonymous union.
    npl_rpf_compressed_destination_t_anonymous_union_rpf_id_or_lp_id_t rpf_id_or_lp_id;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rpf_compressed_destination_t element);
std::string to_short_string(npl_rpf_compressed_destination_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_rtf_payload_t_anonymous_union_rtf_result_profile_t
{
    npl_rtf_result_profile_0_t rtf_result_profile_0;
    npl_rtf_result_profile_1_t rtf_result_profile_1;
    npl_rtf_result_profile_2_t rtf_result_profile_2;
    npl_rtf_result_profile_3_t rtf_result_profile_3;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rtf_payload_t_anonymous_union_rtf_result_profile_t element);
std::string to_short_string(npl_rtf_payload_t_anonymous_union_rtf_result_profile_t element);


struct npl_single_label_encap_data_t
{
    // This is an NPL anonymous union.
    npl_single_label_encap_data_t_anonymous_union_udat_t udat;
    npl_exp_bos_and_label_t v6_label_encap;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_single_label_encap_data_t element);
std::string to_short_string(npl_single_label_encap_data_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_slp_info_t_anonymous_union_global_slp_id_t
{
    npl_l2_global_slp_t l2_slp;
    npl_l3_global_slp_t l3_slp;
    uint64_t is_l2 : 1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_slp_info_t_anonymous_union_global_slp_id_t element);
std::string to_short_string(npl_slp_info_t_anonymous_union_global_slp_id_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_snoop_or_rcy_data_t_anonymous_union_snoop_or_rcy_data_t
{
    uint64_t snoop_code : 8;
    npl_tx_to_rx_rcy_data_t tx_to_rx_rcy_data;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_snoop_or_rcy_data_t_anonymous_union_snoop_or_rcy_data_t element);
std::string to_short_string(npl_snoop_or_rcy_data_t_anonymous_union_snoop_or_rcy_data_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_svi_eve_profile_and_data_t_anonymous_union_sub_type_or_vid_2_plus_prf_t
{
    npl_svi_eve_sub_type_plus_pad_plus_prf_t svi_eve_sub_type_plus_pad_plus_prf;
    npl_svi_eve_vid2_plus_prf_t svi_eve_vid2_plus_prf_t;
    uint64_t vid2 : 12;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_svi_eve_profile_and_data_t_anonymous_union_sub_type_or_vid_2_plus_prf_t element);
std::string to_short_string(npl_svi_eve_profile_and_data_t_anonymous_union_sub_type_or_vid_2_plus_prf_t element);


struct npl_svl_data_t
{
    // This is an NPL anonymous union.
    npl_svl_data_t_anonymous_union_svl_uc_mc_data_t svl_uc_mc_data;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_svl_data_t element);
std::string to_short_string(npl_svl_data_t element);


struct npl_term_l2_lp_attributes_t
{
    uint64_t enable_monitor : 1;
    uint64_t mip_exists : 1;
    uint64_t mep_exists : 1;
    npl_ive_profile_and_data_t ive_profile_and_data;
    uint64_t max_mep_level : 3;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_term_l2_lp_attributes_t element);
std::string to_short_string(npl_term_l2_lp_attributes_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_tm_headers_template_t_anonymous_union_u_t
{
    npl_unicast_flb_tm_header_padded_t unicast_flb;
    npl_unicast_plb_tm_header_padded_t unicast_plb;
    npl_mmm_tm_header_padded_t mmm;
    npl_mum_tm_header_t mum;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_tm_headers_template_t_anonymous_union_u_t element);
std::string to_short_string(npl_tm_headers_template_t_anonymous_union_u_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_tx_punt_local_var_t_anonymous_union_ene_eth_or_npu_host_data_t
{
    npl_punt_eth_nw_common_encap_data_t punt_eth_nw_encap_data;
    npl_punt_eth_transport_update_t punt_eth_transport_update;
    npl_punt_npu_host_data_t punt_npu_host_data;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_tx_punt_local_var_t_anonymous_union_ene_eth_or_npu_host_data_t element);
std::string to_short_string(npl_tx_punt_local_var_t_anonymous_union_ene_eth_or_npu_host_data_t element);


struct npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t
{
    // This is an NPL anonymous union.
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_mark_y_t mark_y;
    // This is an NPL anonymous union.
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_mark_g_t mark_g;
    npl_quan_1b evict_to_dram[16];
    // This is an NPL anonymous union.
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_y_t drop_y;
    // This is an NPL anonymous union.
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_g_t drop_g;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t element);
std::string to_short_string(npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_vpn_label_encap_data_t
{
    npl_single_label_encap_data_t single_label_encap_data;
    npl_l2vpn_label_encap_data_t l2vpn_label_encap_data;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_vpn_label_encap_data_t element);
std::string to_short_string(npl_vpn_label_encap_data_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_app_mc_cud_narrow_t
{
    npl_l2_mc_cud_narrow_t l2;
    npl_npu_ip_collapsed_mc_encap_header_t ip_collapsed_mc;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_app_mc_cud_narrow_t element);
std::string to_short_string(npl_app_mc_cud_narrow_t element);


struct npl_base_l3_lp_attributes_t
{
    // This is an NPL anonymous union.
    npl_base_l3_lp_attributes_t_anonymous_union_rtf_conf_set_and_stages_or_post_fwd_stage_t rtf_conf_set_and_stages_or_post_fwd_stage;
    npl_common_cntr_offset_packed_t acl_drop_offset;
    npl_rpf_mode_e uc_rpf_mode;
    npl_port_mirror_type_e l3_lp_mirror_type;
    uint64_t mirror_cmd : 5;
    npl_minimal_l3_lp_attributes_t minimal_l3_lp_attributes;
    npl_counter_ptr_t q_counter;
    npl_counter_ptr_t m_counter;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_base_l3_lp_attributes_t element);
std::string to_short_string(npl_base_l3_lp_attributes_t element);


struct npl_bfd_aux_payload_t
{
    npl_bfd_aux_transmit_payload_t transmit;
    npl_bfd_aux_shared_payload_t shared;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_aux_payload_t element);
std::string to_short_string(npl_bfd_aux_payload_t element);


struct npl_bfd_em_compound_results_t
{
    npl_bfd_em_lookup_t bfd_payload;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_em_compound_results_t element);
std::string to_short_string(npl_bfd_em_compound_results_t element);


struct npl_ene_punt_data_on_npuh_t
{
    npl_fwd_header_type_e ene_punt_fwd_header_type;
    npl_punt_source_e ene_punt_src;
    uint64_t ene_current_nw_hdr_offset : 8;
    npl_ene_punt_sub_code_and_dsp_and_ssp_t ene_punt_sub_code_and_padding_dsp_and_ssp;
    npl_protocol_type_e ene_punt_next_header_type;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ene_punt_data_on_npuh_t element);
std::string to_short_string(npl_ene_punt_data_on_npuh_t element);


struct npl_host_nh_mac_t
{
    npl_npu_encap_header_l3_dlp_t l3_dlp;
    uint64_t host_mac : 48;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_host_nh_mac_t element);
std::string to_short_string(npl_host_nh_mac_t element);


struct npl_host_nh_ptr_t
{
    npl_npu_encap_header_l3_dlp_t l3_dlp;
    uint64_t host_ptr : 20;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_host_nh_ptr_t element);
std::string to_short_string(npl_host_nh_ptr_t element);


struct npl_ingress_punt_mc_expand_encap_t
{
    npl_npu_mirror_or_redirect_encap_type_e npu_mirror_or_redirect_encapsulation_type;
    npl_lpts_tcam_first_result_encap_data_msb_t lpts_tcam_first_result_encap_data_msb;
    uint64_t current_nw_hdr_offset : 8;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ingress_punt_mc_expand_encap_t element);
std::string to_short_string(npl_ingress_punt_mc_expand_encap_t element);


struct npl_ingress_qos_acl_result_t
{
    uint64_t override_phb : 1;
    uint64_t override_qos : 1;
    npl_q_or_meter_cntr_e meter;
    npl_phb_t phb;
    // This is an NPL anonymous union.
    npl_ingress_qos_acl_result_t_anonymous_union_ctr_offest_union_t ctr_offest_union;
    npl_ingress_qos_mapping_remark_t ingress_qos_remark;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ingress_qos_acl_result_t element);
std::string to_short_string(npl_ingress_qos_acl_result_t element);


struct npl_ingress_qos_result_t
{
    uint64_t override_qos : 1;
    uint64_t enable_ingress_remark : 1;
    // This is an NPL anonymous union.
    npl_ingress_qos_result_t_anonymous_union_ctr_offest_union_t ctr_offest_union;
    npl_phb_t phb;
    npl_encap_mpls_exp_t encap_mpls_exp;
    // This is an NPL anonymous union.
    npl_ingress_qos_result_t_anonymous_union_fwd_class_qos_group_u_t fwd_class_qos_group_u;
    uint64_t meter : 1;
    uint64_t fwd_qos_tag : 7;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ingress_qos_result_t element);
std::string to_short_string(npl_ingress_qos_result_t element);


struct npl_inject_down_encap_dlp_and_nh_t
{
    npl_npu_encap_header_l3_dlp_t down_l3_dlp;
    uint64_t down_nh : 12;
    npl_pcp_dei_t down_pcp_dei;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_down_encap_dlp_and_nh_t element);
std::string to_short_string(npl_inject_down_encap_dlp_and_nh_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_inject_down_encap_ptr_or_dlp_t
{
    uint64_t inject_down_encap_ptr : 8;
    npl_inject_down_encap_dlp_and_nh_t inject_down_encap_nh;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_down_encap_ptr_or_dlp_t element);
std::string to_short_string(npl_inject_down_encap_ptr_or_dlp_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_inject_header_specific_data_t_anonymous_union_inject_header_encap_hdr_ptr_t
{
    npl_inject_down_encap_ptr_or_dlp_t inject_down_encap_ptr_or_dlp;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_header_specific_data_t_anonymous_union_inject_header_encap_hdr_ptr_t element);
std::string to_short_string(npl_inject_header_specific_data_t_anonymous_union_inject_header_encap_hdr_ptr_t element);


struct npl_inject_up_eth_header_t
{
    // This is an NPL anonymous union.
    npl_inject_up_eth_header_t_anonymous_union_qos_or_dest_t qos_or_dest;
    // This is an NPL anonymous union.
    npl_inject_up_eth_header_t_anonymous_union_from_port_t from_port;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_up_eth_header_t element);
std::string to_short_string(npl_inject_up_eth_header_t element);


struct npl_ip_encap_data_t
{
    // This is an NPL anonymous union.
    npl_ip_encap_data_t_anonymous_union_ip_t ip;
    // This is an NPL anonymous union.
    npl_ip_encap_data_t_anonymous_union_upper_layer_t upper_layer;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_encap_data_t element);
std::string to_short_string(npl_ip_encap_data_t element);


struct npl_ip_mc_result_payload_t
{
    npl_mcid_t local_mcid;
    npl_rpf_compressed_destination_t rpf_destination;
    uint64_t punt_on_rpf_fail : 1;
    uint64_t punt_and_fwd : 1;
    npl_system_mcid_t global_mcid;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_mc_result_payload_t element);
std::string to_short_string(npl_ip_mc_result_payload_t element);


struct npl_ip_mc_result_payload_with_format_t
{
    uint64_t format : 1;
    npl_ip_mc_result_payload_t mc_result_payload;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_mc_result_payload_with_format_t element);
std::string to_short_string(npl_ip_mc_result_payload_with_format_t element);


struct npl_ip_sgt_em_padded_result_t
{
    npl_ip_sgt_em_result_t ip_sgt_em_result;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_sgt_em_padded_result_t element);
std::string to_short_string(npl_ip_sgt_em_padded_result_t element);


struct npl_l2_adj_sid_nhlfe_t
{
    npl_npu_l3_common_dlp_nh_encap_t l3_dlp_nh_encap;
    uint64_t prefix : 16;
    uint64_t dsp : 16;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2_adj_sid_nhlfe_t element);
std::string to_short_string(npl_l2_adj_sid_nhlfe_t element);


struct npl_l2_lp_attributes_t
{
    npl_learn_type_e learn_type;
    npl_learn_prob_e learn_prob;
    npl_term_l2_lp_attributes_t term;
    npl_shared_l2_lp_attributes_t shared;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2_lp_attributes_t element);
std::string to_short_string(npl_l2_lp_attributes_t element);


struct npl_l2_pwe_encap_t
{
    npl_npu_encap_header_l3_dlp_t l3_dlp;
    uint64_t nh : 12;
    npl_lsp_destination_t lsp_destination;
    npl_npu_encap_header_l2_dlp_t l2_dlp;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2_pwe_encap_t element);
std::string to_short_string(npl_l2_pwe_encap_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_l2_relay_and_l3_lp_attributes_payload_t
{
    npl_mac_relay_attributes_inf_payload_t relay_att_inf_payload;
    npl_mac_relay_attributes_t mac_relay_attributes;
    npl_mac_relay_attributes_payload_t relay_att_table_payload;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2_relay_and_l3_lp_attributes_payload_t element);
std::string to_short_string(npl_l2_relay_and_l3_lp_attributes_payload_t element);


struct npl_l2_vxlan_encap_t
{
    npl_npu_encap_header_l3_dlp_t l3_dlp;
    uint64_t nh : 12;
    npl_npu_encap_header_l2_dlp_t tunnel_dlp;
    uint64_t overlay_nh : 10;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2_vxlan_encap_t element);
std::string to_short_string(npl_l2_vxlan_encap_t element);


struct npl_l3_dlp_attributes_t
{
    uint64_t svi_dhcp_snooping : 1;
    // This is an NPL anonymous union.
    npl_l3_dlp_attributes_t_anonymous_union_l3_dlp_encap_or_te_labels_t l3_dlp_encap_or_te_labels;
    uint64_t disabled : 1;
    npl_nh_ene_macro_code_e nh_ene_macro_code;
    npl_l3_dlp_qos_and_attributes_t l3_dlp_qos_and_attributes;
    npl_tx_to_rx_rcy_data_t tx_to_rx_rcy_data;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_dlp_attributes_t element);
std::string to_short_string(npl_l3_dlp_attributes_t element);


struct npl_l3_lp_attributes_t
{
    npl_l3_lp_additional_attributes_t additional;
    npl_base_l3_lp_attributes_t base;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_lp_attributes_t element);
std::string to_short_string(npl_l3_lp_attributes_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_lsp_encap_mapping_data_payload_t_anonymous_union_label_stack_t
{
    npl_lsp_labels_opt3_t opt3;
    npl_lsp_labels_opt2_t opt2;
    npl_lsp_labels_opt1_t opt1;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lsp_encap_mapping_data_payload_t_anonymous_union_label_stack_t element);
std::string to_short_string(npl_lsp_encap_mapping_data_payload_t_anonymous_union_label_stack_t element);


struct npl_mac_l3_lp_attributes_t
{
    uint64_t l3_lp_mymac_da_prefix : 5;
    uint64_t mldp_budnode_terminate : 1;
    uint64_t l3_lp_mymac_da_lsb : 16;
    npl_base_l3_lp_attributes_t base;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_l3_lp_attributes_t element);
std::string to_short_string(npl_mac_l3_lp_attributes_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_mac_lp_attributes_payload_t_anonymous_union_layer_t
{
    npl_l2_lp_attributes_t two;
    npl_mac_l3_lp_attributes_t three;
    npl_pd_lp_attributes_t pd;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_lp_attributes_payload_t_anonymous_union_layer_t element);
std::string to_short_string(npl_mac_lp_attributes_payload_t_anonymous_union_layer_t element);


struct npl_mac_qos_macro_pack_table_fields_t
{
    uint64_t pd_qos_mapping_7b : 7;
    npl_qos_mapping_key_t l3_qos_mapping_key;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_qos_macro_pack_table_fields_t element);
std::string to_short_string(npl_mac_qos_macro_pack_table_fields_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_mc_em_db_result_t
{
    npl_mc_em_db_result_rx_t rx;
    npl_mc_em_db_result_tx_t tx;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mc_em_db_result_t element);
std::string to_short_string(npl_mc_em_db_result_t element);


struct npl_mpls_termination_l3vpn_t
{
    npl_l3_relay_id_t l3_relay_id;
    // This is an NPL anonymous union.
    npl_mpls_termination_l3vpn_t_anonymous_union_vpn_mldp_info_t vpn_mldp_info;
    npl_counter_ptr_t vpn_p_counter;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mpls_termination_l3vpn_t element);
std::string to_short_string(npl_mpls_termination_l3vpn_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_mpls_termination_result_t_anonymous_union_pwe_vpn_mldp_info_t
{
    npl_mpls_termination_l3vpn_t l3vpn_info;
    npl_mpls_termination_pwe_t pwe_info;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mpls_termination_result_t_anonymous_union_pwe_vpn_mldp_info_t element);
std::string to_short_string(npl_mpls_termination_result_t_anonymous_union_pwe_vpn_mldp_info_t element);


struct npl_nh_and_svi_payload_t
{
    npl_nh_payload_t nh_payload;
    uint64_t nh_da : 48;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_nh_and_svi_payload_t element);
std::string to_short_string(npl_nh_and_svi_payload_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_nhlfe_t_anonymous_union_nhlfe_payload_t
{
    npl_te_headend_nhlfe_t te_headend;
    npl_te_midpoint_nhlfe_t te_midpoint;
    npl_l2_adj_sid_nhlfe_t l2_adj_sid;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_nhlfe_t_anonymous_union_nhlfe_payload_t element);
std::string to_short_string(npl_nhlfe_t_anonymous_union_nhlfe_payload_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_npu_encap_header_ip_host_t_anonymous_union_next_hop_t
{
    npl_host_nh_mac_t host_nh_mac;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npu_encap_header_ip_host_t_anonymous_union_next_hop_t element);
std::string to_short_string(npl_npu_encap_header_ip_host_t_anonymous_union_next_hop_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_npu_l2_encap_header_t_anonymous_union_l2_dlp_type_t
{
    npl_l2_ac_encap_t ac;
    npl_l2_pwe_encap_t pwe;
    npl_l2_vxlan_encap_t vxlan;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npu_l2_encap_header_t_anonymous_union_l2_dlp_type_t element);
std::string to_short_string(npl_npu_l2_encap_header_t_anonymous_union_l2_dlp_type_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_npu_l3_common_encap_header_t_anonymous_union_l3_dlp_nh_encap_t
{
    npl_npu_l3_common_dlp_nh_encap_t npu_l3_common_dlp_nh_encap;
    npl_npu_l3_mc_host_gb_dlp_encap_t npu_l3_mc_host_gb_dlp_encap;
    npl_npu_l3_mc_accounting_encap_data_t npu_l3_mc_accounting_encap_data;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npu_l3_common_encap_header_t_anonymous_union_l3_dlp_nh_encap_t element);
std::string to_short_string(npl_npu_l3_common_encap_header_t_anonymous_union_l3_dlp_nh_encap_t element);


struct npl_og_em_result_t
{
    npl_ip_uc_em_result_type_e result_type;
    // This is an NPL anonymous union.
    npl_og_em_result_t_anonymous_union_result_t result;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_og_em_result_t element);
std::string to_short_string(npl_og_em_result_t element);


struct npl_punt_l3_lp_t
{
    // This is an NPL anonymous union.
    npl_punt_l3_lp_t_anonymous_union_id_or_pfc_t id_or_pfc;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_l3_lp_t element);
std::string to_short_string(npl_punt_l3_lp_t element);


struct npl_punt_msb_encap_t
{
    npl_ingress_punt_mc_expand_encap_t punt_encap_msb;
    npl_lm_command_t punt_lm_cmd;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_msb_encap_t element);
std::string to_short_string(npl_punt_msb_encap_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_resolution_stage_assoc_data_result_t
{
    npl_resolution_stage_assoc_data_raw_t raw;
    npl_resolution_stage_assoc_data_narrow_line_t narrow;
    npl_resolution_stage_assoc_data_wide_line_t wide;
    npl_resolution_stage_assoc_data_narrow_protection_line_t narrow_protection;
    npl_resolution_stage_assoc_data_wide_protection_line_t wide_protection;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_stage_assoc_data_result_t element);
std::string to_short_string(npl_resolution_stage_assoc_data_result_t element);


struct npl_rtf_payload_t
{
    npl_rtf_profile_type_e rtf_profile_index;
    // This is an NPL anonymous union.
    npl_rtf_payload_t_anonymous_union_rtf_result_profile_t rtf_result_profile;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_rtf_payload_t element);
std::string to_short_string(npl_rtf_payload_t element);


struct npl_slp_info_t
{
    uint64_t slp_profile : 2;
    // This is an NPL anonymous union.
    npl_slp_info_t_anonymous_union_global_slp_id_t global_slp_id;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_slp_info_t element);
std::string to_short_string(npl_slp_info_t element);


struct npl_snoop_or_rcy_data_t
{
    // This is an NPL anonymous union.
    npl_snoop_or_rcy_data_t_anonymous_union_snoop_or_rcy_data_t snoop_or_rcy_data;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_snoop_or_rcy_data_t element);
std::string to_short_string(npl_snoop_or_rcy_data_t element);


struct npl_std_ip_em_lpm_result_host_and_l3_dlp_t
{
    uint64_t lpm_payload : 40;
    npl_host_nh_mac_t host_nh_mac;
    // This is an NPL anonymous union.
    npl_std_ip_em_lpm_result_host_and_l3_dlp_t_anonymous_union_dest_or_dest_with_class_id_t dest_or_dest_with_class_id;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_std_ip_em_lpm_result_host_and_l3_dlp_t element);
std::string to_short_string(npl_std_ip_em_lpm_result_host_and_l3_dlp_t element);


struct npl_std_ip_em_lpm_result_ptr_and_l3_dlp_t
{
    npl_host_nh_ptr_t host_ptr;
    npl_destination_t destination;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_std_ip_em_lpm_result_ptr_and_l3_dlp_t element);
std::string to_short_string(npl_std_ip_em_lpm_result_ptr_and_l3_dlp_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_std_ip_uc_lpm_results_t_anonymous_union_result_t
{
    npl_std_ip_em_lpm_result_ptr_and_l3_dlp_t ptr_and_l3_dlp;
    npl_std_ip_em_lpm_result_host_and_l3_dlp_t host_and_l3_dlp;
    npl_lpm_std_ip_em_lpm_result_destination_t destination_from_lpm;
    npl_ip_mc_result_payload_with_format_t mc_result;
    npl_ip_sgt_result_t sgt_data;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_std_ip_uc_lpm_results_t_anonymous_union_result_t element);
std::string to_short_string(npl_std_ip_uc_lpm_results_t_anonymous_union_result_t element);


struct npl_svi_eve_profile_and_data_t
{
    npl_vlan_edit_command_main_type_e main_type;
    // This is an NPL anonymous union.
    npl_svi_eve_profile_and_data_t_anonymous_union_sub_type_or_vid_2_plus_prf_t sub_type_or_vid_2_plus_prf;
    uint64_t vid1 : 12;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_svi_eve_profile_and_data_t element);
std::string to_short_string(npl_svi_eve_profile_and_data_t element);


struct npl_tm_headers_template_t
{
    // This is an NPL anonymous union.
    npl_tm_headers_template_t_anonymous_union_u_t u;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_tm_headers_template_t element);
std::string to_short_string(npl_tm_headers_template_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_ac_dlp_specific_t_anonymous_union_eve_types_t
{
    npl_ive_profile_and_data_t eve;
    npl_svi_eve_profile_and_data_t eve_svi;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ac_dlp_specific_t_anonymous_union_eve_types_t element);
std::string to_short_string(npl_ac_dlp_specific_t_anonymous_union_eve_types_t element);


struct npl_app_mc_cud_narrow_even_t
{
    uint64_t raw : 60;
    npl_app_mc_cud_narrow_t app_mc_cud_narrow;
    uint64_t raw1 : 20;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_app_mc_cud_narrow_even_t element);
std::string to_short_string(npl_app_mc_cud_narrow_even_t element);


struct npl_app_mc_cud_narrow_odd_and_even_t
{
    npl_app_mc_cud_narrow_t odd;
    uint64_t raw : 20;
    npl_app_mc_cud_narrow_t even;
    uint64_t raw1 : 20;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_app_mc_cud_narrow_odd_and_even_t element);
std::string to_short_string(npl_app_mc_cud_narrow_odd_and_even_t element);


struct npl_app_mc_cud_narrow_odd_t
{
    npl_app_mc_cud_narrow_t app_mc_cud_narrow;
    uint64_t reserved[2];
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_app_mc_cud_narrow_odd_t element);
std::string to_short_string(npl_app_mc_cud_narrow_odd_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_base_l3_lp_attr_union_t
{
    npl_lp_attr_update_raw_bits_t update;
    npl_base_l3_lp_attributes_t base;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_base_l3_lp_attr_union_t element);
std::string to_short_string(npl_base_l3_lp_attr_union_t element);


struct npl_em_result_ptr_and_l3_dlp_t
{
    npl_host_nh_ptr_t host_ptr;
    npl_destination_t destination;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_em_result_ptr_and_l3_dlp_t element);
std::string to_short_string(npl_em_result_ptr_and_l3_dlp_t element);


struct npl_inject_down_data_t
{
    npl_inject_down_encap_ptr_or_dlp_t bfd_ih_down;
    npl_inject_down_header_t inject_down;
    npl_counter_ptr_t counter_ptr;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_down_data_t element);
std::string to_short_string(npl_inject_down_data_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_inject_specific_data_t_anonymous_union_inject_data_t
{
    // This is an NPL anonymous union.
    npl_inject_specific_data_t_anonymous_union_inject_data_t_anonymous_union_inject_down_u_t inject_down_u;
    npl_inject_up_eth_header_t inject_up_eth;
    npl_inject_up_none_routable_mc_lpts_t inject_up_none_routable_mc_lpts;
    npl_inject_up_vxlan_mc_t inject_vxlan_mc_up;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_specific_data_t_anonymous_union_inject_data_t element);
std::string to_short_string(npl_inject_specific_data_t_anonymous_union_inject_data_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_ip_em_result_t_anonymous_union_result_t
{
    npl_em_destination_t em_dest;
    npl_em_result_ptr_and_l3_dlp_t ptr_and_l3_dlp;
    npl_em_result_dsp_host_t dsp_host;
    npl_em_result_dsp_host_w_class_t dsp_host_w_class;
    npl_em_result_dsp_host_wo_class_t dsp_host_wo_class;
    npl_ip_mc_result_payload_t mc_result;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_em_result_t_anonymous_union_result_t element);
std::string to_short_string(npl_ip_em_result_t_anonymous_union_result_t element);


struct npl_ip_mc_result_em_payload_t
{
    npl_ip_mc_result_payload_t raw_payload;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_mc_result_em_payload_t element);
std::string to_short_string(npl_ip_mc_result_em_payload_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_l3_lp_extra_data_with_padding_t_anonymous_union_l3_punt_info_t
{
    npl_punt_l3_lp_t l3_lp;
    npl_l3_pfc_data_t pfc;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_lp_extra_data_with_padding_t_anonymous_union_l3_punt_info_t element);
std::string to_short_string(npl_l3_lp_extra_data_with_padding_t_anonymous_union_l3_punt_info_t element);


struct npl_l3_lp_with_padding_t
{
    npl_punt_l3_lp_t l3_lp;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_lp_with_padding_t element);
std::string to_short_string(npl_l3_lp_with_padding_t element);


struct npl_lsp_encap_mapping_data_payload_t
{
    // This is an NPL anonymous union.
    npl_lsp_encap_mapping_data_payload_t_anonymous_union_label_stack_t label_stack;
    // This is an NPL anonymous union.
    npl_lsp_encap_mapping_data_payload_t_anonymous_union_counter_and_flag_t counter_and_flag;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_lsp_encap_mapping_data_payload_t element);
std::string to_short_string(npl_lsp_encap_mapping_data_payload_t element);


struct npl_mac_lp_attributes_payload_t
{
    npl_mac_lp_type_e mac_lp_type;
    // This is an NPL anonymous union.
    npl_mac_lp_attributes_payload_t_anonymous_union_layer_t layer;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_lp_attributes_payload_t element);
std::string to_short_string(npl_mac_lp_attributes_payload_t element);


struct npl_mac_lp_attributes_t
{
    npl_mac_lp_attributes_payload_t payload;
    npl_lp_id_t local_slp_id;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_lp_attributes_t element);
std::string to_short_string(npl_mac_lp_attributes_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_mac_lp_attributes_table_payload_t
{
    npl_mac_lp_attributes_payload_t lp_attr;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_lp_attributes_table_payload_t element);
std::string to_short_string(npl_mac_lp_attributes_table_payload_t element);


struct npl_mac_relay_pack_table_payload_t
{
    uint64_t local_mapped_qos_group : 7;
    npl_slp_info_t muxed_slp_info;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mac_relay_pack_table_payload_t element);
std::string to_short_string(npl_mac_relay_pack_table_payload_t element);


struct npl_mpls_termination_result_t
{
    npl_mpls_service_e service;
    // This is an NPL anonymous union.
    npl_mpls_termination_result_t_anonymous_union_pwe_vpn_mldp_info_t pwe_vpn_mldp_info;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mpls_termination_result_t element);
std::string to_short_string(npl_mpls_termination_result_t element);


struct npl_nhlfe_t
{
    npl_nhlfe_type_e type;
    // This is an NPL anonymous union.
    npl_nhlfe_t_anonymous_union_nhlfe_payload_t nhlfe_payload;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_nhlfe_t element);
std::string to_short_string(npl_nhlfe_t element);


struct npl_npu_encap_header_ip_host_t
{
    npl_npu_encap_l3_header_type_e l3_encapsulation_type;
    // This is an NPL anonymous union.
    npl_npu_encap_header_ip_host_t_anonymous_union_next_hop_t next_hop;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npu_encap_header_ip_host_t element);
std::string to_short_string(npl_npu_encap_header_ip_host_t element);


struct npl_npu_l2_encap_header_t
{
    npl_npu_encap_l2_header_type_e l2_encapsulation_type;
    // This is an NPL anonymous union.
    npl_npu_l2_encap_header_t_anonymous_union_l2_dlp_type_t l2_dlp_type;
    npl_npu_dsp_pif_ifg_t npu_pif_ifg;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npu_l2_encap_header_t element);
std::string to_short_string(npl_npu_l2_encap_header_t element);


struct npl_npu_l3_common_encap_header_t
{
    npl_npu_encap_l3_header_type_e l3_encap_type;
    // This is an NPL anonymous union.
    npl_npu_l3_common_encap_header_t_anonymous_union_l3_dlp_nh_encap_t l3_dlp_nh_encap;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npu_l3_common_encap_header_t element);
std::string to_short_string(npl_npu_l3_common_encap_header_t element);


struct npl_npu_l3_encap_header_t
{
    npl_npu_l3_common_encap_header_t l3_common_encap;
    // This is an NPL anonymous union.
    npl_npu_l3_encap_header_t_anonymous_union_encap_ext_t encap_ext;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npu_l3_encap_header_t element);
std::string to_short_string(npl_npu_l3_encap_header_t element);


struct npl_og_em_padded_result_t
{
    npl_og_em_result_t og_em_result;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_og_em_padded_result_t element);
std::string to_short_string(npl_og_em_padded_result_t element);


struct npl_punt_encap_data_t
{
    npl_punt_msb_encap_t punt_msb_encap;
    npl_punt_lsb_encap_t punt_lsb_encap;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_encap_data_t element);
std::string to_short_string(npl_punt_encap_data_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_punt_header_t_anonymous_union_slp_t
{
    npl_l2_lp_with_padding_t l2_slp;
    npl_l3_lp_with_padding_t l3_slp;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_header_t_anonymous_union_slp_t element);
std::string to_short_string(npl_punt_header_t_anonymous_union_slp_t element);


struct npl_raw_ip_mc_result_t
{
    npl_ip_mc_result_em_payload_t result_payload;
    uint64_t raw : 4;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_raw_ip_mc_result_t element);
std::string to_short_string(npl_raw_ip_mc_result_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_resolution_result_enc_data_t
{
    npl_npu_l2_encap_header_t l2;
    npl_npu_l3_encap_header_t l3;
    npl_npu_ip_collapsed_mc_encap_header_t ip_collapsed_mc_encap_header;
    npl_npu_encap_header_ip_host_t mpls_mc_host_encap_header;
    npl_resolution_dlp_attributes_t dlp_attributes;
    npl_npu_dsp_pif_ifg_t pif_ifg_data;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_result_enc_data_t element);
std::string to_short_string(npl_resolution_result_enc_data_t element);


struct npl_std_ip_uc_lpm_results_t
{
    // This is an NPL anonymous union.
    npl_std_ip_uc_lpm_results_t_anonymous_union_result_t result;
    uint64_t is_default_unused : 1;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_std_ip_uc_lpm_results_t element);
std::string to_short_string(npl_std_ip_uc_lpm_results_t element);


struct npl_wrap_nhlfe_t
{
    npl_nhlfe_t nhlfe;
    uint64_t reserved : 4;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_wrap_nhlfe_t element);
std::string to_short_string(npl_wrap_nhlfe_t element);


struct npl_ac_dlp_specific_t
{
    uint64_t vlan_after_eve_format : 20;
    // This is an NPL anonymous union.
    npl_ac_dlp_specific_t_anonymous_union_eve_types_t eve_types;
    uint64_t mep_exists : 1;
    uint64_t max_mep_level : 3;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ac_dlp_specific_t element);
std::string to_short_string(npl_ac_dlp_specific_t element);


struct npl_app_mc_cud_t
{
    npl_resolution_result_enc_data_t npu_encap_data;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_app_mc_cud_t element);
std::string to_short_string(npl_app_mc_cud_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_slp_t
{
    npl_l2_lp_with_padding_t l2_slp;
    npl_l3_lp_with_padding_t l3_slp;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_slp_t element);
std::string to_short_string(npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_slp_t element);


struct npl_inject_specific_data_t
{
    // This is an NPL anonymous union.
    npl_inject_specific_data_t_anonymous_union_inject_data_t inject_data;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_specific_data_t element);
std::string to_short_string(npl_inject_specific_data_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_ip_em_lpm_result_t_anonymous_union_result_t
{
    npl_std_ip_uc_lpm_results_t lpm_result;
    npl_gb_std_ip_em_lpm_result_destination_with_default_t destination_with_default;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_em_lpm_result_t_anonymous_union_result_t element);
std::string to_short_string(npl_ip_em_lpm_result_t_anonymous_union_result_t element);


struct npl_ip_em_result_t
{
    npl_ip_uc_em_result_type_e result_type;
    // This is an NPL anonymous union.
    npl_ip_em_result_t_anonymous_union_result_t result;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_em_result_t element);
std::string to_short_string(npl_ip_em_result_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_l2_dlp_specific_t
{
    npl_ac_dlp_specific_t ac;
    npl_pwe_dlp_specific_t pwe;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2_dlp_specific_t element);
std::string to_short_string(npl_l2_dlp_specific_t element);


struct npl_l3_lp_extra_data_with_padding_t
{
    // This is an NPL anonymous union.
    npl_l3_lp_extra_data_with_padding_t_anonymous_union_l3_punt_info_t l3_punt_info;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l3_lp_extra_data_with_padding_t element);
std::string to_short_string(npl_l3_lp_extra_data_with_padding_t element);


struct npl_mpls_termination_res_t
{
    npl_mpls_termination_result_t result;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mpls_termination_res_t element);
std::string to_short_string(npl_mpls_termination_res_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_punt_app_encap_t
{
    npl_punt_encap_data_t punt_encap_data;
    npl_fabric_mc_ibm_cmd_t fabric_mc_ibm_cmd;
    uint64_t dcf_data : 38;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_app_encap_t element);
std::string to_short_string(npl_punt_app_encap_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_punt_header_t_anonymous_union_dlp_t
{
    npl_l2_lp_with_padding_t l2_dlp;
    npl_l3_lp_extra_data_with_padding_t l3_dlp;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_header_t_anonymous_union_dlp_t element);
std::string to_short_string(npl_punt_header_t_anonymous_union_dlp_t element);


struct npl_resolution_result_dest_and_enc_data_t
{
    npl_resolution_result_enc_data_t enc;
    npl_resolution_result_dest_data_t dest;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_resolution_result_dest_and_enc_data_t element);
std::string to_short_string(npl_resolution_result_dest_and_enc_data_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_app_mirror_cud_t
{
    npl_punt_app_encap_t mirror_cud_encap;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_app_mirror_cud_t element);
std::string to_short_string(npl_app_mirror_cud_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_cud_mapping_local_vars_t_anonymous_union_mapped_cud_t
{
    npl_app_mc_cud_t app_mc_cud;
    npl_app_mc_cud_narrow_odd_t app_mc_cud_narrow_odd;
    npl_app_mc_cud_narrow_even_t app_mc_cud_narrow_even;
    npl_app_mc_cud_narrow_odd_and_even_t app_mc_cud_narrow_odd_and_even;
    npl_app_mirror_cud_t mirror;
    uint64_t raw[2];
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_cud_mapping_local_vars_t_anonymous_union_mapped_cud_t element);
std::string to_short_string(npl_cud_mapping_local_vars_t_anonymous_union_mapped_cud_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_cud_mapping_local_vars_t_anonymous_union_wide_mc_cud_t
{
    npl_app_mc_cud_t app_mc_cud;
    npl_app_mirror_cud_t mirror;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_cud_mapping_local_vars_t_anonymous_union_wide_mc_cud_t element);
std::string to_short_string(npl_cud_mapping_local_vars_t_anonymous_union_wide_mc_cud_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_dlp_t
{
    npl_l2_lp_with_padding_t l2_dlp;
    npl_l3_lp_extra_data_with_padding_t l3_dlp;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_dlp_t element);
std::string to_short_string(npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_dlp_t element);


struct npl_ibm_encap_header_on_direct_t
{
    uint64_t wide_bit : 1;
    npl_punt_app_encap_t ibm_encap_header;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ibm_encap_header_on_direct_t element);
std::string to_short_string(npl_ibm_encap_header_on_direct_t element);


struct npl_inject_header_app_specific_data_t
{
    npl_inject_specific_data_t inject_specific_data;
    npl_counter_ptr_t counter_ptr;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_header_app_specific_data_t element);
std::string to_short_string(npl_inject_header_app_specific_data_t element);


struct npl_inject_header_specific_data_t
{
    npl_inject_header_app_specific_data_t inject_header_app_specific_data;
    // This is an NPL anonymous union.
    npl_inject_header_specific_data_t_anonymous_union_inject_header_encap_hdr_ptr_t inject_header_encap_hdr_ptr;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_header_specific_data_t element);
std::string to_short_string(npl_inject_header_specific_data_t element);


struct npl_inject_header_t
{
    npl_inject_header_type_e inject_header_type;
    npl_inject_header_specific_data_t inject_header_specific_data;
    // This is an NPL anonymous union.
    npl_inject_header_t_anonymous_union_ts_and_cntr_stamp_cmd_t ts_and_cntr_stamp_cmd;
    npl_npl_internal_info_t npl_internal_info;
    npl_inject_header_trailer_type_e inject_header_trailer_type;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_header_t element);
std::string to_short_string(npl_inject_header_t element);


struct npl_inject_header_with_time_t
{
    npl_inject_header_t base_inject_header;
    uint64_t time_extension : 32;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_header_with_time_t element);
std::string to_short_string(npl_inject_header_with_time_t element);


struct npl_inject_up_data_t
{
    npl_inject_header_app_specific_data_t bfd_ih_app;
    uint64_t inject_vlan_id : 12;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_inject_up_data_t element);
std::string to_short_string(npl_inject_up_data_t element);


struct npl_ip_em_lpm_result_t
{
    // This is an NPL anonymous union.
    npl_ip_em_lpm_result_t_anonymous_union_result_t result;
    uint64_t result_type : 2;
    uint64_t no_hbm_access : 1;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ip_em_lpm_result_t element);
std::string to_short_string(npl_ip_em_lpm_result_t element);


struct npl_l2_dlp_attributes_t
{
    uint64_t disabled : 1;
    uint64_t stp_state_is_block : 1;
    npl_dlp_attributes_t dlp_attributes;
    npl_tx_to_rx_rcy_data_t tx_to_rx_rcy_data;
    npl_l2_dlp_specific_t l2_dlp_specific;
    npl_qos_attributes_t qos_attributes;
    uint64_t acl_id : 4;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_l2_dlp_attributes_t element);
std::string to_short_string(npl_l2_dlp_attributes_t element);


struct npl_pfc_mp_table_shared_payload_t
{
    npl_inject_header_t inj_header;
    uint64_t inject_ifg_id : 4;
    uint64_t profile : 2;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_pfc_mp_table_shared_payload_t element);
std::string to_short_string(npl_pfc_mp_table_shared_payload_t element);


struct npl_punt_header_t
{
    npl_protocol_type_e punt_next_header;
    npl_fwd_header_type_e punt_fwd_header_type;
    uint64_t reserved : 3;
    // This is an NPL anonymous union.
    npl_punt_header_t_anonymous_union_pl_header_offset_t pl_header_offset;
    npl_punt_src_and_code_t punt_src_and_code;
    npl_punt_sub_code_with_padding_t punt_sub_code;
    uint64_t ssp : 16;
    uint64_t dsp : 16;
    // This is an NPL anonymous union.
    npl_punt_header_t_anonymous_union_slp_t slp;
    // This is an NPL anonymous union.
    npl_punt_header_t_anonymous_union_dlp_t dlp;
    npl_app_relay_id_t punt_relay_id;
    uint64_t time_stamp_val : 64;
    uint64_t receive_time : 32;
    bit_vector384_t pack(void) const;
    void unpack(bit_vector384_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_punt_header_t element);
std::string to_short_string(npl_punt_header_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_bfd_mp_table_shared_lsb_t_anonymous_union_inject_data_t
{
    npl_inject_down_data_t inject_down_data;
    npl_inject_up_data_t inject_up_data;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_mp_table_shared_lsb_t_anonymous_union_inject_data_t element);
std::string to_short_string(npl_bfd_mp_table_shared_lsb_t_anonymous_union_inject_data_t element);


struct npl_ene_punt_dlp_and_slp_t
{
    // This is an NPL anonymous union.
    npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_slp_t ene_slp;
    // This is an NPL anonymous union.
    npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_dlp_t ene_dlp;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ene_punt_dlp_and_slp_t element);
std::string to_short_string(npl_ene_punt_dlp_and_slp_t element);


struct npl_ene_punt_encap_data_t
{
    npl_ene_punt_dlp_and_slp_t ene_punt_dlp_and_slp;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ene_punt_encap_data_t element);
std::string to_short_string(npl_ene_punt_encap_data_t element);


struct npl_eth_mp_table_shared_payload_t
{
    npl_punt_code_t punt_code;
    npl_meg_id_format_e meg_id_format;
    npl_eth_oam_da_e dmr_lmr_da;
    uint64_t md_level : 3;
    uint64_t ccm_period : 3;
    uint64_t mep_address_lsb : 16;
    uint64_t per_tc_count : 1;
    uint64_t mep_address_prefix_index : 2;
    npl_inject_header_app_specific_data_t inject_header_data;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_eth_mp_table_shared_payload_t element);
std::string to_short_string(npl_eth_mp_table_shared_payload_t element);


struct npl_bfd_mp_table_shared_lsb_t
{
    uint64_t inject_ifg_id : 4;
    uint64_t udp_checksum : 16;
    // This is an NPL anonymous union.
    npl_bfd_mp_table_shared_lsb_t_anonymous_union_inject_data_t inject_data;
    bit_vector128_t pack(void) const;
    void unpack(bit_vector128_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_mp_table_shared_lsb_t element);
std::string to_short_string(npl_bfd_mp_table_shared_lsb_t element);


struct npl_bfd_mp_table_shared_payload_t
{
    npl_bfd_mp_table_shared_msb_t shared_msb;
    npl_bfd_mp_table_shared_lsb_t shared_lsb;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_mp_table_shared_payload_t element);
std::string to_short_string(npl_bfd_mp_table_shared_payload_t element);


struct npl_ene_punt_encap_data_and_misc_pack_payload_t
{
    uint64_t ene_bytes_to_remove : 8;
    npl_ene_punt_encap_data_t ene_punt_encap_data;
    bit_vector64_t pack(void) const;
    void unpack(bit_vector64_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_ene_punt_encap_data_and_misc_pack_payload_t element);
std::string to_short_string(npl_ene_punt_encap_data_and_misc_pack_payload_t element);


struct npl_eth_mp_table_app_t
{
    npl_eth_mp_table_transmit_a_payload_t transmit_a;
    npl_eth_mp_table_shared_payload_t shared;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_eth_mp_table_app_t element);
std::string to_short_string(npl_eth_mp_table_app_t element);


struct npl_bfd_mp_table_app_t
{
    npl_bfd_mp_table_shared_payload_t shared;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_bfd_mp_table_app_t element);
std::string to_short_string(npl_bfd_mp_table_app_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_mp_table_rd_app_t_anonymous_union_mp_data_union_t
{
    npl_eth_mp_table_app_t eth;
    npl_bfd_mp_table_app_t bfd;
    npl_bfd_mp_table_extra_payload_t bfd_extra;
    npl_pfc_mp_table_shared_payload_t pfc;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mp_table_rd_app_t_anonymous_union_mp_data_union_t element);
std::string to_short_string(npl_mp_table_rd_app_t_anonymous_union_mp_data_union_t element);


struct npl_mp_table_rd_app_t
{
    // This is an NPL anonymous union.
    npl_mp_table_rd_app_t_anonymous_union_mp_data_union_t mp_data_union;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mp_table_rd_app_t element);
std::string to_short_string(npl_mp_table_rd_app_t element);


struct npl_mp_table_app_t
{
    npl_mp_table_rd_app_t mp_rd_data;
    npl_mp_type_e mp_type;
    // This is an NPL anonymous union.
    npl_mp_table_app_t_anonymous_union_mp2_data_union_t mp2_data_union;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mp_table_app_t element);
std::string to_short_string(npl_mp_table_app_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_overload_union_npu_host_mp_data_t_app_defined_t
{
    npl_mp_table_app_t app;
    uint64_t app_defined[3];
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_overload_union_npu_host_mp_data_t_app_defined_t element);
std::string to_short_string(npl_overload_union_npu_host_mp_data_t_app_defined_t element);

// This is an NPL union modeled as a C struct. Only one field may be non-zero.
struct npl_npu_host_mp_data_t
{
    npl_overload_union_npu_host_mp_data_t_app_defined_t overload_union_app_defined;
    uint64_t raw[3];
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npu_host_mp_data_t element);
std::string to_short_string(npl_npu_host_mp_data_t element);


struct npl_npu_host_mp_data_with_padding_t
{
    npl_npu_host_mp_data_t host_data;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_npu_host_mp_data_with_padding_t element);
std::string to_short_string(npl_npu_host_mp_data_with_padding_t element);

// This is an NPL anonymous union modeled as a C struct. Only one field may be non-zero.
struct npl_mp_data_result_t_anonymous_union_npu_host_mp_data_t
{
    npl_npu_host_mp_data_with_padding_t npu_host_mp_data;
    npl_npu_host_data_result_count_phase_t npu_host_data_res_count_phase;
    bit_vector192_t pack(void) const;
    void unpack(bit_vector192_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mp_data_result_t_anonymous_union_npu_host_mp_data_t element);
std::string to_short_string(npl_mp_data_result_t_anonymous_union_npu_host_mp_data_t element);


struct npl_mp_data_result_t
{
    // This is an NPL anonymous union.
    npl_mp_data_result_t_anonymous_union_npu_host_mp_data_t npu_host_mp_data;
    uint64_t ccm_period : 3;
    uint64_t dm_valid : 1;
    uint64_t lm_valid : 1;
    uint64_t ccm_valid : 1;
    uint64_t aux_ptr : 12;
    uint64_t mp_valid : 1;
    bit_vector384_t pack(void) const;
    void unpack(bit_vector384_t);
    field_structure to_field_structure(void) const;
};
std::string to_string(npl_mp_data_result_t element);
std::string to_short_string(npl_mp_data_result_t element);

#pragma pack(pop)

#endif
