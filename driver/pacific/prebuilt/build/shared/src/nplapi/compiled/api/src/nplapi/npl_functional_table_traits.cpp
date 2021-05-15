
// This file has been automatically generated using nplc.py. Do not edit it manually.
// Version: 1.76.2_0.0.0.0 generated on devsrv15.leaba.local at 2021-05-12 16:09:15


#include "nplapi/npl_functional_table_traits.h"

using namespace silicon_one;

bool
npl_ternary_field_compare(uint64_t v1, uint64_t v2, uint64_t mask)
{
    return ((v1 ^ v2) & mask) == 0;
}

bool
npl_ternary_wide_field_compare(const void* v1, const void* v2, const void* mask, size_t width)
{
    const size_t BITS_IN_BYTE = 8;
    
    const char* c1 = (const char*)v1;
    const char* c2 = (const char*)v2;
    const char* m = (const char*)mask;
    
    size_t i;
    for (i = 0; i < width / BITS_IN_BYTE; i++) {
        if (((c1[i] ^ c2[i]) & m[i]) != 0) {
            return false;
        }
    }
    
    size_t remainder = width % BITS_IN_BYTE;
    if (remainder == 0) {
        return true;
    }
    
    const char remainder_bits_mask = (1 << remainder) - 1;
    return ((c1[i] ^ c2[i]) & m[i] & remainder_bits_mask) == 0;
}

void
npl_lpm_wide_field_apply_mask(uint64_t* buf, size_t bits_nr, size_t length)
{
    if (length >= bits_nr) { // eliminates also bits_nr == 0
        return;
    }
    
    // clearing the elements needed to be fully cleared
    static const size_t ELEMENT_SIZE = 64;
    size_t elements_to_fully_clear = (bits_nr - length) / ELEMENT_SIZE;
    for (size_t j = 0; j < elements_to_fully_clear; j++) {
        buf[j] = 0;
    }
    
    // clearing also the msb element if needed
    size_t bits_to_clear_in_msb_element = (bits_nr - length) % ELEMENT_SIZE;
    if (bits_to_clear_in_msb_element != 0) {
        uint64_t msb_element_mask = ~((1ULL << (bits_to_clear_in_msb_element)) - 1);
        buf[elements_to_fully_clear] &= msb_element_mask;
    }
}


bool
npl_bfd_udp_port_map_static_table_functional_traits_t::key_match(const npl_bfd_udp_port_map_static_table_key_t& lookup_key, const npl_bfd_udp_port_map_static_table_key_t& table_key, const npl_bfd_udp_port_map_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.pd_redirect_stage_vars_skip_bfd_or_ttl_255, table_key.pd_redirect_stage_vars_skip_bfd_or_ttl_255, table_mask.pd_redirect_stage_vars_skip_bfd_or_ttl_255)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.packet_header_info_type, table_key.packet_header_info_type, table_mask.packet_header_info_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.packet_ipv4_header_protocol, table_key.packet_ipv4_header_protocol, table_mask.packet_ipv4_header_protocol)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.packet_ipv6_header_next_header, table_key.packet_ipv6_header_next_header, table_mask.packet_ipv6_header_next_header)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.packet_header_1__udp_header_dst_port, table_key.packet_header_1__udp_header_dst_port, table_mask.packet_header_1__udp_header_dst_port)) {
        return false;
    }
    
    
    return true;
}

bool
npl_default_egress_ipv4_sec_acl_table_functional_traits_t::key_match(const npl_default_egress_ipv4_sec_acl_table_key_t& lookup_key, const npl_default_egress_ipv4_sec_acl_table_key_t& table_key, const npl_default_egress_ipv4_sec_acl_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.sip, table_key.sip, table_mask.sip)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.dip, table_key.dip, table_mask.dip)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.src_port, table_key.src_port, table_mask.src_port)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.dst_port, table_key.dst_port, table_mask.dst_port)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.fwd_qos_tag_5_0_, table_key.fwd_qos_tag_5_0_, table_mask.fwd_qos_tag_5_0_)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.new_ttl, table_key.new_ttl, table_mask.new_ttl)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.protocol, table_key.protocol, table_mask.protocol)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.tcp_flags, table_key.tcp_flags, table_mask.tcp_flags)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ip_first_fragment.val, table_key.ip_first_fragment.val, table_mask.ip_first_fragment.val)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.acl_id, table_key.acl_id, table_mask.acl_id)) {
        return false;
    }
    
    
    return true;
}

bool
npl_default_egress_ipv6_acl_sec_table_functional_traits_t::key_match(const npl_default_egress_ipv6_acl_sec_table_key_t& lookup_key, const npl_default_egress_ipv6_acl_sec_table_key_t& table_key, const npl_default_egress_ipv6_acl_sec_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.next_header, table_key.next_header, table_mask.next_header)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.dst_port, table_key.dst_port, table_mask.dst_port)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.acl_id, table_key.acl_id, table_mask.acl_id)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.dip, &table_key.dip, &table_mask.dip, 128)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.first_fragment.val, table_key.first_fragment.val, table_mask.first_fragment.val)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.sip, &table_key.sip, &table_mask.sip, 128)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.src_port, table_key.src_port, table_mask.src_port)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.qos_tag, table_key.qos_tag, table_mask.qos_tag)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.tcp_flags, table_key.tcp_flags, table_mask.tcp_flags)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ecn_remark_static_table_functional_traits_t::key_match(const npl_ecn_remark_static_table_key_t& lookup_key, const npl_ecn_remark_static_table_key_t& table_key, const npl_ecn_remark_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.pd_cong_on.val, table_key.pd_cong_on.val, table_mask.pd_cong_on.val)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.tx_npu_header_fwd_header_type, table_key.tx_npu_header_fwd_header_type, table_mask.tx_npu_header_fwd_header_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.packet_ipv4_header_tos_3_0_, table_key.packet_ipv4_header_tos_3_0_, table_mask.packet_ipv4_header_tos_3_0_)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.packet_ipv6_header_tos_3_0_, table_key.packet_ipv6_header_tos_3_0_, table_mask.packet_ipv6_header_tos_3_0_)) {
        return false;
    }
    
    
    return true;
}

bool
npl_egress_mac_ipv4_sec_acl_table_functional_traits_t::key_match(const npl_egress_mac_ipv4_sec_acl_table_key_t& lookup_key, const npl_egress_mac_ipv4_sec_acl_table_key_t& table_key, const npl_egress_mac_ipv4_sec_acl_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.sip_dip.sip, table_key.sip_dip.sip, table_mask.sip_dip.sip)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.sip_dip.dip, table_key.sip_dip.dip, table_mask.sip_dip.dip)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l4_ports.src_port, table_key.l4_ports.src_port, table_mask.l4_ports.src_port)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l4_ports.dst_port, table_key.l4_ports.dst_port, table_mask.l4_ports.dst_port)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.tos.dscp, table_key.tos.dscp, table_mask.tos.dscp)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.tos.ecn, table_key.tos.ecn, table_mask.tos.ecn)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ttl_and_protocol.ttl, table_key.ttl_and_protocol.ttl, table_mask.ttl_and_protocol.ttl)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ttl_and_protocol.protocol, table_key.ttl_and_protocol.protocol, table_mask.ttl_and_protocol.protocol)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.tcp_flags, table_key.tcp_flags, table_mask.tcp_flags)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ip_first_fragment.val, table_key.ip_first_fragment.val, table_mask.ip_first_fragment.val)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.acl_id, table_key.acl_id, table_mask.acl_id)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ene_byte_addition_static_table_functional_traits_t::key_match(const npl_ene_byte_addition_static_table_key_t& lookup_key, const npl_ene_byte_addition_static_table_key_t& table_key, const npl_ene_byte_addition_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.pd_first_ene_macro.id, table_key.pd_first_ene_macro.id, table_mask.pd_first_ene_macro.id)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.pd_ene_macro_ids_0_.id, table_key.pd_ene_macro_ids_0_.id, table_mask.pd_ene_macro_ids_0_.id)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.pd_ene_macro_ids_1_.id, table_key.pd_ene_macro_ids_1_.id, table_mask.pd_ene_macro_ids_1_.id)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.pd_ene_macro_ids_2_.id, table_key.pd_ene_macro_ids_2_.id, table_mask.pd_ene_macro_ids_2_.id)) {
        return false;
    }
    
    
    return true;
}

bool
npl_erpp_fabric_counters_offset_table_functional_traits_t::key_match(const npl_erpp_fabric_counters_offset_table_key_t& lookup_key, const npl_erpp_fabric_counters_offset_table_key_t& table_key, const npl_erpp_fabric_counters_offset_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.vce, table_key.vce, table_mask.vce)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.tc, table_key.tc, table_mask.tc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.dp, table_key.dp, table_mask.dp)) {
        return false;
    }
    
    
    return true;
}

bool
npl_erpp_fabric_counters_table_functional_traits_t::key_match(const npl_erpp_fabric_counters_table_key_t& lookup_key, const npl_erpp_fabric_counters_table_key_t& table_key, const npl_erpp_fabric_counters_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.dest_device, table_key.dest_device, table_mask.dest_device)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.dest_slice, table_key.dest_slice, table_mask.dest_slice)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.dest_oq, table_key.dest_oq, table_mask.dest_oq)) {
        return false;
    }
    
    
    return true;
}

bool
npl_fabric_and_tm_header_size_static_table_functional_traits_t::key_match(const npl_fabric_and_tm_header_size_static_table_key_t& lookup_key, const npl_fabric_and_tm_header_size_static_table_key_t& table_key, const npl_fabric_and_tm_header_size_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.fabric_header_type, table_key.fabric_header_type, table_mask.fabric_header_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.tm_header_type, table_key.tm_header_type, table_mask.tm_header_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.npuh_size, table_key.npuh_size, table_mask.npuh_size)) {
        return false;
    }
    
    
    return true;
}

bool
npl_fabric_header_ene_macro_table_functional_traits_t::key_match(const npl_fabric_header_ene_macro_table_key_t& lookup_key, const npl_fabric_header_ene_macro_table_key_t& table_key, const npl_fabric_header_ene_macro_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.fabric_header_type, table_key.fabric_header_type, table_mask.fabric_header_type)) {
        return false;
    }
    
    
    return true;
}

bool
npl_fabric_headers_type_table_functional_traits_t::key_match(const npl_fabric_headers_type_table_key_t& lookup_key, const npl_fabric_headers_type_table_key_t& table_key, const npl_fabric_headers_type_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.initial_fabric_header_type, table_key.initial_fabric_header_type, table_mask.initial_fabric_header_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.plb_header_type, table_key.plb_header_type, table_mask.plb_header_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.start_packing, table_key.start_packing, table_mask.start_packing)) {
        return false;
    }
    
    
    return true;
}

bool
npl_fabric_init_cfg_functional_traits_t::key_match(const npl_fabric_init_cfg_key_t& lookup_key, const npl_fabric_init_cfg_key_t& table_key, const npl_fabric_init_cfg_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.ser, table_key.ser, table_mask.ser)) {
        return false;
    }
    
    
    return true;
}

bool
npl_fabric_npuh_size_calculation_static_table_functional_traits_t::key_match(const npl_fabric_npuh_size_calculation_static_table_key_t& lookup_key, const npl_fabric_npuh_size_calculation_static_table_key_t& table_key, const npl_fabric_npuh_size_calculation_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.device_tx_cud_msb_4bits, table_key.device_tx_cud_msb_4bits, table_mask.device_tx_cud_msb_4bits)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.packet_tx_npu_header_fwd_header_type, table_key.packet_tx_npu_header_fwd_header_type, table_mask.packet_tx_npu_header_fwd_header_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.packet_tx_npu_header_encap_encapsulation_type_redirect_encap_type, table_key.packet_tx_npu_header_encap_encapsulation_type_redirect_encap_type, table_mask.packet_tx_npu_header_encap_encapsulation_type_redirect_encap_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.packet_tx_npu_header_is_inject_up.val, table_key.packet_tx_npu_header_is_inject_up.val, table_mask.packet_tx_npu_header_is_inject_up.val)) {
        return false;
    }
    
    
    return true;
}

bool
npl_fabric_out_color_map_table_functional_traits_t::key_match(const npl_fabric_out_color_map_table_key_t& lookup_key, const npl_fabric_out_color_map_table_key_t& table_key, const npl_fabric_out_color_map_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.out_color, table_key.out_color, table_mask.out_color)) {
        return false;
    }
    
    
    return true;
}

bool
npl_fabric_term_error_checker_static_table_functional_traits_t::key_match(const npl_fabric_term_error_checker_static_table_key_t& lookup_key, const npl_fabric_term_error_checker_static_table_key_t& table_key, const npl_fabric_term_error_checker_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.is_keepalive, table_key.is_keepalive, table_mask.is_keepalive)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.fabric_header_type_ok.val, table_key.fabric_header_type_ok.val, table_mask.fabric_header_type_ok.val)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.fabric_init_cfg_table_hit.val, table_key.fabric_init_cfg_table_hit.val, table_mask.fabric_init_cfg_table_hit.val)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.mismatch_indications.issu_codespace, table_key.mismatch_indications.issu_codespace, table_mask.mismatch_indications.issu_codespace)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.mismatch_indications.first_packet_size, table_key.mismatch_indications.first_packet_size, table_mask.mismatch_indications.first_packet_size)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.mismatch_indications.is_single_fragment, table_key.mismatch_indications.is_single_fragment, table_mask.mismatch_indications.is_single_fragment)) {
        return false;
    }
    
    
    return true;
}

bool
npl_fabric_transmit_error_checker_static_table_functional_traits_t::key_match(const npl_fabric_transmit_error_checker_static_table_key_t& lookup_key, const npl_fabric_transmit_error_checker_static_table_key_t& table_key, const npl_fabric_transmit_error_checker_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.npu_header, table_key.npu_header, table_mask.npu_header)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.fabric_init_cfg_table_hit.val, table_key.fabric_init_cfg_table_hit.val, table_mask.fabric_init_cfg_table_hit.val)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.expected_issu, table_key.expected_issu, table_mask.expected_issu)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.pkt_issu, table_key.pkt_issu, table_mask.pkt_issu)) {
        return false;
    }
    
    
    return true;
}

bool
npl_fi_core_tcam_table_functional_traits_t::key_match(const npl_fi_core_tcam_table_key_t& lookup_key, const npl_fi_core_tcam_table_key_t& table_key, const npl_fi_core_tcam_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.fi_macro, table_key.fi_macro, table_mask.fi_macro)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.header_data, table_key.header_data, table_mask.header_data)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_eth_db1_160_f0_table_functional_traits_t::key_match(const npl_ingress_rtf_eth_db1_160_f0_table_key_t& lookup_key, const npl_ingress_rtf_eth_db1_160_f0_table_key_t& table_key, const npl_ingress_rtf_eth_db1_160_f0_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_eth_db2_160_f0_table_functional_traits_t::key_match(const npl_ingress_rtf_eth_db2_160_f0_table_key_t& lookup_key, const npl_ingress_rtf_eth_db2_160_f0_table_key_t& table_key, const npl_ingress_rtf_eth_db2_160_f0_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv4_db1_160_f0_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv4_db1_160_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db1_160_f0_table_key_t& table_key, const npl_ingress_rtf_ipv4_db1_160_f0_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv4_db1_160_f1_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv4_db1_160_f1_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db1_160_f1_table_key_t& table_key, const npl_ingress_rtf_ipv4_db1_160_f1_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv4_db1_320_f0_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv4_db1_320_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db1_320_f0_table_key_t& table_key, const npl_ingress_rtf_ipv4_db1_320_f0_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv4_db2_160_f0_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv4_db2_160_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db2_160_f0_table_key_t& table_key, const npl_ingress_rtf_ipv4_db2_160_f0_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv4_db2_160_f1_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv4_db2_160_f1_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db2_160_f1_table_key_t& table_key, const npl_ingress_rtf_ipv4_db2_160_f1_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv4_db2_320_f0_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv4_db2_320_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db2_320_f0_table_key_t& table_key, const npl_ingress_rtf_ipv4_db2_320_f0_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv4_db3_160_f0_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv4_db3_160_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db3_160_f0_table_key_t& table_key, const npl_ingress_rtf_ipv4_db3_160_f0_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv4_db3_160_f1_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv4_db3_160_f1_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db3_160_f1_table_key_t& table_key, const npl_ingress_rtf_ipv4_db3_160_f1_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv4_db3_320_f0_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv4_db3_320_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db3_320_f0_table_key_t& table_key, const npl_ingress_rtf_ipv4_db3_320_f0_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv4_db4_160_f0_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv4_db4_160_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db4_160_f0_table_key_t& table_key, const npl_ingress_rtf_ipv4_db4_160_f0_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv4_db4_160_f1_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv4_db4_160_f1_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db4_160_f1_table_key_t& table_key, const npl_ingress_rtf_ipv4_db4_160_f1_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv4_db4_320_f0_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv4_db4_320_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db4_320_f0_table_key_t& table_key, const npl_ingress_rtf_ipv4_db4_320_f0_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv6_db1_160_f0_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv6_db1_160_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db1_160_f0_table_key_t& table_key, const npl_ingress_rtf_ipv6_db1_160_f0_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv6_db1_160_f1_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv6_db1_160_f1_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db1_160_f1_table_key_t& table_key, const npl_ingress_rtf_ipv6_db1_160_f1_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv6_db1_320_f0_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv6_db1_320_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db1_320_f0_table_key_t& table_key, const npl_ingress_rtf_ipv6_db1_320_f0_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv6_db2_160_f0_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv6_db2_160_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db2_160_f0_table_key_t& table_key, const npl_ingress_rtf_ipv6_db2_160_f0_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv6_db2_160_f1_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv6_db2_160_f1_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db2_160_f1_table_key_t& table_key, const npl_ingress_rtf_ipv6_db2_160_f1_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv6_db2_320_f0_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv6_db2_320_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db2_320_f0_table_key_t& table_key, const npl_ingress_rtf_ipv6_db2_320_f0_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv6_db3_160_f0_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv6_db3_160_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db3_160_f0_table_key_t& table_key, const npl_ingress_rtf_ipv6_db3_160_f0_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv6_db3_160_f1_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv6_db3_160_f1_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db3_160_f1_table_key_t& table_key, const npl_ingress_rtf_ipv6_db3_160_f1_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv6_db3_320_f0_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv6_db3_320_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db3_320_f0_table_key_t& table_key, const npl_ingress_rtf_ipv6_db3_320_f0_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv6_db4_160_f0_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv6_db4_160_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db4_160_f0_table_key_t& table_key, const npl_ingress_rtf_ipv6_db4_160_f0_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv6_db4_160_f1_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv6_db4_160_f1_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db4_160_f1_table_key_t& table_key, const npl_ingress_rtf_ipv6_db4_160_f1_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ingress_rtf_ipv6_db4_320_f0_table_functional_traits_t::key_match(const npl_ingress_rtf_ipv6_db4_320_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db4_320_f0_table_key_t& table_key, const npl_ingress_rtf_ipv6_db4_320_f0_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[31].value, &table_key.ud_key.udfs[31].value, &table_mask.ud_key.udfs[31].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[30].value, &table_key.ud_key.udfs[30].value, &table_mask.ud_key.udfs[30].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[29].value, &table_key.ud_key.udfs[29].value, &table_mask.ud_key.udfs[29].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[28].value, &table_key.ud_key.udfs[28].value, &table_mask.ud_key.udfs[28].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[27].value, &table_key.ud_key.udfs[27].value, &table_mask.ud_key.udfs[27].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[26].value, &table_key.ud_key.udfs[26].value, &table_mask.ud_key.udfs[26].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[25].value, &table_key.ud_key.udfs[25].value, &table_mask.ud_key.udfs[25].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[24].value, &table_key.ud_key.udfs[24].value, &table_mask.ud_key.udfs[24].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[23].value, &table_key.ud_key.udfs[23].value, &table_mask.ud_key.udfs[23].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[22].value, &table_key.ud_key.udfs[22].value, &table_mask.ud_key.udfs[22].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[21].value, &table_key.ud_key.udfs[21].value, &table_mask.ud_key.udfs[21].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[20].value, &table_key.ud_key.udfs[20].value, &table_mask.ud_key.udfs[20].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[19].value, &table_key.ud_key.udfs[19].value, &table_mask.ud_key.udfs[19].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[18].value, &table_key.ud_key.udfs[18].value, &table_mask.ud_key.udfs[18].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[17].value, &table_key.ud_key.udfs[17].value, &table_mask.ud_key.udfs[17].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[16].value, &table_key.ud_key.udfs[16].value, &table_mask.ud_key.udfs[16].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[15].value, &table_key.ud_key.udfs[15].value, &table_mask.ud_key.udfs[15].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[14].value, &table_key.ud_key.udfs[14].value, &table_mask.ud_key.udfs[14].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[13].value, &table_key.ud_key.udfs[13].value, &table_mask.ud_key.udfs[13].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[12].value, &table_key.ud_key.udfs[12].value, &table_mask.ud_key.udfs[12].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[11].value, &table_key.ud_key.udfs[11].value, &table_mask.ud_key.udfs[11].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[10].value, &table_key.ud_key.udfs[10].value, &table_mask.ud_key.udfs[10].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[9].value, &table_key.ud_key.udfs[9].value, &table_mask.ud_key.udfs[9].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[8].value, &table_key.ud_key.udfs[8].value, &table_mask.ud_key.udfs[8].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[7].value, &table_key.ud_key.udfs[7].value, &table_mask.ud_key.udfs[7].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[6].value, &table_key.ud_key.udfs[6].value, &table_mask.ud_key.udfs[6].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[5].value, &table_key.ud_key.udfs[5].value, &table_mask.ud_key.udfs[5].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[4].value, &table_key.ud_key.udfs[4].value, &table_mask.ud_key.udfs[4].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[3].value, &table_key.ud_key.udfs[3].value, &table_mask.ud_key.udfs[3].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[2].value, &table_key.ud_key.udfs[2].value, &table_mask.ud_key.udfs[2].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[1].value, &table_key.ud_key.udfs[1].value, &table_mask.ud_key.udfs[1].value, 128)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.ud_key.udfs[0].value, &table_key.ud_key.udfs[0].value, &table_mask.ud_key.udfs[0].value, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_inject_down_select_ene_static_table_functional_traits_t::key_match(const npl_inject_down_select_ene_static_table_key_t& lookup_key, const npl_inject_down_select_ene_static_table_key_t& table_key, const npl_inject_down_select_ene_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.dsp_is_dma, table_key.dsp_is_dma, table_mask.dsp_is_dma)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.fwd_header_type, table_key.fwd_header_type, table_mask.fwd_header_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.inject_down_encap, table_key.inject_down_encap, table_mask.inject_down_encap)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.pkt_size_4lsb, table_key.pkt_size_4lsb, table_mask.pkt_size_4lsb)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ip_ingress_cmp_mcid_static_table_functional_traits_t::key_match(const npl_ip_ingress_cmp_mcid_static_table_key_t& lookup_key, const npl_ip_ingress_cmp_mcid_static_table_key_t& table_key, const npl_ip_ingress_cmp_mcid_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.global_mcid_17_downto_16, table_key.global_mcid_17_downto_16, table_mask.global_mcid_17_downto_16)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ip_ver_mc_static_table_functional_traits_t::key_match(const npl_ip_ver_mc_static_table_key_t& lookup_key, const npl_ip_ver_mc_static_table_key_t& table_key, const npl_ip_ver_mc_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.is_v6, table_key.is_v6, table_mask.is_v6)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.v6_sip_127_120, table_key.v6_sip_127_120, table_mask.v6_sip_127_120)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.v4_sip_31_28, table_key.v4_sip_31_28, table_mask.v4_sip_31_28)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.v4_frag_offset, table_key.v4_frag_offset, table_mask.v4_frag_offset)) {
        return false;
    }
    
    
    return true;
}

bool
npl_ipv4_acl_map_protocol_type_to_protocol_number_table_functional_traits_t::key_match(const npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t& lookup_key, const npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t& table_key, const npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.protocol, table_key.protocol, table_mask.protocol)) {
        return false;
    }
    
    
    return true;
}

void
npl_ipv4_lpm_table_functional_traits_t::mask_key(npl_ipv4_lpm_table_key_t* key, size_t length)
{
    if (length < 32) {
        key->ipv4_ip_address_address &= (((1ULL << length) - 1) << (32 - length));
    }
    
}

bool
npl_ipv4_lpts_table_functional_traits_t::key_match(const npl_ipv4_lpts_table_key_t& lookup_key, const npl_ipv4_lpts_table_key_t& table_key, const npl_ipv4_lpts_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.fragmented, table_key.fragmented, table_mask.fragmented)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.is_mc, table_key.is_mc, table_mask.is_mc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.app_id, table_key.app_id, table_mask.app_id)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.established, table_key.established, table_mask.established)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ttl_255, table_key.ttl_255, table_mask.ttl_255)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.og_codes.src_code.id, table_key.og_codes.src_code.id, table_mask.og_codes.src_code.id)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.og_codes.dest_code.id, table_key.og_codes.dest_code.id, table_mask.og_codes.dest_code.id)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l4_protocol, table_key.l4_protocol, table_mask.l4_protocol)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l4_ports.src_port, table_key.l4_ports.src_port, table_mask.l4_ports.src_port)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l4_ports.dst_port, table_key.l4_ports.dst_port, table_mask.l4_ports.dst_port)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l3_relay_id.id, table_key.l3_relay_id.id, table_mask.l3_relay_id.id)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.v4_frag, table_key.v4_frag, table_mask.v4_frag)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ip_length, table_key.ip_length, table_mask.ip_length)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.sip, table_key.sip, table_mask.sip)) {
        return false;
    }
    
    
    return true;
}

void
npl_ipv4_og_pcl_lpm_table_functional_traits_t::mask_key(npl_ipv4_og_pcl_lpm_table_key_t* key, size_t length)
{
    if (length < 32) {
        key->ip_address &= (((1ULL << length) - 1) << (32 - length));
    }
    
}

bool
npl_ipv6_first_fragment_static_table_functional_traits_t::key_match(const npl_ipv6_first_fragment_static_table_key_t& lookup_key, const npl_ipv6_first_fragment_static_table_key_t& table_key, const npl_ipv6_first_fragment_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.acl_on_outer, table_key.acl_on_outer, table_mask.acl_on_outer)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.acl_changed_destination, table_key.acl_changed_destination, table_mask.acl_changed_destination)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.saved_not_first_fragment, table_key.saved_not_first_fragment, table_mask.saved_not_first_fragment)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.packet_not_first_fragment, table_key.packet_not_first_fragment, table_mask.packet_not_first_fragment)) {
        return false;
    }
    
    
    return true;
}

void
npl_ipv6_lpm_table_functional_traits_t::mask_key(npl_ipv6_lpm_table_key_t* key, size_t length)
{
    npl_lpm_wide_field_apply_mask(key->ipv6_ip_address_address, 128, length);
    
}

bool
npl_ipv6_lpts_table_functional_traits_t::key_match(const npl_ipv6_lpts_table_key_t& lookup_key, const npl_ipv6_lpts_table_key_t& table_key, const npl_ipv6_lpts_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.src_port, table_key.src_port, table_mask.src_port)) {
        return false;
    }
    
    if (!npl_ternary_wide_field_compare(&lookup_key.sip, &table_key.sip, &table_mask.sip, 128)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l3_relay_id.id, table_key.l3_relay_id.id, table_mask.l3_relay_id.id)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.is_mc, table_key.is_mc, table_mask.is_mc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.app_id, table_key.app_id, table_mask.app_id)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.established, table_key.established, table_mask.established)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ttl_255, table_key.ttl_255, table_mask.ttl_255)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.og_codes.src_code.id, table_key.og_codes.src_code.id, table_mask.og_codes.src_code.id)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.og_codes.dest_code.id, table_key.og_codes.dest_code.id, table_mask.og_codes.dest_code.id)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l4_protocol, table_key.l4_protocol, table_mask.l4_protocol)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.dst_port, table_key.dst_port, table_mask.dst_port)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ip_length, table_key.ip_length, table_mask.ip_length)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.pad, table_key.pad, table_mask.pad)) {
        return false;
    }
    
    
    return true;
}

void
npl_ipv6_og_pcl_lpm_table_functional_traits_t::mask_key(npl_ipv6_og_pcl_lpm_table_key_t* key, size_t length)
{
    npl_lpm_wide_field_apply_mask(key->ip_address, 128, length);
    
}

bool
npl_ipv6_sip_compression_table_functional_traits_t::key_match(const npl_ipv6_sip_compression_table_key_t& lookup_key, const npl_ipv6_sip_compression_table_key_t& table_key, const npl_ipv6_sip_compression_table_key_t& table_mask)
{
    if (!npl_ternary_wide_field_compare(&lookup_key.ipv6_sip, &table_key.ipv6_sip, &table_mask.ipv6_sip, 128)) {
        return false;
    }
    
    
    return true;
}

bool
npl_l2_lpts_ctrl_fields_static_table_functional_traits_t::key_match(const npl_l2_lpts_ctrl_fields_static_table_key_t& lookup_key, const npl_l2_lpts_ctrl_fields_static_table_key_t& table_key, const npl_l2_lpts_ctrl_fields_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.mac_lp_type, table_key.mac_lp_type, table_mask.mac_lp_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.mac_terminated, table_key.mac_terminated, table_mask.mac_terminated)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.is_tagged, table_key.is_tagged, table_mask.is_tagged)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.is_svi, table_key.is_svi, table_mask.is_svi)) {
        return false;
    }
    
    
    return true;
}

bool
npl_l2_lpts_ipv4_table_functional_traits_t::key_match(const npl_l2_lpts_ipv4_table_key_t& lookup_key, const npl_l2_lpts_ipv4_table_key_t& table_key, const npl_l2_lpts_ipv4_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.dip, table_key.dip, table_mask.dip)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l4_ports.src_port, table_key.l4_ports.src_port, table_mask.l4_ports.src_port)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l4_ports.dst_port, table_key.l4_ports.dst_port, table_mask.l4_ports.dst_port)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ttl, table_key.ttl, table_mask.ttl)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.protocol, table_key.protocol, table_mask.protocol)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.npp_attributes, table_key.npp_attributes, table_mask.npp_attributes)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.bd_attributes, table_key.bd_attributes, table_mask.bd_attributes)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l2_slp_attributes, table_key.l2_slp_attributes, table_mask.l2_slp_attributes)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.mac_lp_type, table_key.mac_lp_type, table_mask.mac_lp_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.mac_terminated, table_key.mac_terminated, table_mask.mac_terminated)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.is_tagged, table_key.is_tagged, table_mask.is_tagged)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.is_svi, table_key.is_svi, table_mask.is_svi)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ip_not_first_fragment.v6_not_first_fragment, table_key.ip_not_first_fragment.v6_not_first_fragment, table_mask.ip_not_first_fragment.v6_not_first_fragment)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ip_not_first_fragment.v4_not_first_fragment, table_key.ip_not_first_fragment.v4_not_first_fragment, table_mask.ip_not_first_fragment.v4_not_first_fragment)) {
        return false;
    }
    
    
    return true;
}

bool
npl_l2_lpts_ipv6_table_functional_traits_t::key_match(const npl_l2_lpts_ipv6_table_key_t& lookup_key, const npl_l2_lpts_ipv6_table_key_t& table_key, const npl_l2_lpts_ipv6_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.dip_32_msb, table_key.dip_32_msb, table_mask.dip_32_msb)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.dip_32_lsb, table_key.dip_32_lsb, table_mask.dip_32_lsb)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l4_ports.src_port, table_key.l4_ports.src_port, table_mask.l4_ports.src_port)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l4_ports.dst_port, table_key.l4_ports.dst_port, table_mask.l4_ports.dst_port)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.next_header, table_key.next_header, table_mask.next_header)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.hop_limit, table_key.hop_limit, table_mask.hop_limit)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.npp_attributes, table_key.npp_attributes, table_mask.npp_attributes)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.bd_attributes, table_key.bd_attributes, table_mask.bd_attributes)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l2_slp_attributes, table_key.l2_slp_attributes, table_mask.l2_slp_attributes)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.mac_lp_type, table_key.mac_lp_type, table_mask.mac_lp_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.mac_terminated, table_key.mac_terminated, table_mask.mac_terminated)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.is_tagged, table_key.is_tagged, table_mask.is_tagged)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.is_svi, table_key.is_svi, table_mask.is_svi)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ip_not_first_fragment.v6_not_first_fragment, table_key.ip_not_first_fragment.v6_not_first_fragment, table_mask.ip_not_first_fragment.v6_not_first_fragment)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ip_not_first_fragment.v4_not_first_fragment, table_key.ip_not_first_fragment.v4_not_first_fragment, table_mask.ip_not_first_fragment.v4_not_first_fragment)) {
        return false;
    }
    
    
    return true;
}

bool
npl_l2_lpts_mac_table_functional_traits_t::key_match(const npl_l2_lpts_mac_table_key_t& lookup_key, const npl_l2_lpts_mac_table_key_t& table_key, const npl_l2_lpts_mac_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.mac_da.mac_address, table_key.mac_da.mac_address, table_mask.mac_da.mac_address)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ether_type, table_key.ether_type, table_mask.ether_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.npp_attributes, table_key.npp_attributes, table_mask.npp_attributes)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.bd_attributes, table_key.bd_attributes, table_mask.bd_attributes)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l2_slp_attributes, table_key.l2_slp_attributes, table_mask.l2_slp_attributes)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.mac_lp_type, table_key.mac_lp_type, table_mask.mac_lp_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.mac_terminated, table_key.mac_terminated, table_mask.mac_terminated)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.is_tagged, table_key.is_tagged, table_mask.is_tagged)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.is_svi, table_key.is_svi, table_mask.is_svi)) {
        return false;
    }
    
    
    return true;
}

bool
npl_l2_lpts_next_macro_static_table_functional_traits_t::key_match(const npl_l2_lpts_next_macro_static_table_key_t& lookup_key, const npl_l2_lpts_next_macro_static_table_key_t& table_key, const npl_l2_lpts_next_macro_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.type, table_key.type, table_mask.type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ctrl_fields.l2_lpts, table_key.ctrl_fields.l2_lpts, table_mask.ctrl_fields.l2_lpts)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.v4_mc, table_key.v4_mc, table_mask.v4_mc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.v6_mc, table_key.v6_mc, table_mask.v6_mc)) {
        return false;
    }
    
    
    return true;
}

bool
npl_l2_lpts_protocol_table_functional_traits_t::key_match(const npl_l2_lpts_protocol_table_key_t& lookup_key, const npl_l2_lpts_protocol_table_key_t& table_key, const npl_l2_lpts_protocol_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.next_protocol_type, table_key.next_protocol_type, table_mask.next_protocol_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.next_header_1_type, table_key.next_header_1_type, table_mask.next_header_1_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.dst_udp_port, table_key.dst_udp_port, table_mask.dst_udp_port)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.mac_da_use_l2_lpts, table_key.mac_da_use_l2_lpts, table_mask.mac_da_use_l2_lpts)) {
        return false;
    }
    
    
    return true;
}

bool
npl_l2_termination_next_macro_static_table_functional_traits_t::key_match(const npl_l2_termination_next_macro_static_table_key_t& lookup_key, const npl_l2_termination_next_macro_static_table_key_t& table_key, const npl_l2_termination_next_macro_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.next_hdr_type, table_key.next_hdr_type, table_mask.next_hdr_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ipv4_ipv6_eth_init_rtf_stage.ipv4_ipv6_init_rtf_stage.ipv4_init_rtf_stage, table_key.ipv4_ipv6_eth_init_rtf_stage.ipv4_ipv6_init_rtf_stage.ipv4_init_rtf_stage, table_mask.ipv4_ipv6_eth_init_rtf_stage.ipv4_ipv6_init_rtf_stage.ipv4_init_rtf_stage)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ipv4_ipv6_eth_init_rtf_stage.ipv4_ipv6_init_rtf_stage.ipv6_init_rtf_stage, table_key.ipv4_ipv6_eth_init_rtf_stage.ipv4_ipv6_init_rtf_stage.ipv6_init_rtf_stage, table_mask.ipv4_ipv6_eth_init_rtf_stage.ipv4_ipv6_init_rtf_stage.ipv6_init_rtf_stage)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ipv4_ipv6_eth_init_rtf_stage.eth_init_rtf_stage, table_key.ipv4_ipv6_eth_init_rtf_stage.eth_init_rtf_stage, table_mask.ipv4_ipv6_eth_init_rtf_stage.eth_init_rtf_stage)) {
        return false;
    }
    
    
    return true;
}

bool
npl_l3_dlp_p_counter_offset_table_functional_traits_t::key_match(const npl_l3_dlp_p_counter_offset_table_key_t& lookup_key, const npl_l3_dlp_p_counter_offset_table_key_t& table_key, const npl_l3_dlp_p_counter_offset_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.is_mc, table_key.is_mc, table_mask.is_mc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ip_acl_macro_control, table_key.ip_acl_macro_control, table_mask.ip_acl_macro_control)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l3_encap_type, table_key.l3_encap_type, table_mask.l3_encap_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.fwd_header_type, table_key.fwd_header_type, table_mask.fwd_header_type)) {
        return false;
    }
    
    
    return true;
}

bool
npl_l3_termination_classify_ip_tunnels_table_functional_traits_t::key_match(const npl_l3_termination_classify_ip_tunnels_table_key_t& lookup_key, const npl_l3_termination_classify_ip_tunnels_table_key_t& table_key, const npl_l3_termination_classify_ip_tunnels_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.l3_protocol_type, table_key.l3_protocol_type, table_mask.l3_protocol_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l4_protocol_type, table_key.l4_protocol_type, table_mask.l4_protocol_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.udp_dst_port_or_gre_proto, table_key.udp_dst_port_or_gre_proto, table_mask.udp_dst_port_or_gre_proto)) {
        return false;
    }
    
    
    return true;
}

bool
npl_l3_termination_next_macro_static_table_functional_traits_t::key_match(const npl_l3_termination_next_macro_static_table_key_t& lookup_key, const npl_l3_termination_next_macro_static_table_key_t& table_key, const npl_l3_termination_next_macro_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.hdr_type, table_key.hdr_type, table_mask.hdr_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ipv4_ipv6_init_rtf_stage.ipv4_init_rtf_stage, table_key.ipv4_ipv6_init_rtf_stage.ipv4_init_rtf_stage, table_mask.ipv4_ipv6_init_rtf_stage.ipv4_init_rtf_stage)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ipv4_ipv6_init_rtf_stage.ipv6_init_rtf_stage, table_key.ipv4_ipv6_init_rtf_stage.ipv6_init_rtf_stage, table_mask.ipv4_ipv6_init_rtf_stage.ipv6_init_rtf_stage)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.dont_inc_pl, table_key.dont_inc_pl, table_mask.dont_inc_pl)) {
        return false;
    }
    
    
    return true;
}

bool
npl_l3_tunnel_termination_next_macro_static_table_functional_traits_t::key_match(const npl_l3_tunnel_termination_next_macro_static_table_key_t& lookup_key, const npl_l3_tunnel_termination_next_macro_static_table_key_t& table_key, const npl_l3_tunnel_termination_next_macro_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.next_hdr_type, table_key.next_hdr_type, table_mask.next_hdr_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.term_attr_ipv4_ipv6_init_rtf_stage.ipv4_init_rtf_stage, table_key.term_attr_ipv4_ipv6_init_rtf_stage.ipv4_init_rtf_stage, table_mask.term_attr_ipv4_ipv6_init_rtf_stage.ipv4_init_rtf_stage)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.term_attr_ipv4_ipv6_init_rtf_stage.ipv6_init_rtf_stage, table_key.term_attr_ipv4_ipv6_init_rtf_stage.ipv6_init_rtf_stage, table_mask.term_attr_ipv4_ipv6_init_rtf_stage.ipv6_init_rtf_stage)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.pd_ipv4_init_rtf_stage, table_key.pd_ipv4_init_rtf_stage, table_mask.pd_ipv4_init_rtf_stage)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.lp_set, table_key.lp_set, table_mask.lp_set)) {
        return false;
    }
    
    
    return true;
}

bool
npl_light_fi_nw_0_table_functional_traits_t::key_match(const npl_light_fi_nw_0_table_key_t& lookup_key, const npl_light_fi_nw_0_table_key_t& table_key, const npl_light_fi_nw_0_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.current_header_type, table_key.current_header_type, table_mask.current_header_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.next_protocol_field, table_key.next_protocol_field, table_mask.next_protocol_field)) {
        return false;
    }
    
    
    return true;
}

bool
npl_light_fi_nw_1_table_functional_traits_t::key_match(const npl_light_fi_nw_1_table_key_t& lookup_key, const npl_light_fi_nw_1_table_key_t& table_key, const npl_light_fi_nw_1_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.current_header_type, table_key.current_header_type, table_mask.current_header_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.next_protocol_field, table_key.next_protocol_field, table_mask.next_protocol_field)) {
        return false;
    }
    
    
    return true;
}

bool
npl_light_fi_nw_2_table_functional_traits_t::key_match(const npl_light_fi_nw_2_table_key_t& lookup_key, const npl_light_fi_nw_2_table_key_t& table_key, const npl_light_fi_nw_2_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.current_header_type, table_key.current_header_type, table_mask.current_header_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.next_protocol_field, table_key.next_protocol_field, table_mask.next_protocol_field)) {
        return false;
    }
    
    
    return true;
}

bool
npl_light_fi_nw_3_table_functional_traits_t::key_match(const npl_light_fi_nw_3_table_key_t& lookup_key, const npl_light_fi_nw_3_table_key_t& table_key, const npl_light_fi_nw_3_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.current_header_type, table_key.current_header_type, table_mask.current_header_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.next_protocol_field, table_key.next_protocol_field, table_mask.next_protocol_field)) {
        return false;
    }
    
    
    return true;
}

bool
npl_lpts_og_application_table_functional_traits_t::key_match(const npl_lpts_og_application_table_key_t& lookup_key, const npl_lpts_og_application_table_key_t& table_key, const npl_lpts_og_application_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.ip_version, table_key.ip_version, table_mask.ip_version)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ipv4_l4_protocol, table_key.ipv4_l4_protocol, table_mask.ipv4_l4_protocol)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ipv6_l4_protocol, table_key.ipv6_l4_protocol, table_mask.ipv6_l4_protocol)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l4_ports.src_port, table_key.l4_ports.src_port, table_mask.l4_ports.src_port)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l4_ports.dst_port, table_key.l4_ports.dst_port, table_mask.l4_ports.dst_port)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.fragmented, table_key.fragmented, table_mask.fragmented)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l3_relay_id.id, table_key.l3_relay_id.id, table_mask.l3_relay_id.id)) {
        return false;
    }
    
    
    return true;
}

bool
npl_mac_da_table_functional_traits_t::key_match(const npl_mac_da_table_key_t& lookup_key, const npl_mac_da_table_key_t& table_key, const npl_mac_da_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.packet_ethernet_header_da.mac_address, table_key.packet_ethernet_header_da.mac_address, table_mask.packet_ethernet_header_da.mac_address)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.next_protocol_type, table_key.next_protocol_type, table_mask.next_protocol_type)) {
        return false;
    }
    
    
    return true;
}

bool
npl_mac_ethernet_rate_limit_type_static_table_functional_traits_t::key_match(const npl_mac_ethernet_rate_limit_type_static_table_key_t& lookup_key, const npl_mac_ethernet_rate_limit_type_static_table_key_t& table_key, const npl_mac_ethernet_rate_limit_type_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.is_bc, table_key.is_bc, table_mask.is_bc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.is_mc, table_key.is_mc, table_mask.is_mc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.mac_forwarding_hit, table_key.mac_forwarding_hit, table_mask.mac_forwarding_hit)) {
        return false;
    }
    
    
    return true;
}

bool
npl_mac_mc_tcam_termination_attributes_table_functional_traits_t::key_match(const npl_mac_mc_tcam_termination_attributes_table_key_t& lookup_key, const npl_mac_mc_tcam_termination_attributes_table_key_t& table_key, const npl_mac_mc_tcam_termination_attributes_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.l2_relay_attributes_id, table_key.l2_relay_attributes_id, table_mask.l2_relay_attributes_id)) {
        return false;
    }
    
    
    return true;
}

bool
npl_mac_termination_next_macro_static_table_functional_traits_t::key_match(const npl_mac_termination_next_macro_static_table_key_t& lookup_key, const npl_mac_termination_next_macro_static_table_key_t& table_key, const npl_mac_termination_next_macro_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.next_proto_type, table_key.next_proto_type, table_mask.next_proto_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l2_lp_type, table_key.l2_lp_type, table_mask.l2_lp_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ipv4_ipv6_init_rtf_stage.ipv4_init_rtf_stage, table_key.ipv4_ipv6_init_rtf_stage.ipv4_init_rtf_stage, table_mask.ipv4_ipv6_init_rtf_stage.ipv4_init_rtf_stage)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ipv4_ipv6_init_rtf_stage.ipv6_init_rtf_stage, table_key.ipv4_ipv6_init_rtf_stage.ipv6_init_rtf_stage, table_mask.ipv4_ipv6_init_rtf_stage.ipv6_init_rtf_stage)) {
        return false;
    }
    
    
    return true;
}

bool
npl_mac_termination_tcam_table_functional_traits_t::key_match(const npl_mac_termination_tcam_table_key_t& lookup_key, const npl_mac_termination_tcam_table_key_t& table_key, const npl_mac_termination_tcam_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.service_relay_attributes_table_key.id, table_key.service_relay_attributes_table_key.id, table_mask.service_relay_attributes_table_key.id)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.ethernet_header_da_18_0_, table_key.ethernet_header_da_18_0_, table_mask.ethernet_header_da_18_0_)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.da_prefix, table_key.da_prefix, table_mask.da_prefix)) {
        return false;
    }
    
    
    return true;
}

bool
npl_map_inject_ccm_macro_static_table_functional_traits_t::key_match(const npl_map_inject_ccm_macro_static_table_key_t& lookup_key, const npl_map_inject_ccm_macro_static_table_key_t& table_key, const npl_map_inject_ccm_macro_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.outer_tpid_ptr, table_key.outer_tpid_ptr, table_mask.outer_tpid_ptr)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.inner_tpid_ptr, table_key.inner_tpid_ptr, table_mask.inner_tpid_ptr)) {
        return false;
    }
    
    
    return true;
}

bool
npl_map_tx_punt_next_macro_static_table_functional_traits_t::key_match(const npl_map_tx_punt_next_macro_static_table_key_t& lookup_key, const npl_map_tx_punt_next_macro_static_table_key_t& table_key, const npl_map_tx_punt_next_macro_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.cud_type, table_key.cud_type, table_mask.cud_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.punt_encap_type, table_key.punt_encap_type, table_mask.punt_encap_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.punt_format, table_key.punt_format, table_mask.punt_format)) {
        return false;
    }
    
    
    return true;
}

bool
npl_map_tx_punt_rcy_next_macro_static_table_functional_traits_t::key_match(const npl_map_tx_punt_rcy_next_macro_static_table_key_t& lookup_key, const npl_map_tx_punt_rcy_next_macro_static_table_key_t& table_key, const npl_map_tx_punt_rcy_next_macro_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.inject_only, table_key.inject_only, table_mask.inject_only)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.eth_stage, table_key.eth_stage, table_mask.eth_stage)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.redirect_code, table_key.redirect_code, table_mask.redirect_code)) {
        return false;
    }
    
    
    return true;
}

bool
npl_meg_id_format_table_functional_traits_t::key_match(const npl_meg_id_format_table_key_t& lookup_key, const npl_meg_id_format_table_key_t& table_key, const npl_meg_id_format_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.eth_oam_mp_table_read_payload_meg_id_format, table_key.eth_oam_mp_table_read_payload_meg_id_format, table_mask.eth_oam_mp_table_read_payload_meg_id_format)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.eth_oam_ccm_meg_id_format, table_key.eth_oam_ccm_meg_id_format, table_mask.eth_oam_ccm_meg_id_format)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.meg_id_length, table_key.meg_id_length, table_mask.meg_id_length)) {
        return false;
    }
    
    
    return true;
}

bool
npl_mldp_protection_enabled_static_table_functional_traits_t::key_match(const npl_mldp_protection_enabled_static_table_key_t& lookup_key, const npl_mldp_protection_enabled_static_table_key_t& table_key, const npl_mldp_protection_enabled_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.is_mc, table_key.is_mc, table_mask.is_mc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l3_encap, table_key.l3_encap, table_mask.l3_encap)) {
        return false;
    }
    
    
    return true;
}

bool
npl_mpls_resolve_service_labels_static_table_functional_traits_t::key_match(const npl_mpls_resolve_service_labels_static_table_key_t& lookup_key, const npl_mpls_resolve_service_labels_static_table_key_t& table_key, const npl_mpls_resolve_service_labels_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.lsp_flags.service_flags.push_entropy_label, table_key.lsp_flags.service_flags.push_entropy_label, table_mask.lsp_flags.service_flags.push_entropy_label)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.lsp_flags.service_flags.add_ipv6_explicit_null, table_key.lsp_flags.service_flags.add_ipv6_explicit_null, table_mask.lsp_flags.service_flags.add_ipv6_explicit_null)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.lsp_flags.num_outer_transport_labels.total_num_labels, table_key.lsp_flags.num_outer_transport_labels.total_num_labels, table_mask.lsp_flags.num_outer_transport_labels.total_num_labels)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.lsp_flags.num_outer_transport_labels.num_labels_is_3, table_key.lsp_flags.num_outer_transport_labels.num_labels_is_3, table_mask.lsp_flags.num_outer_transport_labels.num_labels_is_3)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.vpn_enabled, table_key.vpn_enabled, table_mask.vpn_enabled)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.fwd_hdr_type, table_key.fwd_hdr_type, table_mask.fwd_hdr_type)) {
        return false;
    }
    
    
    return true;
}

bool
npl_mpls_vpn_enabled_static_table_functional_traits_t::key_match(const npl_mpls_vpn_enabled_static_table_key_t& lookup_key, const npl_mpls_vpn_enabled_static_table_key_t& table_key, const npl_mpls_vpn_enabled_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.is_vpn, table_key.is_vpn, table_mask.is_vpn)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.fwd_header_type, table_key.fwd_header_type, table_mask.fwd_header_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l3_relay_id.id, table_key.l3_relay_id.id, table_mask.l3_relay_id.id)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.is_prefix_id, table_key.is_prefix_id, table_mask.is_prefix_id)) {
        return false;
    }
    
    
    return true;
}

bool
npl_my_ipv4_table_functional_traits_t::key_match(const npl_my_ipv4_table_key_t& lookup_key, const npl_my_ipv4_table_key_t& table_key, const npl_my_ipv4_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.l4_protocol_type_3_2, table_key.l4_protocol_type_3_2, table_mask.l4_protocol_type_3_2)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l3_relay_id.id, table_key.l3_relay_id.id, table_mask.l3_relay_id.id)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.dip, table_key.dip, table_mask.dip)) {
        return false;
    }
    
    
    return true;
}

bool
npl_null_rtf_next_macro_static_table_functional_traits_t::key_match(const npl_null_rtf_next_macro_static_table_key_t& lookup_key, const npl_null_rtf_next_macro_static_table_key_t& table_key, const npl_null_rtf_next_macro_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.next_prot_type, table_key.next_prot_type, table_mask.next_prot_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.pd_tunnel_ipv4_ipv6_init_rtf_stage.ipv4_init_rtf_stage, table_key.pd_tunnel_ipv4_ipv6_init_rtf_stage.ipv4_init_rtf_stage, table_mask.pd_tunnel_ipv4_ipv6_init_rtf_stage.ipv4_init_rtf_stage)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.pd_tunnel_ipv4_ipv6_init_rtf_stage.ipv6_init_rtf_stage, table_key.pd_tunnel_ipv4_ipv6_init_rtf_stage.ipv6_init_rtf_stage, table_mask.pd_tunnel_ipv4_ipv6_init_rtf_stage.ipv6_init_rtf_stage)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.acl_outer, table_key.acl_outer, table_mask.acl_outer)) {
        return false;
    }
    
    
    return true;
}

bool
npl_obm_next_macro_static_table_functional_traits_t::key_match(const npl_obm_next_macro_static_table_key_t& lookup_key, const npl_obm_next_macro_static_table_key_t& table_key, const npl_obm_next_macro_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.rcy_data_suffix, table_key.rcy_data_suffix, table_mask.rcy_data_suffix)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.has_punt_header, table_key.has_punt_header, table_mask.has_punt_header)) {
        return false;
    }
    
    
    return true;
}

bool
npl_og_next_macro_static_table_functional_traits_t::key_match(const npl_og_next_macro_static_table_key_t& lookup_key, const npl_og_next_macro_static_table_key_t& table_key, const npl_og_next_macro_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.ip_version, table_key.ip_version, table_mask.ip_version)) {
        return false;
    }
    
    
    return true;
}

bool
npl_pad_mtu_inj_check_static_table_functional_traits_t::key_match(const npl_pad_mtu_inj_check_static_table_key_t& lookup_key, const npl_pad_mtu_inj_check_static_table_key_t& table_key, const npl_pad_mtu_inj_check_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.tx_npu_header_is_inject_up.val, table_key.tx_npu_header_is_inject_up.val, table_mask.tx_npu_header_is_inject_up.val)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l3_tx_local_vars_fwd_pkt_size, table_key.l3_tx_local_vars_fwd_pkt_size, table_mask.l3_tx_local_vars_fwd_pkt_size)) {
        return false;
    }
    
    
    return true;
}

bool
npl_pfc_filter_wd_table_functional_traits_t::key_match(const npl_pfc_filter_wd_table_key_t& lookup_key, const npl_pfc_filter_wd_table_key_t& table_key, const npl_pfc_filter_wd_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.tc, table_key.tc, table_mask.tc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.dsp, table_key.dsp, table_mask.dsp)) {
        return false;
    }
    
    
    return true;
}

bool
npl_pfc_offset_from_vector_static_table_functional_traits_t::key_match(const npl_pfc_offset_from_vector_static_table_key_t& lookup_key, const npl_pfc_offset_from_vector_static_table_key_t& table_key, const npl_pfc_offset_from_vector_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.vector, table_key.vector, table_mask.vector)) {
        return false;
    }
    
    
    return true;
}

bool
npl_pfc_ssp_slice_map_table_functional_traits_t::key_match(const npl_pfc_ssp_slice_map_table_key_t& lookup_key, const npl_pfc_ssp_slice_map_table_key_t& table_key, const npl_pfc_ssp_slice_map_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.ssp, table_key.ssp, table_mask.ssp)) {
        return false;
    }
    
    
    return true;
}

bool
npl_pfc_tc_latency_table_functional_traits_t::key_match(const npl_pfc_tc_latency_table_key_t& lookup_key, const npl_pfc_tc_latency_table_key_t& table_key, const npl_pfc_tc_latency_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.tc, table_key.tc, table_mask.tc)) {
        return false;
    }
    
    
    return true;
}

bool
npl_pfc_tc_wrap_latency_table_functional_traits_t::key_match(const npl_pfc_tc_wrap_latency_table_key_t& lookup_key, const npl_pfc_tc_wrap_latency_table_key_t& table_key, const npl_pfc_tc_wrap_latency_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.tc, table_key.tc, table_mask.tc)) {
        return false;
    }
    
    
    return true;
}

bool
npl_punt_ethertype_static_table_functional_traits_t::key_match(const npl_punt_ethertype_static_table_key_t& lookup_key, const npl_punt_ethertype_static_table_key_t& table_key, const npl_punt_ethertype_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.punt_nw_encap_type, table_key.punt_nw_encap_type, table_mask.punt_nw_encap_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.punt_format, table_key.punt_format, table_mask.punt_format)) {
        return false;
    }
    
    
    return true;
}

bool
npl_redirect_table_functional_traits_t::key_match(const npl_redirect_table_key_t& lookup_key, const npl_redirect_table_key_t& table_key, const npl_redirect_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.acl_drop, table_key.traps.ethernet.acl_drop, table_mask.traps.ethernet.acl_drop)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.acl_force_punt, table_key.traps.ethernet.acl_force_punt, table_mask.traps.ethernet.acl_force_punt)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.vlan_membership, table_key.traps.ethernet.vlan_membership, table_mask.traps.ethernet.vlan_membership)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.acceptable_format, table_key.traps.ethernet.acceptable_format, table_mask.traps.ethernet.acceptable_format)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.no_service_mapping, table_key.traps.ethernet.no_service_mapping, table_mask.traps.ethernet.no_service_mapping)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.no_termination_on_l3_port, table_key.traps.ethernet.no_termination_on_l3_port, table_mask.traps.ethernet.no_termination_on_l3_port)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.no_sip_mapping, table_key.traps.ethernet.no_sip_mapping, table_mask.traps.ethernet.no_sip_mapping)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.no_vni_mapping, table_key.traps.ethernet.no_vni_mapping, table_mask.traps.ethernet.no_vni_mapping)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.no_vsid_mapping, table_key.traps.ethernet.no_vsid_mapping, table_mask.traps.ethernet.no_vsid_mapping)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.arp, table_key.traps.ethernet.arp, table_mask.traps.ethernet.arp)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.sa_da_error, table_key.traps.ethernet.sa_da_error, table_mask.traps.ethernet.sa_da_error)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.sa_error, table_key.traps.ethernet.sa_error, table_mask.traps.ethernet.sa_error)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.da_error, table_key.traps.ethernet.da_error, table_mask.traps.ethernet.da_error)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.sa_multicast, table_key.traps.ethernet.sa_multicast, table_mask.traps.ethernet.sa_multicast)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.dhcpv4_server, table_key.traps.ethernet.dhcpv4_server, table_mask.traps.ethernet.dhcpv4_server)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.dhcpv4_client, table_key.traps.ethernet.dhcpv4_client, table_mask.traps.ethernet.dhcpv4_client)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.dhcpv6_server, table_key.traps.ethernet.dhcpv6_server, table_mask.traps.ethernet.dhcpv6_server)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.dhcpv6_client, table_key.traps.ethernet.dhcpv6_client, table_mask.traps.ethernet.dhcpv6_client)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.ingress_stp_block, table_key.traps.ethernet.ingress_stp_block, table_mask.traps.ethernet.ingress_stp_block)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.ptp_over_eth, table_key.traps.ethernet.ptp_over_eth, table_mask.traps.ethernet.ptp_over_eth)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.isis_over_l2, table_key.traps.ethernet.isis_over_l2, table_mask.traps.ethernet.isis_over_l2)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.l2cp0, table_key.traps.ethernet.l2cp0, table_mask.traps.ethernet.l2cp0)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.l2cp1, table_key.traps.ethernet.l2cp1, table_mask.traps.ethernet.l2cp1)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.l2cp2, table_key.traps.ethernet.l2cp2, table_mask.traps.ethernet.l2cp2)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.l2cp3, table_key.traps.ethernet.l2cp3, table_mask.traps.ethernet.l2cp3)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.l2cp4, table_key.traps.ethernet.l2cp4, table_mask.traps.ethernet.l2cp4)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.l2cp5, table_key.traps.ethernet.l2cp5, table_mask.traps.ethernet.l2cp5)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.l2cp6, table_key.traps.ethernet.l2cp6, table_mask.traps.ethernet.l2cp6)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.l2cp7, table_key.traps.ethernet.l2cp7, table_mask.traps.ethernet.l2cp7)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.lacp, table_key.traps.ethernet.lacp, table_mask.traps.ethernet.lacp)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.cisco_protocols, table_key.traps.ethernet.cisco_protocols, table_mask.traps.ethernet.cisco_protocols)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.macsec, table_key.traps.ethernet.macsec, table_mask.traps.ethernet.macsec)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.unknown_l3, table_key.traps.ethernet.unknown_l3, table_mask.traps.ethernet.unknown_l3)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.test_oam_ac_mep, table_key.traps.ethernet.test_oam_ac_mep, table_mask.traps.ethernet.test_oam_ac_mep)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.test_oam_ac_mip, table_key.traps.ethernet.test_oam_ac_mip, table_mask.traps.ethernet.test_oam_ac_mip)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.test_oam_cfm_link_mdl0, table_key.traps.ethernet.test_oam_cfm_link_mdl0, table_mask.traps.ethernet.test_oam_cfm_link_mdl0)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.system_mymac, table_key.traps.ethernet.system_mymac, table_mask.traps.ethernet.system_mymac)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.unknown_bc, table_key.traps.ethernet.unknown_bc, table_mask.traps.ethernet.unknown_bc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.unknown_mc, table_key.traps.ethernet.unknown_mc, table_mask.traps.ethernet.unknown_mc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.unknown_uc, table_key.traps.ethernet.unknown_uc, table_mask.traps.ethernet.unknown_uc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.learn_punt, table_key.traps.ethernet.learn_punt, table_mask.traps.ethernet.learn_punt)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.bcast_pkt, table_key.traps.ethernet.bcast_pkt, table_mask.traps.ethernet.bcast_pkt)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.pfc_sample, table_key.traps.ethernet.pfc_sample, table_mask.traps.ethernet.pfc_sample)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.hop_by_hop, table_key.traps.ethernet.hop_by_hop, table_mask.traps.ethernet.hop_by_hop)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.l2_dlp_not_found, table_key.traps.ethernet.l2_dlp_not_found, table_mask.traps.ethernet.l2_dlp_not_found)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.same_interface, table_key.traps.ethernet.same_interface, table_mask.traps.ethernet.same_interface)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.dspa_mc_trim, table_key.traps.ethernet.dspa_mc_trim, table_mask.traps.ethernet.dspa_mc_trim)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.egress_stp_block, table_key.traps.ethernet.egress_stp_block, table_mask.traps.ethernet.egress_stp_block)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.split_horizon, table_key.traps.ethernet.split_horizon, table_mask.traps.ethernet.split_horizon)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.disabled, table_key.traps.ethernet.disabled, table_mask.traps.ethernet.disabled)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.incompatible_eve_cmd, table_key.traps.ethernet.incompatible_eve_cmd, table_mask.traps.ethernet.incompatible_eve_cmd)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.padding_residue_in_second_line, table_key.traps.ethernet.padding_residue_in_second_line, table_mask.traps.ethernet.padding_residue_in_second_line)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.pfc_direct_sample, table_key.traps.ethernet.pfc_direct_sample, table_mask.traps.ethernet.pfc_direct_sample)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.svi_egress_dhcp, table_key.traps.ethernet.svi_egress_dhcp, table_mask.traps.ethernet.svi_egress_dhcp)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.no_pwe_l3_dest, table_key.traps.ethernet.no_pwe_l3_dest, table_mask.traps.ethernet.no_pwe_l3_dest)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv4.mc_forwarding_disabled, table_key.traps.ipv4.mc_forwarding_disabled, table_mask.traps.ipv4.mc_forwarding_disabled)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv4.uc_forwarding_disabled, table_key.traps.ipv4.uc_forwarding_disabled, table_mask.traps.ipv4.uc_forwarding_disabled)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv4.checksum, table_key.traps.ipv4.checksum, table_mask.traps.ipv4.checksum)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv4.header_error, table_key.traps.ipv4.header_error, table_mask.traps.ipv4.header_error)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv4.unknown_protocol, table_key.traps.ipv4.unknown_protocol, table_mask.traps.ipv4.unknown_protocol)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv4.options_exist, table_key.traps.ipv4.options_exist, table_mask.traps.ipv4.options_exist)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv4.non_comp_mc, table_key.traps.ipv4.non_comp_mc, table_mask.traps.ipv4.non_comp_mc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv6.mc_forwarding_disabled, table_key.traps.ipv6.mc_forwarding_disabled, table_mask.traps.ipv6.mc_forwarding_disabled)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv6.uc_forwarding_disabled, table_key.traps.ipv6.uc_forwarding_disabled, table_mask.traps.ipv6.uc_forwarding_disabled)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv6.hop_by_hop, table_key.traps.ipv6.hop_by_hop, table_mask.traps.ipv6.hop_by_hop)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv6.header_error, table_key.traps.ipv6.header_error, table_mask.traps.ipv6.header_error)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv6.illegal_sip, table_key.traps.ipv6.illegal_sip, table_mask.traps.ipv6.illegal_sip)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv6.illegal_dip, table_key.traps.ipv6.illegal_dip, table_mask.traps.ipv6.illegal_dip)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv6.zero_payload, table_key.traps.ipv6.zero_payload, table_mask.traps.ipv6.zero_payload)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv6.next_header_check, table_key.traps.ipv6.next_header_check, table_mask.traps.ipv6.next_header_check)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv6.non_comp_mc, table_key.traps.ipv6.non_comp_mc, table_mask.traps.ipv6.non_comp_mc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.unknown_protocol_after_bos, table_key.traps.mpls.unknown_protocol_after_bos, table_mask.traps.mpls.unknown_protocol_after_bos)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.ttl_is_zero, table_key.traps.mpls.ttl_is_zero, table_mask.traps.mpls.ttl_is_zero)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.bfd_over_pwe_ttl, table_key.traps.mpls.bfd_over_pwe_ttl, table_mask.traps.mpls.bfd_over_pwe_ttl)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.bfd_over_pwe_raw, table_key.traps.mpls.bfd_over_pwe_raw, table_mask.traps.mpls.bfd_over_pwe_raw)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.bfd_over_pwe_ipv4, table_key.traps.mpls.bfd_over_pwe_ipv4, table_mask.traps.mpls.bfd_over_pwe_ipv4)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.bfd_over_pwe_ipv6, table_key.traps.mpls.bfd_over_pwe_ipv6, table_mask.traps.mpls.bfd_over_pwe_ipv6)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.unknown_bfd_g_ach_channel_type, table_key.traps.mpls.unknown_bfd_g_ach_channel_type, table_mask.traps.mpls.unknown_bfd_g_ach_channel_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.bfd_over_pwe_ra, table_key.traps.mpls.bfd_over_pwe_ra, table_mask.traps.mpls.bfd_over_pwe_ra)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.mpls_tp_over_pwe, table_key.traps.mpls.mpls_tp_over_pwe, table_mask.traps.mpls.mpls_tp_over_pwe)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.unknown_g_ach, table_key.traps.mpls.unknown_g_ach, table_mask.traps.mpls.unknown_g_ach)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.mpls_tp_over_lsp, table_key.traps.mpls.mpls_tp_over_lsp, table_mask.traps.mpls.mpls_tp_over_lsp)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.oam_alert_label, table_key.traps.mpls.oam_alert_label, table_mask.traps.mpls.oam_alert_label)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.extension_label, table_key.traps.mpls.extension_label, table_mask.traps.mpls.extension_label)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.router_alert_label, table_key.traps.mpls.router_alert_label, table_mask.traps.mpls.router_alert_label)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.unexpected_reserved_label, table_key.traps.mpls.unexpected_reserved_label, table_mask.traps.mpls.unexpected_reserved_label)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.forwarding_disabled, table_key.traps.mpls.forwarding_disabled, table_mask.traps.mpls.forwarding_disabled)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.ilm_miss, table_key.traps.mpls.ilm_miss, table_mask.traps.mpls.ilm_miss)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.ipv4_over_ipv6_explicit_null, table_key.traps.mpls.ipv4_over_ipv6_explicit_null, table_mask.traps.mpls.ipv4_over_ipv6_explicit_null)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.invalid_ttl, table_key.traps.mpls.invalid_ttl, table_mask.traps.mpls.invalid_ttl)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.te_midpopint_ldp_labels_miss, table_key.traps.mpls.te_midpopint_ldp_labels_miss, table_mask.traps.mpls.te_midpopint_ldp_labels_miss)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.asbr_label_miss, table_key.traps.mpls.asbr_label_miss, table_mask.traps.mpls.asbr_label_miss)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.ilm_vrf_label_miss, table_key.traps.mpls.ilm_vrf_label_miss, table_mask.traps.mpls.ilm_vrf_label_miss)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.pwe_pwach, table_key.traps.mpls.pwe_pwach, table_mask.traps.mpls.pwe_pwach)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.vpn_ttl_one, table_key.traps.mpls.vpn_ttl_one, table_mask.traps.mpls.vpn_ttl_one)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.missing_fwd_label_after_pop, table_key.traps.mpls.missing_fwd_label_after_pop, table_mask.traps.mpls.missing_fwd_label_after_pop)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_unicast_rpf, table_key.traps.l3.ip_unicast_rpf, table_mask.traps.l3.ip_unicast_rpf)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_multicast_rpf, table_key.traps.l3.ip_multicast_rpf, table_mask.traps.l3.ip_multicast_rpf)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_mc_drop, table_key.traps.l3.ip_mc_drop, table_mask.traps.l3.ip_mc_drop)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_mc_punt_dc_pass, table_key.traps.l3.ip_mc_punt_dc_pass, table_mask.traps.l3.ip_mc_punt_dc_pass)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_mc_snoop_dc_pass, table_key.traps.l3.ip_mc_snoop_dc_pass, table_mask.traps.l3.ip_mc_snoop_dc_pass)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_mc_snoop_rpf_fail, table_key.traps.l3.ip_mc_snoop_rpf_fail, table_mask.traps.l3.ip_mc_snoop_rpf_fail)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_mc_punt_rpf_fail, table_key.traps.l3.ip_mc_punt_rpf_fail, table_mask.traps.l3.ip_mc_punt_rpf_fail)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_mc_snoop_lookup_miss, table_key.traps.l3.ip_mc_snoop_lookup_miss, table_mask.traps.l3.ip_mc_snoop_lookup_miss)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_multicast_not_found, table_key.traps.l3.ip_multicast_not_found, table_mask.traps.l3.ip_multicast_not_found)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_mc_s_g_punt_member, table_key.traps.l3.ip_mc_s_g_punt_member, table_mask.traps.l3.ip_mc_s_g_punt_member)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_mc_g_punt_member, table_key.traps.l3.ip_mc_g_punt_member, table_mask.traps.l3.ip_mc_g_punt_member)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_mc_egress_punt, table_key.traps.l3.ip_mc_egress_punt, table_mask.traps.l3.ip_mc_egress_punt)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.isis_over_l3, table_key.traps.l3.isis_over_l3, table_mask.traps.l3.isis_over_l3)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.isis_drain, table_key.traps.l3.isis_drain, table_mask.traps.l3.isis_drain)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.no_hbm_access_dip, table_key.traps.l3.no_hbm_access_dip, table_mask.traps.l3.no_hbm_access_dip)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.no_hbm_access_sip, table_key.traps.l3.no_hbm_access_sip, table_mask.traps.l3.no_hbm_access_sip)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.lpm_error, table_key.traps.l3.lpm_error, table_mask.traps.l3.lpm_error)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.lpm_drop, table_key.traps.l3.lpm_drop, table_mask.traps.l3.lpm_drop)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.local_subnet, table_key.traps.l3.local_subnet, table_mask.traps.l3.local_subnet)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.icmp_redirect, table_key.traps.l3.icmp_redirect, table_mask.traps.l3.icmp_redirect)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.no_lp_over_lag_mapping, table_key.traps.l3.no_lp_over_lag_mapping, table_mask.traps.l3.no_lp_over_lag_mapping)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ingress_monitor, table_key.traps.l3.ingress_monitor, table_mask.traps.l3.ingress_monitor)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.egress_monitor, table_key.traps.l3.egress_monitor, table_mask.traps.l3.egress_monitor)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.acl_drop, table_key.traps.l3.acl_drop, table_mask.traps.l3.acl_drop)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.acl_force_punt, table_key.traps.l3.acl_force_punt, table_mask.traps.l3.acl_force_punt)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.acl_force_punt1, table_key.traps.l3.acl_force_punt1, table_mask.traps.l3.acl_force_punt1)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.acl_force_punt2, table_key.traps.l3.acl_force_punt2, table_mask.traps.l3.acl_force_punt2)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.acl_force_punt3, table_key.traps.l3.acl_force_punt3, table_mask.traps.l3.acl_force_punt3)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.acl_force_punt4, table_key.traps.l3.acl_force_punt4, table_mask.traps.l3.acl_force_punt4)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.acl_force_punt5, table_key.traps.l3.acl_force_punt5, table_mask.traps.l3.acl_force_punt5)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.acl_force_punt6, table_key.traps.l3.acl_force_punt6, table_mask.traps.l3.acl_force_punt6)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.acl_force_punt7, table_key.traps.l3.acl_force_punt7, table_mask.traps.l3.acl_force_punt7)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.glean_adj, table_key.traps.l3.glean_adj, table_mask.traps.l3.glean_adj)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.drop_adj, table_key.traps.l3.drop_adj, table_mask.traps.l3.drop_adj)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.drop_adj_non_inject, table_key.traps.l3.drop_adj_non_inject, table_mask.traps.l3.drop_adj_non_inject)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.null_adj, table_key.traps.l3.null_adj, table_mask.traps.l3.null_adj)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.user_trap1, table_key.traps.l3.user_trap1, table_mask.traps.l3.user_trap1)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.user_trap2, table_key.traps.l3.user_trap2, table_mask.traps.l3.user_trap2)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.lpm_default_drop, table_key.traps.l3.lpm_default_drop, table_mask.traps.l3.lpm_default_drop)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.lpm_incomplete0, table_key.traps.l3.lpm_incomplete0, table_mask.traps.l3.lpm_incomplete0)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.lpm_incomplete2, table_key.traps.l3.lpm_incomplete2, table_mask.traps.l3.lpm_incomplete2)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.bfd_micro_ip_disabled, table_key.traps.l3.bfd_micro_ip_disabled, table_mask.traps.l3.bfd_micro_ip_disabled)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.no_vni_mapping, table_key.traps.l3.no_vni_mapping, table_mask.traps.l3.no_vni_mapping)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.no_hbm_access_og_sip, table_key.traps.l3.no_hbm_access_og_sip, table_mask.traps.l3.no_hbm_access_og_sip)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.no_hbm_access_og_dip, table_key.traps.l3.no_hbm_access_og_dip, table_mask.traps.l3.no_hbm_access_og_dip)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.no_l3_dlp_mapping, table_key.traps.l3.no_l3_dlp_mapping, table_mask.traps.l3.no_l3_dlp_mapping)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.l3_dlp_disabled, table_key.traps.l3.l3_dlp_disabled, table_mask.traps.l3.l3_dlp_disabled)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.split_horizon, table_key.traps.l3.split_horizon, table_mask.traps.l3.split_horizon)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.mc_same_interface, table_key.traps.l3.mc_same_interface, table_mask.traps.l3.mc_same_interface)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.no_vpn_label_found, table_key.traps.l3.no_vpn_label_found, table_mask.traps.l3.no_vpn_label_found)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ttl_or_hop_limit_is_one, table_key.traps.l3.ttl_or_hop_limit_is_one, table_mask.traps.l3.ttl_or_hop_limit_is_one)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.tx_mtu_failure, table_key.traps.l3.tx_mtu_failure, table_mask.traps.l3.tx_mtu_failure)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.tx_frr_drop, table_key.traps.l3.tx_frr_drop, table_mask.traps.l3.tx_frr_drop)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_unknown_punt_reason, table_key.traps.oamp.eth_unknown_punt_reason, table_mask.traps.oamp.eth_unknown_punt_reason)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_mep_mapping_failed, table_key.traps.oamp.eth_mep_mapping_failed, table_mask.traps.oamp.eth_mep_mapping_failed)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_mp_type_mismatch, table_key.traps.oamp.eth_mp_type_mismatch, table_mask.traps.oamp.eth_mp_type_mismatch)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_meg_level_mismatch, table_key.traps.oamp.eth_meg_level_mismatch, table_mask.traps.oamp.eth_meg_level_mismatch)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_bad_md_name_format, table_key.traps.oamp.eth_bad_md_name_format, table_mask.traps.oamp.eth_bad_md_name_format)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_unicast_da_no_match, table_key.traps.oamp.eth_unicast_da_no_match, table_mask.traps.oamp.eth_unicast_da_no_match)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_multicast_da_no_match, table_key.traps.oamp.eth_multicast_da_no_match, table_mask.traps.oamp.eth_multicast_da_no_match)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_wrong_meg_id_format, table_key.traps.oamp.eth_wrong_meg_id_format, table_mask.traps.oamp.eth_wrong_meg_id_format)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_meg_id_no_match, table_key.traps.oamp.eth_meg_id_no_match, table_mask.traps.oamp.eth_meg_id_no_match)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_ccm_period_no_match, table_key.traps.oamp.eth_ccm_period_no_match, table_mask.traps.oamp.eth_ccm_period_no_match)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_ccm_tlv_no_match, table_key.traps.oamp.eth_ccm_tlv_no_match, table_mask.traps.oamp.eth_ccm_tlv_no_match)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_lmm_tlv_no_match, table_key.traps.oamp.eth_lmm_tlv_no_match, table_mask.traps.oamp.eth_lmm_tlv_no_match)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_not_supported_oam_opcode, table_key.traps.oamp.eth_not_supported_oam_opcode, table_mask.traps.oamp.eth_not_supported_oam_opcode)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.bfd_transport_not_supported, table_key.traps.oamp.bfd_transport_not_supported, table_mask.traps.oamp.bfd_transport_not_supported)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.bfd_session_lookup_failed, table_key.traps.oamp.bfd_session_lookup_failed, table_mask.traps.oamp.bfd_session_lookup_failed)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.bfd_incorrect_ttl, table_key.traps.oamp.bfd_incorrect_ttl, table_mask.traps.oamp.bfd_incorrect_ttl)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.bfd_invalid_protocol, table_key.traps.oamp.bfd_invalid_protocol, table_mask.traps.oamp.bfd_invalid_protocol)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.bfd_invalid_udp_port, table_key.traps.oamp.bfd_invalid_udp_port, table_mask.traps.oamp.bfd_invalid_udp_port)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.bfd_incorrect_version, table_key.traps.oamp.bfd_incorrect_version, table_mask.traps.oamp.bfd_incorrect_version)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.bfd_incorrect_address, table_key.traps.oamp.bfd_incorrect_address, table_mask.traps.oamp.bfd_incorrect_address)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.bfd_mismatch_discr, table_key.traps.oamp.bfd_mismatch_discr, table_mask.traps.oamp.bfd_mismatch_discr)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.bfd_state_flag_change, table_key.traps.oamp.bfd_state_flag_change, table_mask.traps.oamp.bfd_state_flag_change)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.bfd_session_received, table_key.traps.oamp.bfd_session_received, table_mask.traps.oamp.bfd_session_received)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.pfc_lookup_failed, table_key.traps.oamp.pfc_lookup_failed, table_mask.traps.oamp.pfc_lookup_failed)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.pfc_drop_invalid_rx, table_key.traps.oamp.pfc_drop_invalid_rx, table_mask.traps.oamp.pfc_drop_invalid_rx)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.app.sgacl_drop, table_key.traps.app.sgacl_drop, table_mask.traps.app.sgacl_drop)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.app.sgacl_log, table_key.traps.app.sgacl_log, table_mask.traps.app.sgacl_log)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.app.ip_inactivity, table_key.traps.app.ip_inactivity, table_mask.traps.app.ip_inactivity)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.svl.control_protocol, table_key.traps.svl.control_protocol, table_mask.traps.svl.control_protocol)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.svl.control_ipc, table_key.traps.svl.control_ipc, table_mask.traps.svl.control_ipc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.svl.svl_mc_prune, table_key.traps.svl.svl_mc_prune, table_mask.traps.svl.svl_mc_prune)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap0, table_key.traps.l2_lpts.trap0, table_mask.traps.l2_lpts.trap0)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap1, table_key.traps.l2_lpts.trap1, table_mask.traps.l2_lpts.trap1)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap2, table_key.traps.l2_lpts.trap2, table_mask.traps.l2_lpts.trap2)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap3, table_key.traps.l2_lpts.trap3, table_mask.traps.l2_lpts.trap3)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap4, table_key.traps.l2_lpts.trap4, table_mask.traps.l2_lpts.trap4)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap5, table_key.traps.l2_lpts.trap5, table_mask.traps.l2_lpts.trap5)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap6, table_key.traps.l2_lpts.trap6, table_mask.traps.l2_lpts.trap6)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap7, table_key.traps.l2_lpts.trap7, table_mask.traps.l2_lpts.trap7)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap8, table_key.traps.l2_lpts.trap8, table_mask.traps.l2_lpts.trap8)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap9, table_key.traps.l2_lpts.trap9, table_mask.traps.l2_lpts.trap9)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap10, table_key.traps.l2_lpts.trap10, table_mask.traps.l2_lpts.trap10)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap11, table_key.traps.l2_lpts.trap11, table_mask.traps.l2_lpts.trap11)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.internal.l3_lpm_lpts, table_key.traps.internal.l3_lpm_lpts, table_mask.traps.internal.l3_lpm_lpts)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.internal.ipv4_non_routable_mc_routing, table_key.traps.internal.ipv4_non_routable_mc_routing, table_mask.traps.internal.ipv4_non_routable_mc_routing)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.internal.ipv4_non_routable_mc_bridging, table_key.traps.internal.ipv4_non_routable_mc_bridging, table_mask.traps.internal.ipv4_non_routable_mc_bridging)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.internal.ipv6_non_routable_mc_routing, table_key.traps.internal.ipv6_non_routable_mc_routing, table_mask.traps.internal.ipv6_non_routable_mc_routing)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.internal.ipv6_non_routable_mc_bridging, table_key.traps.internal.ipv6_non_routable_mc_bridging, table_mask.traps.internal.ipv6_non_routable_mc_bridging)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.trap_conditions.non_inject_up, table_key.trap_conditions.non_inject_up, table_mask.trap_conditions.non_inject_up)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.trap_conditions.skip_p2p, table_key.trap_conditions.skip_p2p, table_mask.trap_conditions.skip_p2p)) {
        return false;
    }
    
    
    return true;
}

bool
npl_resolution_pfc_select_table_functional_traits_t::key_match(const npl_resolution_pfc_select_table_key_t& lookup_key, const npl_resolution_pfc_select_table_key_t& table_key, const npl_resolution_pfc_select_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.rx_time, table_key.rx_time, table_mask.rx_time)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.tc, table_key.tc, table_mask.tc)) {
        return false;
    }
    
    
    return true;
}

bool
npl_rtf_next_macro_static_table_functional_traits_t::key_match(const npl_rtf_next_macro_static_table_key_t& lookup_key, const npl_rtf_next_macro_static_table_key_t& table_key, const npl_rtf_next_macro_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.curr_and_next_prot_type.current_proto_type, table_key.curr_and_next_prot_type.current_proto_type, table_mask.curr_and_next_prot_type.current_proto_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.curr_and_next_prot_type.next_proto_type, table_key.curr_and_next_prot_type.next_proto_type, table_mask.curr_and_next_prot_type.next_proto_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.pd_tunnel_ipv4_ipv6_init_rtf_stage.ipv4_init_rtf_stage, table_key.pd_tunnel_ipv4_ipv6_init_rtf_stage.ipv4_init_rtf_stage, table_mask.pd_tunnel_ipv4_ipv6_init_rtf_stage.ipv4_init_rtf_stage)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.pd_tunnel_ipv4_ipv6_init_rtf_stage.ipv6_init_rtf_stage, table_key.pd_tunnel_ipv4_ipv6_init_rtf_stage.ipv6_init_rtf_stage, table_mask.pd_tunnel_ipv4_ipv6_init_rtf_stage.ipv6_init_rtf_stage)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.next_rtf_stage, table_key.next_rtf_stage, table_mask.next_rtf_stage)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.rtf_indications.acl_outer, table_key.rtf_indications.acl_outer, table_mask.rtf_indications.acl_outer)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.rtf_indications.fwd_layer_and_rtf_stage_compressed_fields.fwd_layer, table_key.rtf_indications.fwd_layer_and_rtf_stage_compressed_fields.fwd_layer, table_mask.rtf_indications.fwd_layer_and_rtf_stage_compressed_fields.fwd_layer)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.rtf_indications.fwd_layer_and_rtf_stage_compressed_fields.rtf_stage, table_key.rtf_indications.fwd_layer_and_rtf_stage_compressed_fields.rtf_stage, table_mask.rtf_indications.fwd_layer_and_rtf_stage_compressed_fields.rtf_stage)) {
        return false;
    }
    
    
    return true;
}

bool
npl_rx_redirect_next_macro_static_table_functional_traits_t::key_match(const npl_rx_redirect_next_macro_static_table_key_t& lookup_key, const npl_rx_redirect_next_macro_static_table_key_t& table_key, const npl_rx_redirect_next_macro_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.cud_type, table_key.cud_type, table_mask.cud_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.redirect_code, table_key.redirect_code, table_mask.redirect_code)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.protocol_type, table_key.protocol_type, table_mask.protocol_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.next_protocol_type, table_key.next_protocol_type, table_mask.next_protocol_type)) {
        return false;
    }
    
    
    return true;
}

bool
npl_second_ene_static_table_functional_traits_t::key_match(const npl_second_ene_static_table_key_t& lookup_key, const npl_second_ene_static_table_key_t& table_key, const npl_second_ene_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.second_ene_macro_code, table_key.second_ene_macro_code, table_mask.second_ene_macro_code)) {
        return false;
    }
    
    
    return true;
}

bool
npl_select_inject_next_macro_static_table_functional_traits_t::key_match(const npl_select_inject_next_macro_static_table_key_t& lookup_key, const npl_select_inject_next_macro_static_table_key_t& table_key, const npl_select_inject_next_macro_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.local_inject_type_7_0_.inject_type, table_key.local_inject_type_7_0_.inject_type, table_mask.local_inject_type_7_0_.inject_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.protocol, table_key.protocol, table_mask.protocol)) {
        return false;
    }
    
    
    return true;
}

bool
npl_service_mapping_tcam_ac_port_table_functional_traits_t::key_match(const npl_service_mapping_tcam_ac_port_table_key_t& lookup_key, const npl_service_mapping_tcam_ac_port_table_key_t& table_key, const npl_service_mapping_tcam_ac_port_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.local_slp_id.id, table_key.local_slp_id.id, table_mask.local_slp_id.id)) {
        return false;
    }
    
    
    return true;
}

bool
npl_service_mapping_tcam_ac_port_tag_table_functional_traits_t::key_match(const npl_service_mapping_tcam_ac_port_tag_table_key_t& lookup_key, const npl_service_mapping_tcam_ac_port_tag_table_key_t& table_key, const npl_service_mapping_tcam_ac_port_tag_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.vid1.id, table_key.vid1.id, table_mask.vid1.id)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.local_slp_id.id, table_key.local_slp_id.id, table_mask.local_slp_id.id)) {
        return false;
    }
    
    
    return true;
}

bool
npl_service_mapping_tcam_ac_port_tag_tag_table_functional_traits_t::key_match(const npl_service_mapping_tcam_ac_port_tag_tag_table_key_t& lookup_key, const npl_service_mapping_tcam_ac_port_tag_tag_table_key_t& table_key, const npl_service_mapping_tcam_ac_port_tag_tag_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.vid2.id, table_key.vid2.id, table_mask.vid2.id)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.vid1.id, table_key.vid1.id, table_mask.vid1.id)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.local_slp_id.id, table_key.local_slp_id.id, table_mask.local_slp_id.id)) {
        return false;
    }
    
    
    return true;
}

bool
npl_service_mapping_tcam_pwe_tag_table_functional_traits_t::key_match(const npl_service_mapping_tcam_pwe_tag_table_key_t& lookup_key, const npl_service_mapping_tcam_pwe_tag_table_key_t& table_key, const npl_service_mapping_tcam_pwe_tag_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.vid1.id, table_key.vid1.id, table_mask.vid1.id)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.local_slp_id.id, table_key.local_slp_id.id, table_mask.local_slp_id.id)) {
        return false;
    }
    
    
    return true;
}

bool
npl_sgacl_table_functional_traits_t::key_match(const npl_sgacl_table_key_t& lookup_key, const npl_sgacl_table_key_t& table_key, const npl_sgacl_table_key_t& table_mask)
{
    
    
    return true;
}

bool
npl_snoop_table_functional_traits_t::key_match(const npl_snoop_table_key_t& lookup_key, const npl_snoop_table_key_t& table_key, const npl_snoop_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.acl_drop, table_key.traps.ethernet.acl_drop, table_mask.traps.ethernet.acl_drop)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.acl_force_punt, table_key.traps.ethernet.acl_force_punt, table_mask.traps.ethernet.acl_force_punt)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.vlan_membership, table_key.traps.ethernet.vlan_membership, table_mask.traps.ethernet.vlan_membership)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.acceptable_format, table_key.traps.ethernet.acceptable_format, table_mask.traps.ethernet.acceptable_format)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.no_service_mapping, table_key.traps.ethernet.no_service_mapping, table_mask.traps.ethernet.no_service_mapping)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.no_termination_on_l3_port, table_key.traps.ethernet.no_termination_on_l3_port, table_mask.traps.ethernet.no_termination_on_l3_port)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.no_sip_mapping, table_key.traps.ethernet.no_sip_mapping, table_mask.traps.ethernet.no_sip_mapping)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.no_vni_mapping, table_key.traps.ethernet.no_vni_mapping, table_mask.traps.ethernet.no_vni_mapping)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.no_vsid_mapping, table_key.traps.ethernet.no_vsid_mapping, table_mask.traps.ethernet.no_vsid_mapping)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.arp, table_key.traps.ethernet.arp, table_mask.traps.ethernet.arp)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.sa_da_error, table_key.traps.ethernet.sa_da_error, table_mask.traps.ethernet.sa_da_error)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.sa_error, table_key.traps.ethernet.sa_error, table_mask.traps.ethernet.sa_error)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.da_error, table_key.traps.ethernet.da_error, table_mask.traps.ethernet.da_error)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.sa_multicast, table_key.traps.ethernet.sa_multicast, table_mask.traps.ethernet.sa_multicast)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.dhcpv4_server, table_key.traps.ethernet.dhcpv4_server, table_mask.traps.ethernet.dhcpv4_server)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.dhcpv4_client, table_key.traps.ethernet.dhcpv4_client, table_mask.traps.ethernet.dhcpv4_client)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.dhcpv6_server, table_key.traps.ethernet.dhcpv6_server, table_mask.traps.ethernet.dhcpv6_server)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.dhcpv6_client, table_key.traps.ethernet.dhcpv6_client, table_mask.traps.ethernet.dhcpv6_client)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.ingress_stp_block, table_key.traps.ethernet.ingress_stp_block, table_mask.traps.ethernet.ingress_stp_block)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.ptp_over_eth, table_key.traps.ethernet.ptp_over_eth, table_mask.traps.ethernet.ptp_over_eth)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.isis_over_l2, table_key.traps.ethernet.isis_over_l2, table_mask.traps.ethernet.isis_over_l2)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.l2cp0, table_key.traps.ethernet.l2cp0, table_mask.traps.ethernet.l2cp0)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.l2cp1, table_key.traps.ethernet.l2cp1, table_mask.traps.ethernet.l2cp1)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.l2cp2, table_key.traps.ethernet.l2cp2, table_mask.traps.ethernet.l2cp2)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.l2cp3, table_key.traps.ethernet.l2cp3, table_mask.traps.ethernet.l2cp3)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.l2cp4, table_key.traps.ethernet.l2cp4, table_mask.traps.ethernet.l2cp4)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.l2cp5, table_key.traps.ethernet.l2cp5, table_mask.traps.ethernet.l2cp5)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.l2cp6, table_key.traps.ethernet.l2cp6, table_mask.traps.ethernet.l2cp6)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.l2cp7, table_key.traps.ethernet.l2cp7, table_mask.traps.ethernet.l2cp7)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.lacp, table_key.traps.ethernet.lacp, table_mask.traps.ethernet.lacp)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.cisco_protocols, table_key.traps.ethernet.cisco_protocols, table_mask.traps.ethernet.cisco_protocols)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.macsec, table_key.traps.ethernet.macsec, table_mask.traps.ethernet.macsec)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.unknown_l3, table_key.traps.ethernet.unknown_l3, table_mask.traps.ethernet.unknown_l3)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.test_oam_ac_mep, table_key.traps.ethernet.test_oam_ac_mep, table_mask.traps.ethernet.test_oam_ac_mep)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.test_oam_ac_mip, table_key.traps.ethernet.test_oam_ac_mip, table_mask.traps.ethernet.test_oam_ac_mip)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.test_oam_cfm_link_mdl0, table_key.traps.ethernet.test_oam_cfm_link_mdl0, table_mask.traps.ethernet.test_oam_cfm_link_mdl0)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.system_mymac, table_key.traps.ethernet.system_mymac, table_mask.traps.ethernet.system_mymac)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.unknown_bc, table_key.traps.ethernet.unknown_bc, table_mask.traps.ethernet.unknown_bc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.unknown_mc, table_key.traps.ethernet.unknown_mc, table_mask.traps.ethernet.unknown_mc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.unknown_uc, table_key.traps.ethernet.unknown_uc, table_mask.traps.ethernet.unknown_uc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.learn_punt, table_key.traps.ethernet.learn_punt, table_mask.traps.ethernet.learn_punt)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.bcast_pkt, table_key.traps.ethernet.bcast_pkt, table_mask.traps.ethernet.bcast_pkt)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.pfc_sample, table_key.traps.ethernet.pfc_sample, table_mask.traps.ethernet.pfc_sample)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.hop_by_hop, table_key.traps.ethernet.hop_by_hop, table_mask.traps.ethernet.hop_by_hop)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.l2_dlp_not_found, table_key.traps.ethernet.l2_dlp_not_found, table_mask.traps.ethernet.l2_dlp_not_found)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.same_interface, table_key.traps.ethernet.same_interface, table_mask.traps.ethernet.same_interface)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.dspa_mc_trim, table_key.traps.ethernet.dspa_mc_trim, table_mask.traps.ethernet.dspa_mc_trim)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.egress_stp_block, table_key.traps.ethernet.egress_stp_block, table_mask.traps.ethernet.egress_stp_block)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.split_horizon, table_key.traps.ethernet.split_horizon, table_mask.traps.ethernet.split_horizon)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.disabled, table_key.traps.ethernet.disabled, table_mask.traps.ethernet.disabled)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.incompatible_eve_cmd, table_key.traps.ethernet.incompatible_eve_cmd, table_mask.traps.ethernet.incompatible_eve_cmd)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.padding_residue_in_second_line, table_key.traps.ethernet.padding_residue_in_second_line, table_mask.traps.ethernet.padding_residue_in_second_line)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.pfc_direct_sample, table_key.traps.ethernet.pfc_direct_sample, table_mask.traps.ethernet.pfc_direct_sample)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.svi_egress_dhcp, table_key.traps.ethernet.svi_egress_dhcp, table_mask.traps.ethernet.svi_egress_dhcp)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ethernet.no_pwe_l3_dest, table_key.traps.ethernet.no_pwe_l3_dest, table_mask.traps.ethernet.no_pwe_l3_dest)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv4.mc_forwarding_disabled, table_key.traps.ipv4.mc_forwarding_disabled, table_mask.traps.ipv4.mc_forwarding_disabled)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv4.uc_forwarding_disabled, table_key.traps.ipv4.uc_forwarding_disabled, table_mask.traps.ipv4.uc_forwarding_disabled)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv4.checksum, table_key.traps.ipv4.checksum, table_mask.traps.ipv4.checksum)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv4.header_error, table_key.traps.ipv4.header_error, table_mask.traps.ipv4.header_error)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv4.unknown_protocol, table_key.traps.ipv4.unknown_protocol, table_mask.traps.ipv4.unknown_protocol)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv4.options_exist, table_key.traps.ipv4.options_exist, table_mask.traps.ipv4.options_exist)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv4.non_comp_mc, table_key.traps.ipv4.non_comp_mc, table_mask.traps.ipv4.non_comp_mc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv6.mc_forwarding_disabled, table_key.traps.ipv6.mc_forwarding_disabled, table_mask.traps.ipv6.mc_forwarding_disabled)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv6.uc_forwarding_disabled, table_key.traps.ipv6.uc_forwarding_disabled, table_mask.traps.ipv6.uc_forwarding_disabled)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv6.hop_by_hop, table_key.traps.ipv6.hop_by_hop, table_mask.traps.ipv6.hop_by_hop)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv6.header_error, table_key.traps.ipv6.header_error, table_mask.traps.ipv6.header_error)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv6.illegal_sip, table_key.traps.ipv6.illegal_sip, table_mask.traps.ipv6.illegal_sip)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv6.illegal_dip, table_key.traps.ipv6.illegal_dip, table_mask.traps.ipv6.illegal_dip)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv6.zero_payload, table_key.traps.ipv6.zero_payload, table_mask.traps.ipv6.zero_payload)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv6.next_header_check, table_key.traps.ipv6.next_header_check, table_mask.traps.ipv6.next_header_check)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.ipv6.non_comp_mc, table_key.traps.ipv6.non_comp_mc, table_mask.traps.ipv6.non_comp_mc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.unknown_protocol_after_bos, table_key.traps.mpls.unknown_protocol_after_bos, table_mask.traps.mpls.unknown_protocol_after_bos)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.ttl_is_zero, table_key.traps.mpls.ttl_is_zero, table_mask.traps.mpls.ttl_is_zero)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.bfd_over_pwe_ttl, table_key.traps.mpls.bfd_over_pwe_ttl, table_mask.traps.mpls.bfd_over_pwe_ttl)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.bfd_over_pwe_raw, table_key.traps.mpls.bfd_over_pwe_raw, table_mask.traps.mpls.bfd_over_pwe_raw)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.bfd_over_pwe_ipv4, table_key.traps.mpls.bfd_over_pwe_ipv4, table_mask.traps.mpls.bfd_over_pwe_ipv4)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.bfd_over_pwe_ipv6, table_key.traps.mpls.bfd_over_pwe_ipv6, table_mask.traps.mpls.bfd_over_pwe_ipv6)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.unknown_bfd_g_ach_channel_type, table_key.traps.mpls.unknown_bfd_g_ach_channel_type, table_mask.traps.mpls.unknown_bfd_g_ach_channel_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.bfd_over_pwe_ra, table_key.traps.mpls.bfd_over_pwe_ra, table_mask.traps.mpls.bfd_over_pwe_ra)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.mpls_tp_over_pwe, table_key.traps.mpls.mpls_tp_over_pwe, table_mask.traps.mpls.mpls_tp_over_pwe)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.unknown_g_ach, table_key.traps.mpls.unknown_g_ach, table_mask.traps.mpls.unknown_g_ach)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.mpls_tp_over_lsp, table_key.traps.mpls.mpls_tp_over_lsp, table_mask.traps.mpls.mpls_tp_over_lsp)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.oam_alert_label, table_key.traps.mpls.oam_alert_label, table_mask.traps.mpls.oam_alert_label)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.extension_label, table_key.traps.mpls.extension_label, table_mask.traps.mpls.extension_label)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.router_alert_label, table_key.traps.mpls.router_alert_label, table_mask.traps.mpls.router_alert_label)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.unexpected_reserved_label, table_key.traps.mpls.unexpected_reserved_label, table_mask.traps.mpls.unexpected_reserved_label)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.forwarding_disabled, table_key.traps.mpls.forwarding_disabled, table_mask.traps.mpls.forwarding_disabled)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.ilm_miss, table_key.traps.mpls.ilm_miss, table_mask.traps.mpls.ilm_miss)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.ipv4_over_ipv6_explicit_null, table_key.traps.mpls.ipv4_over_ipv6_explicit_null, table_mask.traps.mpls.ipv4_over_ipv6_explicit_null)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.invalid_ttl, table_key.traps.mpls.invalid_ttl, table_mask.traps.mpls.invalid_ttl)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.te_midpopint_ldp_labels_miss, table_key.traps.mpls.te_midpopint_ldp_labels_miss, table_mask.traps.mpls.te_midpopint_ldp_labels_miss)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.asbr_label_miss, table_key.traps.mpls.asbr_label_miss, table_mask.traps.mpls.asbr_label_miss)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.ilm_vrf_label_miss, table_key.traps.mpls.ilm_vrf_label_miss, table_mask.traps.mpls.ilm_vrf_label_miss)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.pwe_pwach, table_key.traps.mpls.pwe_pwach, table_mask.traps.mpls.pwe_pwach)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.vpn_ttl_one, table_key.traps.mpls.vpn_ttl_one, table_mask.traps.mpls.vpn_ttl_one)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.mpls.missing_fwd_label_after_pop, table_key.traps.mpls.missing_fwd_label_after_pop, table_mask.traps.mpls.missing_fwd_label_after_pop)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_unicast_rpf, table_key.traps.l3.ip_unicast_rpf, table_mask.traps.l3.ip_unicast_rpf)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_multicast_rpf, table_key.traps.l3.ip_multicast_rpf, table_mask.traps.l3.ip_multicast_rpf)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_mc_drop, table_key.traps.l3.ip_mc_drop, table_mask.traps.l3.ip_mc_drop)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_mc_punt_dc_pass, table_key.traps.l3.ip_mc_punt_dc_pass, table_mask.traps.l3.ip_mc_punt_dc_pass)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_mc_snoop_dc_pass, table_key.traps.l3.ip_mc_snoop_dc_pass, table_mask.traps.l3.ip_mc_snoop_dc_pass)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_mc_snoop_rpf_fail, table_key.traps.l3.ip_mc_snoop_rpf_fail, table_mask.traps.l3.ip_mc_snoop_rpf_fail)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_mc_punt_rpf_fail, table_key.traps.l3.ip_mc_punt_rpf_fail, table_mask.traps.l3.ip_mc_punt_rpf_fail)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_mc_snoop_lookup_miss, table_key.traps.l3.ip_mc_snoop_lookup_miss, table_mask.traps.l3.ip_mc_snoop_lookup_miss)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_multicast_not_found, table_key.traps.l3.ip_multicast_not_found, table_mask.traps.l3.ip_multicast_not_found)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_mc_s_g_punt_member, table_key.traps.l3.ip_mc_s_g_punt_member, table_mask.traps.l3.ip_mc_s_g_punt_member)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_mc_g_punt_member, table_key.traps.l3.ip_mc_g_punt_member, table_mask.traps.l3.ip_mc_g_punt_member)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ip_mc_egress_punt, table_key.traps.l3.ip_mc_egress_punt, table_mask.traps.l3.ip_mc_egress_punt)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.isis_over_l3, table_key.traps.l3.isis_over_l3, table_mask.traps.l3.isis_over_l3)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.isis_drain, table_key.traps.l3.isis_drain, table_mask.traps.l3.isis_drain)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.no_hbm_access_dip, table_key.traps.l3.no_hbm_access_dip, table_mask.traps.l3.no_hbm_access_dip)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.no_hbm_access_sip, table_key.traps.l3.no_hbm_access_sip, table_mask.traps.l3.no_hbm_access_sip)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.lpm_error, table_key.traps.l3.lpm_error, table_mask.traps.l3.lpm_error)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.lpm_drop, table_key.traps.l3.lpm_drop, table_mask.traps.l3.lpm_drop)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.local_subnet, table_key.traps.l3.local_subnet, table_mask.traps.l3.local_subnet)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.icmp_redirect, table_key.traps.l3.icmp_redirect, table_mask.traps.l3.icmp_redirect)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.no_lp_over_lag_mapping, table_key.traps.l3.no_lp_over_lag_mapping, table_mask.traps.l3.no_lp_over_lag_mapping)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ingress_monitor, table_key.traps.l3.ingress_monitor, table_mask.traps.l3.ingress_monitor)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.egress_monitor, table_key.traps.l3.egress_monitor, table_mask.traps.l3.egress_monitor)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.acl_drop, table_key.traps.l3.acl_drop, table_mask.traps.l3.acl_drop)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.acl_force_punt, table_key.traps.l3.acl_force_punt, table_mask.traps.l3.acl_force_punt)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.acl_force_punt1, table_key.traps.l3.acl_force_punt1, table_mask.traps.l3.acl_force_punt1)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.acl_force_punt2, table_key.traps.l3.acl_force_punt2, table_mask.traps.l3.acl_force_punt2)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.acl_force_punt3, table_key.traps.l3.acl_force_punt3, table_mask.traps.l3.acl_force_punt3)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.acl_force_punt4, table_key.traps.l3.acl_force_punt4, table_mask.traps.l3.acl_force_punt4)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.acl_force_punt5, table_key.traps.l3.acl_force_punt5, table_mask.traps.l3.acl_force_punt5)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.acl_force_punt6, table_key.traps.l3.acl_force_punt6, table_mask.traps.l3.acl_force_punt6)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.acl_force_punt7, table_key.traps.l3.acl_force_punt7, table_mask.traps.l3.acl_force_punt7)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.glean_adj, table_key.traps.l3.glean_adj, table_mask.traps.l3.glean_adj)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.drop_adj, table_key.traps.l3.drop_adj, table_mask.traps.l3.drop_adj)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.drop_adj_non_inject, table_key.traps.l3.drop_adj_non_inject, table_mask.traps.l3.drop_adj_non_inject)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.null_adj, table_key.traps.l3.null_adj, table_mask.traps.l3.null_adj)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.user_trap1, table_key.traps.l3.user_trap1, table_mask.traps.l3.user_trap1)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.user_trap2, table_key.traps.l3.user_trap2, table_mask.traps.l3.user_trap2)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.lpm_default_drop, table_key.traps.l3.lpm_default_drop, table_mask.traps.l3.lpm_default_drop)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.lpm_incomplete0, table_key.traps.l3.lpm_incomplete0, table_mask.traps.l3.lpm_incomplete0)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.lpm_incomplete2, table_key.traps.l3.lpm_incomplete2, table_mask.traps.l3.lpm_incomplete2)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.bfd_micro_ip_disabled, table_key.traps.l3.bfd_micro_ip_disabled, table_mask.traps.l3.bfd_micro_ip_disabled)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.no_vni_mapping, table_key.traps.l3.no_vni_mapping, table_mask.traps.l3.no_vni_mapping)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.no_hbm_access_og_sip, table_key.traps.l3.no_hbm_access_og_sip, table_mask.traps.l3.no_hbm_access_og_sip)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.no_hbm_access_og_dip, table_key.traps.l3.no_hbm_access_og_dip, table_mask.traps.l3.no_hbm_access_og_dip)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.no_l3_dlp_mapping, table_key.traps.l3.no_l3_dlp_mapping, table_mask.traps.l3.no_l3_dlp_mapping)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.l3_dlp_disabled, table_key.traps.l3.l3_dlp_disabled, table_mask.traps.l3.l3_dlp_disabled)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.split_horizon, table_key.traps.l3.split_horizon, table_mask.traps.l3.split_horizon)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.mc_same_interface, table_key.traps.l3.mc_same_interface, table_mask.traps.l3.mc_same_interface)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.no_vpn_label_found, table_key.traps.l3.no_vpn_label_found, table_mask.traps.l3.no_vpn_label_found)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.ttl_or_hop_limit_is_one, table_key.traps.l3.ttl_or_hop_limit_is_one, table_mask.traps.l3.ttl_or_hop_limit_is_one)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.tx_mtu_failure, table_key.traps.l3.tx_mtu_failure, table_mask.traps.l3.tx_mtu_failure)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l3.tx_frr_drop, table_key.traps.l3.tx_frr_drop, table_mask.traps.l3.tx_frr_drop)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_unknown_punt_reason, table_key.traps.oamp.eth_unknown_punt_reason, table_mask.traps.oamp.eth_unknown_punt_reason)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_mep_mapping_failed, table_key.traps.oamp.eth_mep_mapping_failed, table_mask.traps.oamp.eth_mep_mapping_failed)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_mp_type_mismatch, table_key.traps.oamp.eth_mp_type_mismatch, table_mask.traps.oamp.eth_mp_type_mismatch)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_meg_level_mismatch, table_key.traps.oamp.eth_meg_level_mismatch, table_mask.traps.oamp.eth_meg_level_mismatch)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_bad_md_name_format, table_key.traps.oamp.eth_bad_md_name_format, table_mask.traps.oamp.eth_bad_md_name_format)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_unicast_da_no_match, table_key.traps.oamp.eth_unicast_da_no_match, table_mask.traps.oamp.eth_unicast_da_no_match)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_multicast_da_no_match, table_key.traps.oamp.eth_multicast_da_no_match, table_mask.traps.oamp.eth_multicast_da_no_match)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_wrong_meg_id_format, table_key.traps.oamp.eth_wrong_meg_id_format, table_mask.traps.oamp.eth_wrong_meg_id_format)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_meg_id_no_match, table_key.traps.oamp.eth_meg_id_no_match, table_mask.traps.oamp.eth_meg_id_no_match)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_ccm_period_no_match, table_key.traps.oamp.eth_ccm_period_no_match, table_mask.traps.oamp.eth_ccm_period_no_match)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_ccm_tlv_no_match, table_key.traps.oamp.eth_ccm_tlv_no_match, table_mask.traps.oamp.eth_ccm_tlv_no_match)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_lmm_tlv_no_match, table_key.traps.oamp.eth_lmm_tlv_no_match, table_mask.traps.oamp.eth_lmm_tlv_no_match)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.eth_not_supported_oam_opcode, table_key.traps.oamp.eth_not_supported_oam_opcode, table_mask.traps.oamp.eth_not_supported_oam_opcode)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.bfd_transport_not_supported, table_key.traps.oamp.bfd_transport_not_supported, table_mask.traps.oamp.bfd_transport_not_supported)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.bfd_session_lookup_failed, table_key.traps.oamp.bfd_session_lookup_failed, table_mask.traps.oamp.bfd_session_lookup_failed)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.bfd_incorrect_ttl, table_key.traps.oamp.bfd_incorrect_ttl, table_mask.traps.oamp.bfd_incorrect_ttl)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.bfd_invalid_protocol, table_key.traps.oamp.bfd_invalid_protocol, table_mask.traps.oamp.bfd_invalid_protocol)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.bfd_invalid_udp_port, table_key.traps.oamp.bfd_invalid_udp_port, table_mask.traps.oamp.bfd_invalid_udp_port)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.bfd_incorrect_version, table_key.traps.oamp.bfd_incorrect_version, table_mask.traps.oamp.bfd_incorrect_version)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.bfd_incorrect_address, table_key.traps.oamp.bfd_incorrect_address, table_mask.traps.oamp.bfd_incorrect_address)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.bfd_mismatch_discr, table_key.traps.oamp.bfd_mismatch_discr, table_mask.traps.oamp.bfd_mismatch_discr)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.bfd_state_flag_change, table_key.traps.oamp.bfd_state_flag_change, table_mask.traps.oamp.bfd_state_flag_change)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.bfd_session_received, table_key.traps.oamp.bfd_session_received, table_mask.traps.oamp.bfd_session_received)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.pfc_lookup_failed, table_key.traps.oamp.pfc_lookup_failed, table_mask.traps.oamp.pfc_lookup_failed)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.oamp.pfc_drop_invalid_rx, table_key.traps.oamp.pfc_drop_invalid_rx, table_mask.traps.oamp.pfc_drop_invalid_rx)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.app.sgacl_drop, table_key.traps.app.sgacl_drop, table_mask.traps.app.sgacl_drop)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.app.sgacl_log, table_key.traps.app.sgacl_log, table_mask.traps.app.sgacl_log)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.app.ip_inactivity, table_key.traps.app.ip_inactivity, table_mask.traps.app.ip_inactivity)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.svl.control_protocol, table_key.traps.svl.control_protocol, table_mask.traps.svl.control_protocol)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.svl.control_ipc, table_key.traps.svl.control_ipc, table_mask.traps.svl.control_ipc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.svl.svl_mc_prune, table_key.traps.svl.svl_mc_prune, table_mask.traps.svl.svl_mc_prune)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap0, table_key.traps.l2_lpts.trap0, table_mask.traps.l2_lpts.trap0)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap1, table_key.traps.l2_lpts.trap1, table_mask.traps.l2_lpts.trap1)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap2, table_key.traps.l2_lpts.trap2, table_mask.traps.l2_lpts.trap2)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap3, table_key.traps.l2_lpts.trap3, table_mask.traps.l2_lpts.trap3)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap4, table_key.traps.l2_lpts.trap4, table_mask.traps.l2_lpts.trap4)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap5, table_key.traps.l2_lpts.trap5, table_mask.traps.l2_lpts.trap5)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap6, table_key.traps.l2_lpts.trap6, table_mask.traps.l2_lpts.trap6)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap7, table_key.traps.l2_lpts.trap7, table_mask.traps.l2_lpts.trap7)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap8, table_key.traps.l2_lpts.trap8, table_mask.traps.l2_lpts.trap8)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap9, table_key.traps.l2_lpts.trap9, table_mask.traps.l2_lpts.trap9)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap10, table_key.traps.l2_lpts.trap10, table_mask.traps.l2_lpts.trap10)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.l2_lpts.trap11, table_key.traps.l2_lpts.trap11, table_mask.traps.l2_lpts.trap11)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.internal.l3_lpm_lpts, table_key.traps.internal.l3_lpm_lpts, table_mask.traps.internal.l3_lpm_lpts)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.internal.ipv4_non_routable_mc_routing, table_key.traps.internal.ipv4_non_routable_mc_routing, table_mask.traps.internal.ipv4_non_routable_mc_routing)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.internal.ipv4_non_routable_mc_bridging, table_key.traps.internal.ipv4_non_routable_mc_bridging, table_mask.traps.internal.ipv4_non_routable_mc_bridging)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.internal.ipv6_non_routable_mc_routing, table_key.traps.internal.ipv6_non_routable_mc_routing, table_mask.traps.internal.ipv6_non_routable_mc_routing)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.traps.internal.ipv6_non_routable_mc_bridging, table_key.traps.internal.ipv6_non_routable_mc_bridging, table_mask.traps.internal.ipv6_non_routable_mc_bridging)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.trap_conditions.non_inject_up, table_key.trap_conditions.non_inject_up, table_mask.trap_conditions.non_inject_up)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.trap_conditions.skip_p2p, table_key.trap_conditions.skip_p2p, table_mask.trap_conditions.skip_p2p)) {
        return false;
    }
    
    
    return true;
}

bool
npl_svl_next_macro_static_table_functional_traits_t::key_match(const npl_svl_next_macro_static_table_key_t& lookup_key, const npl_svl_next_macro_static_table_key_t& table_key, const npl_svl_next_macro_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.type, table_key.type, table_mask.type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.mac_da_prefix, table_key.mac_da_prefix, table_mask.mac_da_prefix)) {
        return false;
    }
    
    
    return true;
}

bool
npl_te_headend_lsp_counter_offset_table_functional_traits_t::key_match(const npl_te_headend_lsp_counter_offset_table_key_t& lookup_key, const npl_te_headend_lsp_counter_offset_table_key_t& table_key, const npl_te_headend_lsp_counter_offset_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.is_mc, table_key.is_mc, table_mask.is_mc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.fwd_header_type, table_key.fwd_header_type, table_mask.fwd_header_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l3_encap_type, table_key.l3_encap_type, table_mask.l3_encap_type)) {
        return false;
    }
    
    
    return true;
}

bool
npl_tunnel_dlp_p_counter_offset_table_functional_traits_t::key_match(const npl_tunnel_dlp_p_counter_offset_table_key_t& lookup_key, const npl_tunnel_dlp_p_counter_offset_table_key_t& table_key, const npl_tunnel_dlp_p_counter_offset_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.is_mc, table_key.is_mc, table_mask.is_mc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.is_mpls, table_key.is_mpls, table_mask.is_mpls)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.l3_encap_type, table_key.l3_encap_type, table_mask.l3_encap_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.fwd_header_type, table_key.fwd_header_type, table_mask.fwd_header_type)) {
        return false;
    }
    
    
    return true;
}

bool
npl_txpp_initial_npe_macro_table_functional_traits_t::key_match(const npl_txpp_initial_npe_macro_table_key_t& lookup_key, const npl_txpp_initial_npe_macro_table_key_t& table_key, const npl_txpp_initial_npe_macro_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.txpp_first_macro_table_key.is_mc, table_key.txpp_first_macro_table_key.is_mc, table_mask.txpp_first_macro_table_key.is_mc)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.txpp_first_macro_table_key.fwd_type, table_key.txpp_first_macro_table_key.fwd_type, table_mask.txpp_first_macro_table_key.fwd_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.txpp_first_macro_table_key.first_encap_type, table_key.txpp_first_macro_table_key.first_encap_type, table_mask.txpp_first_macro_table_key.first_encap_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.txpp_first_macro_table_key.second_encap_type, table_key.txpp_first_macro_table_key.second_encap_type, table_mask.txpp_first_macro_table_key.second_encap_type)) {
        return false;
    }
    
    
    return true;
}

bool
npl_urpf_ipsa_dest_is_lpts_static_table_functional_traits_t::key_match(const npl_urpf_ipsa_dest_is_lpts_static_table_key_t& lookup_key, const npl_urpf_ipsa_dest_is_lpts_static_table_key_t& table_key, const npl_urpf_ipsa_dest_is_lpts_static_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.ipsa_dest_prefix, table_key.ipsa_dest_prefix, table_mask.ipsa_dest_prefix)) {
        return false;
    }
    
    
    return true;
}

bool
npl_vlan_format_table_functional_traits_t::key_match(const npl_vlan_format_table_key_t& lookup_key, const npl_vlan_format_table_key_t& table_key, const npl_vlan_format_table_key_t& table_mask)
{
    if (!npl_ternary_field_compare(lookup_key.vlan_profile, table_key.vlan_profile, table_mask.vlan_profile)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.header_1_type, table_key.header_1_type, table_mask.header_1_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.header_2_type, table_key.header_2_type, table_mask.header_2_type)) {
        return false;
    }
    
    if (!npl_ternary_field_compare(lookup_key.is_priority, table_key.is_priority, table_mask.is_priority)) {
        return false;
    }
    
    
    return true;
}

