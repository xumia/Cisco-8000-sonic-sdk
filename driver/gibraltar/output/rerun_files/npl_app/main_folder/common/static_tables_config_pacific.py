# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
#
# This file and all technical concepts, proprietary knowledge, algorithms and
# intellectual property rights it contains (collectively the "Confidential Information"),
# are the sole propriety information of Cisco and shall remain at Cisco's ownership.
# You shall not disclose the Confidential Information to any third party and you
# shall use it solely in connection with operating and/or maintaining of Cisco's
# products and pursuant to the terms and conditions of the license agreement you
# entered into with Cisco.
#
# THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
# IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
# THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# END_LEGAL

# Since we manually indented tables in this file, we don't want pep8 to mess with spaces
# This directive is read by leaba_format.py script
# pep8_extra_args = "--ignore=E2 --max-line-length 200"

from config_tables_utils import *
ENE_END_MACRO = 0
DONT_CARE = 0
_DONT_CARE = Key(value=0, mask=0)
ALL_1 = (1 << 128) - 1


def config_tables():
    config_nhlfe_type_mapping_static_table()
    config_bfd_udp_port_map_static_table()
    config_eve_byte_addition_static_table()
    config_ene_byte_addition_static_table()
    config_mac_termination_next_macro_static_table()
    config_pad_mtu_inj_check_static_table()
    config_rtf_next_macro_static_table()
    config_pfc_vector_static_table()
    config_gre_proto_static_table()
    config_l2_lpts_ip_fragment_static_table()
    config_inject_down_select_ene_static_table()
    config_nh_macro_code_to_id_l6_static_table()
    config_svl_next_macro_static_table()
    config_is_pacific_b1_static_table()
    config_ipv6_mc_select_qos_id()
    # config_write_acl_drop_offset_on_pd()


def config_nh_macro_code_to_id_l6_static_table() :
    table = nh_macro_code_to_id_l6_static_table
    table_data = [
        {"nh_ene_code": NH_ENE_MACRO_ETH,           "nh_ene_macro_id": NH_ETHERNET_NO_VLAN_ENE_MACRO},
        {"nh_ene_code": NH_ENE_MACRO_ETH_VLAN,      "nh_ene_macro_id": NH_ETHERNET_WITH_ONE_VLAN_ENE_MACRO},
        {"nh_ene_code": NH_ENE_MACRO_ETH_VLAN_VLAN, "nh_ene_macro_id": NH_ETHERNET_WITH_TWO_VLAN_ENE_MACRO},
        {"nh_ene_code": NH_ENE_MACRO_ETH,           "nh_ene_macro_id": NH_ETHERNET_NO_VLAN_ENE_MACRO},
    ]
    for line in table_data:
        value = nh_macro_code_to_id_l6_static_table_value_t(l3_tx_local_vars_nh_encap_ene_macro_id=line["nh_ene_macro_id"])
        table.insert(NETWORK_CONTEXT, line["nh_ene_code"], value)


def config_nhlfe_type_mapping_static_table():
    table = nhlfe_type_mapping_static_table
    table_data = [

        #=========================================================================
        #   Key: nhlfe_type_e  |     Payload: nhlfe_type_attributes_t(encap_type, midpoint_nh_destination)
        #==============================================================================
        {"nhlfe_type": NHLFE_TYPE_MIDPOINT_SWAP, "encap_type": NPU_ENCAP_L3_HEADER_TYPE_ILM_LABEL,   "midpoint_nh_destination": DESTINATION_MASK_STAGE3_NH} ,
        {"nhlfe_type": NHLFE_TYPE_MIDPOINT_PHP,  "encap_type": NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH, "midpoint_nh_destination": DESTINATION_MASK_STAGE3_NH} ,
        {"nhlfe_type": NHLFE_TYPE_L2_ADJ_SID,    "encap_type": NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE_SR,  "midpoint_nh_destination": DESTINATION_MASK_DSP} ,
        {"nhlfe_type": NHLFE_TYPE_MIDPOINT_TUNNEL_PROTECTION_FULL,           "encap_type": NPU_ENCAP_L3_HEADER_TYPE_ILM_LABEL, "midpoint_nh_destination": DESTINATION_MASK_STAGE2_P_NH} ,
        {"nhlfe_type": NHLFE_TYPE_MIDPOINT_TUNNEL_PROTECTION_IMPLICIT_SWP,   "encap_type": NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH,   "midpoint_nh_destination": DESTINATION_MASK_STAGE2_P_NH} ,
        {"nhlfe_type": NHLFE_TYPE_MIDPOINT_TUNNEL_PROTECTION_IMPLICIT_MP,    "encap_type": NPU_ENCAP_L3_HEADER_TYPE_ILM_LABEL, "midpoint_nh_destination": DESTINATION_MASK_STAGE2_P_NH} ,
        {"nhlfe_type": NHLFE_TYPE_MIDPOINT_TUNNEL_PROTECTION_IMPLICIT_MP_SWP,"encap_type": NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH,   "midpoint_nh_destination": DESTINATION_MASK_STAGE2_P_NH} ,
        #========================================================================================================================================================
    ]

    for line in range(0,16):
        key = nhlfe_type_mapping_static_table_key_t(mpls_relay_local_vars_nhlfe_type=line)
        nhlfe_attributes = nhlfe_type_attributes_t(encap_type=NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE, midpoint_nh_destination_encoding=(DESTINATION_MASK_LPTS | (1<<5)))

        value = nhlfe_type_mapping_static_table_value_t(mpls_relay_local_vars_nhlfe_attributes=nhlfe_attributes)
        table.insert(NETWORK_CONTEXT, key, value)

    for line in table_data:
        key = nhlfe_type_mapping_static_table_key_t(mpls_relay_local_vars_nhlfe_type=line["nhlfe_type"])
        nhlfe_attributes = nhlfe_type_attributes_t(encap_type=line["encap_type"], midpoint_nh_destination_encoding=line["midpoint_nh_destination"])

        value = nhlfe_type_mapping_static_table_value_t(mpls_relay_local_vars_nhlfe_attributes=nhlfe_attributes)
        table.insert(NETWORK_CONTEXT, key, value)


def config_bfd_udp_port_map_static_table():
    table = bfd_udp_port_map_static_table
    table_data = [
        # IPv4 Single hop dest port
        {
            "key": {"skip_bfd_or_ttl_255": 0, "type": PROTOCOL_TYPE_IPV4, "protocol": IPV4_PROTOCOL_UDP, "next_header": DONT_CARE, "dst_port":  UDP_BFD_SINGLE_HOP_PORT},
            "mask": {"skip_bfd_or_ttl_255": ALL_1, "type": 0b01111, "protocol": ALL_1, "next_header": DONT_CARE, "dst_port": ALL_1},
            "payload": {"bfd_valid": 1, "macro_id": RX_HANDLE_BFD_AND_LPTS_OG_MACRO, "pl_inc": PL_INC_NONE},
        },

        # IPv4 Echo dest port
        {
            "key": {"skip_bfd_or_ttl_255": 0, "type": PROTOCOL_TYPE_IPV4, "protocol": IPV4_PROTOCOL_UDP, "next_header": DONT_CARE, "dst_port":  UDP_BFD_ECHO_PORT},
            "mask": {"skip_bfd_or_ttl_255": ALL_1, "type": 0b01111, "protocol": ALL_1, "next_header": DONT_CARE, "dst_port": ALL_1},
            "payload": {"bfd_valid": 1, "macro_id": RX_HANDLE_BFD_AND_LPTS_OG_MACRO, "pl_inc": PL_INC_NONE},
        },

        # IPv4 Multi hop dest port
        {
            "key": {"skip_bfd_or_ttl_255": 0, "type": PROTOCOL_TYPE_IPV4, "protocol": IPV4_PROTOCOL_UDP, "next_header": DONT_CARE, "dst_port":  UDP_BFD_MULTI_HOP_PORT},
            "mask": {"skip_bfd_or_ttl_255": ALL_1, "type": 0b01111, "protocol": ALL_1, "next_header": DONT_CARE, "dst_port": ALL_1},
            "payload": {"bfd_valid": 1, "macro_id": RX_HANDLE_BFD_AND_LPTS_OG_MACRO, "pl_inc": PL_INC_NONE},
        },

        # IPv4 Micro BFD dest port
        {
            "key": {"skip_bfd_or_ttl_255": 0, "type": PROTOCOL_TYPE_IPV4, "protocol": IPV4_PROTOCOL_UDP, "next_header": DONT_CARE, "dst_port":  UDP_BFD_MICRO_HOP_PORT},
            "mask": {"skip_bfd_or_ttl_255": ALL_1, "type": 0b01111, "protocol": ALL_1, "next_header": DONT_CARE, "dst_port": ALL_1},
            "payload": {"bfd_valid": 1, "macro_id": RX_HANDLE_BFD_AND_LPTS_OG_MACRO, "pl_inc": PL_INC_NONE},
        },

        # IPv6 Single hop dest port
        {
            "key": {"skip_bfd_or_ttl_255": 0, "type": PROTOCOL_TYPE_IPV6, "protocol": DONT_CARE, "next_header": IPV4_PROTOCOL_UDP, "dst_port":  UDP_BFD_SINGLE_HOP_PORT},
            "mask": {"skip_bfd_or_ttl_255": ALL_1, "type": 0b01111, "protocol": DONT_CARE, "next_header": ALL_1, "dst_port": ALL_1},
            "payload": {"bfd_valid": 1, "macro_id": RX_HANDLE_BFD_AND_LPTS_OG_MACRO, "pl_inc": PL_INC_NONE},
        },

        # IPv6 Echo dest port
        {
            "key": {"skip_bfd_or_ttl_255": 0, "type": PROTOCOL_TYPE_IPV6, "protocol": DONT_CARE, "next_header": IPV4_PROTOCOL_UDP, "dst_port":  UDP_BFD_ECHO_PORT},
            "mask": {"skip_bfd_or_ttl_255": ALL_1, "type": 0b01111, "protocol": DONT_CARE, "next_header": ALL_1, "dst_port": ALL_1},
            "payload": {"bfd_valid": 1, "macro_id": RX_HANDLE_BFD_AND_LPTS_OG_MACRO, "pl_inc": PL_INC_NONE},
        },

        # IPv6 Multi hop dest port
        {
            "key": {"skip_bfd_or_ttl_255": 0, "type": PROTOCOL_TYPE_IPV6, "protocol": DONT_CARE, "next_header": IPV4_PROTOCOL_UDP, "dst_port":  UDP_BFD_MULTI_HOP_PORT},
            "mask": {"skip_bfd_or_ttl_255": ALL_1, "type": 0b01111, "protocol": DONT_CARE, "next_header": ALL_1, "dst_port": ALL_1},
            "payload": {"bfd_valid": 1, "macro_id": RX_HANDLE_BFD_AND_LPTS_OG_MACRO, "pl_inc": PL_INC_NONE},
        },

        # IPv6 Micro BFD dest port
        {
            "key": {"skip_bfd_or_ttl_255": 0, "type": PROTOCOL_TYPE_IPV6, "protocol": DONT_CARE, "next_header": IPV4_PROTOCOL_UDP, "dst_port":  UDP_BFD_MICRO_HOP_PORT},
            "mask": {"skip_bfd_or_ttl_255": ALL_1, "type": 0b01111, "protocol": DONT_CARE, "next_header": ALL_1, "dst_port": ALL_1},
            "payload": {"bfd_valid": 1, "macro_id": RX_HANDLE_BFD_AND_LPTS_OG_MACRO, "pl_inc": PL_INC_NONE},
        },

        # Default entry
        {
            "key": {"skip_bfd_or_ttl_255": 0, "type": DONT_CARE, "protocol": DONT_CARE, "next_header": DONT_CARE, "dst_port":  DONT_CARE},
            "mask": {"skip_bfd_or_ttl_255": DONT_CARE, "type": DONT_CARE, "protocol": DONT_CARE, "next_header": DONT_CARE, "dst_port":  DONT_CARE},
            "payload": {"bfd_valid": 0, "macro_id": RX_LPTS_REDIRECT_MACRO, "pl_inc": PL_INC_NONE},
        },
    ]
    location = 0
    for line in table_data:
        key = bfd_udp_port_map_static_table_key_t(pd_redirect_stage_vars_skip_bfd_or_ttl_255=line["key"]["skip_bfd_or_ttl_255"],
                                                  packet_header_info_type=line["key"]["type"],
                                                  packet_ipv4_header_protocol=line["key"]["protocol"],
                                                  packet_ipv6_header_next_header=line["key"]["next_header"],
                                                  packet_header_1__udp_header_dst_port=line["key"]["dst_port"])
        mask = bfd_udp_port_map_static_table_key_t(pd_redirect_stage_vars_skip_bfd_or_ttl_255=line["mask"]["skip_bfd_or_ttl_255"],
                                                   packet_header_info_type=line["mask"]["type"],
                                                   packet_ipv4_header_protocol=line["mask"]["protocol"],
                                                   packet_ipv6_header_next_header=line["mask"]["next_header"],
                                                   packet_header_1__udp_header_dst_port=line["mask"]["dst_port"])
        value = bfd_udp_port_map_static_table_value_t(**line["payload"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


def    config_eve_byte_addition_static_table() :
    table = eve_byte_addition_static_table

    table_data = [
        #=============================================================================================================================================================================
        #       Key                                                                                                                             |           Payload                  |
        #=============================================================================================================================================================================
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_OTHER,         "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_NOP          , "padding_vars_eve_byte_addition" : 0x0},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_OTHER,         "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_REMARK       , "padding_vars_eve_byte_addition" : 0x0},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_OTHER,         "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_POP_1        , "padding_vars_eve_byte_addition" : 0x3ffc},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_OTHER,         "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_TRANSLATE_1_1, "padding_vars_eve_byte_addition" : 0x0},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_OTHER,         "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_PUSH_1       , "padding_vars_eve_byte_addition" : 0x4},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_OTHER,         "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_POP_2        , "padding_vars_eve_byte_addition" : 0x3ff8},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_OTHER,         "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_TRANSLATE_2_1, "padding_vars_eve_byte_addition" : 0x3ffc},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_OTHER,         "padding_vars_eve_16_14_" : 7                                        , "padding_vars_eve_byte_addition" : 0x0},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_TRANSLATE_2_2, "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_NOP          , "padding_vars_eve_byte_addition" : 0x0},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_TRANSLATE_2_2, "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_REMARK       , "padding_vars_eve_byte_addition" : 0x0},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_TRANSLATE_2_2, "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_POP_1        , "padding_vars_eve_byte_addition" : 0x0},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_TRANSLATE_2_2, "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_TRANSLATE_1_1, "padding_vars_eve_byte_addition" : 0x0},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_TRANSLATE_2_2, "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_PUSH_1       , "padding_vars_eve_byte_addition" : 0x0},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_TRANSLATE_2_2, "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_POP_2        , "padding_vars_eve_byte_addition" : 0x0},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_TRANSLATE_2_2, "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_TRANSLATE_2_1, "padding_vars_eve_byte_addition" : 0x0},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_TRANSLATE_2_2, "padding_vars_eve_16_14_" : 7                                        , "padding_vars_eve_byte_addition" : 0x0},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_TRANSLATE_1_2, "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_NOP          , "padding_vars_eve_byte_addition" : 0x4},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_TRANSLATE_1_2, "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_REMARK       , "padding_vars_eve_byte_addition" : 0x4},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_TRANSLATE_1_2, "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_POP_1        , "padding_vars_eve_byte_addition" : 0x4},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_TRANSLATE_1_2, "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_TRANSLATE_1_1, "padding_vars_eve_byte_addition" : 0x4},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_TRANSLATE_1_2, "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_PUSH_1       , "padding_vars_eve_byte_addition" : 0x4},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_TRANSLATE_1_2, "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_POP_2        , "padding_vars_eve_byte_addition" : 0x4},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_TRANSLATE_1_2, "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_TRANSLATE_2_1, "padding_vars_eve_byte_addition" : 0x4},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_TRANSLATE_1_2, "padding_vars_eve_16_14_" : 7                                        , "padding_vars_eve_byte_addition" : 0x4},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_PUSH_2,        "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_NOP          , "padding_vars_eve_byte_addition" : 0x8},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_PUSH_2,        "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_REMARK       , "padding_vars_eve_byte_addition" : 0x8},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_PUSH_2,        "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_POP_1        , "padding_vars_eve_byte_addition" : 0x8},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_PUSH_2,        "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_TRANSLATE_1_1, "padding_vars_eve_byte_addition" : 0x8},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_PUSH_2,        "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_PUSH_1       , "padding_vars_eve_byte_addition" : 0x8},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_PUSH_2,        "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_POP_2        , "padding_vars_eve_byte_addition" : 0x8},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_PUSH_2,        "padding_vars_eve_16_14_" : VLAN_EDIT_COMMAND_SECONDARY_TRANSLATE_2_1, "padding_vars_eve_byte_addition" : 0x8},
        {"padding_vars_eve_27_26_" : VLAN_EDIT_COMMAND_MAIN_PUSH_2,        "padding_vars_eve_16_14_" : 7                                        , "padding_vars_eve_byte_addition" : 0x8}
    ]

    for line in table_data :
        key = eve_byte_addition_static_table_key_t(
            padding_vars_eve_16_14_ = line['padding_vars_eve_16_14_'],
            padding_vars_eve_27_26_ = line['padding_vars_eve_27_26_'])
        value = eve_byte_addition_static_table_value_t (
            padding_vars_eve_byte_addition = line['padding_vars_eve_byte_addition'] )
        table.insert(NETWORK_CONTEXT, key, value)


def    config_ene_byte_addition_static_table() :
    table=ene_byte_addition_static_table
    table_data = [
        #---------------+----------------------------------------------+-----------------------------------------+-----------------------------------------+-----------------------------------------#
        #               |  pd_first_ene_macro                          |     pd_ene_macro_ids_0                  |   pd_ene_macro_ids_1                    |    pd_ene_macro_ids_2                   #
        #---------------+----------------------------------------------+-----------------------------------------+-----------------------------------------+-----------------------------------------#
        {
            "key":     {"first"  : NH_ETHERNET_NO_VLAN_ENE_MACRO,       "0" : 0,                                  "1" : 0,                                   "2" : 0},
            "mask":    {"first"  : ALL_1,                               "0" : DONT_CARE,                          "1" : DONT_CARE,                           "2" : DONT_CARE},
            "payload": {"padding_vars_ene_byte_addition" : 14},
        },
        {
            "key":     {"first"  : NH_ETHERNET_WITH_ONE_VLAN_ENE_MACRO, "0" : 0,                                  "1" : 0,                                   "2" : 0},
            "mask":    {"first"  : ALL_1,                               "0" : DONT_CARE,                          "1" : DONT_CARE,                           "2" : DONT_CARE},
            "payload": {"padding_vars_ene_byte_addition" : 18},
        },
        {
            "key":     {"first"  : NH_ETHERNET_WITH_TWO_VLAN_ENE_MACRO, "0" : 0,                                  "1" : 0,                                   "2" : 0},
            "mask":    {"first"  : ALL_1,                               "0" : DONT_CARE,                          "1" : DONT_CARE,                           "2" : DONT_CARE},
            "payload": {"padding_vars_ene_byte_addition" : 22},
        },
        {
            "key":     {"first"  : 0,                                   "0" : NH_ETHERNET_NO_VLAN_ENE_MACRO,      "1" : 0,                                   "2" : 0},
            "mask":    {"first"  : DONT_CARE,                           "0" : ALL_1,                              "1" : DONT_CARE,                           "2" : DONT_CARE},
            "payload": {"padding_vars_ene_byte_addition" : 14},
        },
        {
            "key":     {"first"  : 0,                                   "0" : NH_ETHERNET_WITH_ONE_VLAN_ENE_MACRO,"1" : 0,                                   "2" : 0},
            "mask":    {"first"  : DONT_CARE,                           "0" : ALL_1,                              "1" : DONT_CARE,                           "2" : DONT_CARE},
            "payload": {"padding_vars_ene_byte_addition" : 18},
        },
        {
            "key":     {"first"  : 0,                                   "0" : NH_ETHERNET_WITH_TWO_VLAN_ENE_MACRO,"1" : 0,                                   "2" : 0},
            "mask":    {"first"  : DONT_CARE,                           "0" : ALL_1,                              "1" : DONT_CARE,                           "2" : DONT_CARE},
            "payload": {"padding_vars_ene_byte_addition" : 22},
        },
        {
            "key":     {"first"  : 0,                                   "0" : 0,                                  "1" : NH_ETHERNET_NO_VLAN_ENE_MACRO,       "2" : 0},
            "mask":    {"first"  : DONT_CARE,                           "0" : DONT_CARE,                          "1" : ALL_1,                               "2" : DONT_CARE},
            "payload": {"padding_vars_ene_byte_addition" : 14},
        },
        {
            "key":     {"first"  : 0,                                   "0" : 0,                                  "1" : NH_ETHERNET_WITH_ONE_VLAN_ENE_MACRO, "2" : 0},
            "mask":    {"first"  : DONT_CARE,                           "0" : DONT_CARE,                          "1" : ALL_1,                               "2" : DONT_CARE},
            "payload": {"padding_vars_ene_byte_addition" : 18},
        },
        {
            "key":     {"first"  : 0,                                   "0" : 0,                                  "1" : NH_ETHERNET_WITH_TWO_VLAN_ENE_MACRO, "2" : 0},
            "mask":    {"first"  : DONT_CARE,                           "0" : DONT_CARE,                          "1" : ALL_1,                               "2" : DONT_CARE},
            "payload": {"padding_vars_ene_byte_addition" : 22},
        },
        {
            "key":     {"first"  : 0,                                   "0" : 0,                                  "1" : 0,                                   "2" : NH_ETHERNET_NO_VLAN_ENE_MACRO},
            "mask":    {"first"  : DONT_CARE,                           "0" : DONT_CARE,                          "1" : DONT_CARE,                           "2" : ALL_1},
            "payload": {"padding_vars_ene_byte_addition" : 14},
        },
        {
            "key":     {"first"  : 0,                                   "0" : 0,                                  "1" : 0,                                   "2" : NH_ETHERNET_WITH_ONE_VLAN_ENE_MACRO},
            "mask":    {"first"  : DONT_CARE,                           "0" : DONT_CARE,                          "1" : DONT_CARE,                           "2" : ALL_1},
            "payload": {"padding_vars_ene_byte_addition" : 18},
        },
        {
            "key":     {"first"  : 0,                                   "0" : 0,                                  "1" : 0,                                   "2" : NH_ETHERNET_WITH_TWO_VLAN_ENE_MACRO},
            "mask":    {"first"  : DONT_CARE,                           "0" : DONT_CARE,                          "1" : DONT_CARE,                           "2" : ALL_1},
            "payload": {"padding_vars_ene_byte_addition" : 22},
        },
        {
            "key":     {"first"  : 0,                                   "0" : 0,                                  "1" : 0,                                   "2" : 0},
            "mask":    {"first"  : DONT_CARE,                           "0" : DONT_CARE,                          "1" : DONT_CARE,                           "2" : DONT_CARE},
            "payload": {"padding_vars_ene_byte_addition" : 0},
        },
    ]
    ENE_MACRO_ID_SIZE = 8
    location = 0
    for line in table_data:
        key = ene_byte_addition_static_table_key_t(
            pd_first_ene_macro  = line["key"]["first"],
            pd_ene_macro_ids_0_ = line["key"]["0"],
            pd_ene_macro_ids_1_ = line["key"]["1"],
            pd_ene_macro_ids_2_ = line["key"]["2"])
        mask = ene_byte_addition_static_table_key_t(
            pd_first_ene_macro  = line["mask"]["first"],
            pd_ene_macro_ids_0_ = line["mask"]["0"],
            pd_ene_macro_ids_1_ = line["mask"]["1"],
            pd_ene_macro_ids_2_ = line["mask"]["2"])
        value = ene_byte_addition_static_table_value_t(
            padding_vars_ene_byte_addition = line ["payload"]["padding_vars_ene_byte_addition"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1

# +-----------------------+------------------+----------------------------+----+----------+------------+
# | next_proto_type       |   l2_lp_type     | ipv4_ipv6_init_rtf_stage   |    |   pl_inc |   macro_id |
# |-----------------------+------------------+----------------------------+----+----------+------------|
# |                       |L2_LP_TYPE_OVERLAY| (4, 'mask=0b1100')         | >  |        3 | NETWORK_RX_IP_OBJECT_GROUPS_MACRO|
# |                       |L2_LP_TYPE_OVERLAY| (8, 'mask=0b1100')         | >  |        3 |NETWORK_RX_ETH_RTF_MACRO|
# |                       |L2_LP_TYPE_OVERLAY| (12, 'mask=0b1100')        | >  |        3 |NETWORK_RX_IPV4_RTF_MACRO|
# |                       |L2_LP_TYPE_OVERLAY| (0, 'mask=0b0000')         | >  |        1 |NETWORK_RX_IP_AF_AND_FORWARDING_MACRO|
# | (IPV4, 'mask=0b1111') |L2_LP_TYPE_NPP    |                            | >  |        1 |NETWORK_RX_IP_AF_AND_TERMINATION_MACRO|
# | (IPV6, 'mask=0b1111') |L2_LP_TYPE_NPP    |                            | >  |        1 |NETWORK_RX_IP_AF_AND_TERMINATION_MACRO|
# | MPLS                  |L2_LP_TYPE_NPP    |                            | >  |        1 |NETWORK_RX_MPLS_AF_AND_TERMINATION_MACRO|
# +-----------------------+--------------+----------------------------+----+----------+------------+


def config_mac_termination_next_macro_static_table():
    table_config = TcamTableConfig("mac_termination_next_macro_static_table")

    table_data = [
        {"key": ["next_proto_type"                    , "l2_lp_type"      , "ipv4_ipv6_init_rtf_stage"                          ], "value": ["pl_inc"   , "macro_id"]},
        # VXLAN/NVGRE Routing cases
        {"key": [_DONT_CARE                           , L2_LP_TYPE_OVERLAY, Key(INIT_RTF_OG        <<2 | DONT_CARE, mask=0b1100)], "value": [PL_DEC_ONCE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [_DONT_CARE                           , L2_LP_TYPE_OVERLAY, Key(INIT_RTF_PRE_FWD_L2<<2 | DONT_CARE, mask=0b1100)], "value": [PL_DEC_ONCE, NETWORK_RX_ETH_RTF_MACRO         ]},
        {"key": [_DONT_CARE                           , L2_LP_TYPE_OVERLAY, Key(INIT_RTF_PRE_FWD_L3<<2 | DONT_CARE, mask=0b1100)], "value": [PL_DEC_ONCE, NETWORK_RX_IPV4_RTF_MACRO        ]},
        # if no RTF is needed on the outer header
        {"key": [_DONT_CARE                           , L2_LP_TYPE_OVERLAY, _DONT_CARE], "value": [PL_INC_ONCE, NETWORK_RX_IP_AF_AND_FORWARDING_MACRO        ]},
        #
        {"key": [Key(PROTOCOL_TYPE_IPV4, mask=0b01111), L2_LP_TYPE_NPP    , _DONT_CARE                                          ], "value": [PL_INC_ONCE, NETWORK_RX_IP_AF_AND_TERMINATION_MACRO]},
        {"key": [Key(PROTOCOL_TYPE_IPV6, mask=0b01111), L2_LP_TYPE_NPP    , _DONT_CARE                                          ], "value": [PL_INC_ONCE, NETWORK_RX_IP_AF_AND_TERMINATION_MACRO]},
        {"key": [PROTOCOL_TYPE_MPLS                   , L2_LP_TYPE_NPP    , _DONT_CARE                                          ], "value": [PL_INC_ONCE, NETWORK_RX_MPLS_AF_AND_TERMINATION_MACRO]},
    ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


# Send to padding macro all packets less than 63 ?
# If outgoing packet is 59 or less, padding needs to happen
# However since routing is occuring at least 14 bytes will be added to the packet
# Also pd.pkt_size could be off by 17 bytes because of fabric related issues
# So any packet less than 59 - 14 + 17 needs to be padded.
# which is 62. But to make the TCAM programming easy, the padding comparison happens including length 63


def    config_pad_mtu_inj_check_static_table() :
    table= pad_mtu_inj_check_static_table
    table_data = [
        {
            "key":      {"tx_npu_header_is_inject_up" : 0x1,        "l3_tx_local_vars_fwd_pkt_size"      : 0x0000},
            "mask":     {"tx_npu_header_is_inject_up" : ALL_1,      "l3_tx_local_vars_fwd_pkt_size"      : DONT_CARE},
            "payload":  {"action"    : "set_macro", "pl_inc" : PL_INC_NONE, "macro_id" : TX_INJECT_MACRO},
        },
        {
            "key":      {"tx_npu_header_is_inject_up" : 0x0,        "l3_tx_local_vars_fwd_pkt_size"      : 0x0000},    # 0 .. 63
            "mask":     {"tx_npu_header_is_inject_up" : DONT_CARE,  "l3_tx_local_vars_fwd_pkt_size"      : 0xFFC0},
            "payload":  {"action"    : "set_macro", "pl_inc" : PL_INC_NONE, "macro_id" : NETWORK_TX_PAD_OR_MTU_MACRO},
        },
        {
            "key":      {"tx_npu_header_is_inject_up" : 0x0,        "l3_tx_local_vars_fwd_pkt_size"      : 0x0000},    # 64 .. 511
            "mask":     {"tx_npu_header_is_inject_up" : DONT_CARE,  "l3_tx_local_vars_fwd_pkt_size"      : 0xFE00},
            "payload":  {"action"    : "default"},
        },
        {
            "key":      {"tx_npu_header_is_inject_up" : 0x0,        "l3_tx_local_vars_fwd_pkt_size"      : 0x0000},    # 512 .. 767
            "mask":     {"tx_npu_header_is_inject_up" : DONT_CARE,  "l3_tx_local_vars_fwd_pkt_size"      : 0xFD00},
            "payload":  {"action"    : "default"},
        },
        {
            "key":      {"tx_npu_header_is_inject_up" : 0x0,        "l3_tx_local_vars_fwd_pkt_size"      : 0x0000},    # 768 .. 1023
            "mask":     {"tx_npu_header_is_inject_up" : DONT_CARE,  "l3_tx_local_vars_fwd_pkt_size"      : 0xFC00},
            "payload":  {"action"    : "default"},
        },
        {
            "key":      {"tx_npu_header_is_inject_up" : 0x0,        "l3_tx_local_vars_fwd_pkt_size"      : 0x0000},    # 1024 - 1279
            "mask":     {"tx_npu_header_is_inject_up" : DONT_CARE,  "l3_tx_local_vars_fwd_pkt_size"      : 0xFB00},
            "payload":  {"action"    : "default"},
        },
        {
            "key":      {"tx_npu_header_is_inject_up" : 0x0,        "l3_tx_local_vars_fwd_pkt_size"      : 0x0000},    # all other cases
            "mask":     {"tx_npu_header_is_inject_up" : DONT_CARE,  "l3_tx_local_vars_fwd_pkt_size"      : 0x0000},
            "payload":  {"action"    : "set_macro", "pl_inc" : PL_INC_NONE, "macro_id" : NETWORK_TX_PAD_OR_MTU_MACRO},
        },
    ]
    location = 0
    for line in table_data:
        key = pad_mtu_inj_check_static_table_key_t(
            l3_tx_local_vars_fwd_pkt_size  = line["key"]["l3_tx_local_vars_fwd_pkt_size"],
            tx_npu_header_is_inject_up     = line["key"]["tx_npu_header_is_inject_up"])
        mask = pad_mtu_inj_check_static_table_key_t(
            l3_tx_local_vars_fwd_pkt_size  = line["mask"]["l3_tx_local_vars_fwd_pkt_size"],
            tx_npu_header_is_inject_up     = line["mask"]["tx_npu_header_is_inject_up"])

        if ( line["payload"]["action"] == "set_macro" ) :
            value = pad_mtu_inj_check_static_table_value_t(
                action = 0x1, pl_inc = line["payload"]["pl_inc"], macro_id = line["payload"]["macro_id"])
        else :
            value = pad_mtu_inj_check_static_table_value_t( action = 0x0)
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


def config_pfc_vector_static_table():
    table = pfc_vector_static_table
    table_data = [
        {
            "tc": 0x0, "vector" : 0x1
        },
        {
            "tc": 0x1, "vector" : 0x2
        },
        {
            "tc": 0x2, "vector" : 0x4
        },
        {
            "tc": 0x3, "vector" : 0x8
        },
        {
            "tc": 0x4, "vector" : 0x10
        },
        {
            "tc": 0x5, "vector" : 0x20
        },
        {
            "tc": 0x6, "vector" : 0x40
        },
        {
            "tc": 0x7, "vector" : 0x80
        }
    ]
    for line in table_data:
        key = pfc_vector_static_table_key_t(
            tc          = line["tc"])
        value = pfc_vector_static_table_value_t(
            pd_pd_npu_host_receive_fields_pfc_priority_table_vector = line["vector"])
        table.insert(HOST_CONTEXT, key, value)


# |  proto  |  label_present  |     GRE Proto         |
# |   v4    |       0         |   ETHER_TYPE_IPV4     |
# |   v6    |       0         |   ETHER_TYPE_IPV6     |
# |   v4    |       1         |   ETHER_TYPE_MPLS_UC  |
# |   v6    |       1         |   ETHER_TYPE_MPLS_UC  |


def config_gre_proto_static_table():
    table = gre_proto_static_table
    table_data = [
        {"proto": 0,    "label_present": 0,    "gre_proto": ETHER_TYPE_IPV4},
        {"proto": 1,    "label_present": 0,    "gre_proto": ETHER_TYPE_IPV6},
        {"proto": 0,    "label_present": 1,    "gre_proto": ETHER_TYPE_MPLS_UC},
        {"proto": 1,    "label_present": 1,    "gre_proto": ETHER_TYPE_MPLS_UC},
    ]

    for line in table_data:
        key = gre_proto_static_table_key_t(proto=line["proto"],
                                           label_present=line["label_present"])
        value = gre_proto_static_table_value_t( gre_proto=(line["gre_proto"]))
        table.insert(NETWORK_CONTEXT, key, value)


# +---------------------+---------------------+-------------------------------+
# | ipv4_first_fragment | ipv6_first_fragment |             action            |
# |          0          |          0          |  2'b00 v6 non-first-fragment  |
# |          0          |          1          |  2'b01 v6 first-fragment      |
# |          1          |          0          |  2'b10 v4 non-first-fragment  |
# |          1          |          1          |  2'b11 v4 first-fragment      |
# +---------------------+---------------------+-------------------------------+
def config_l2_lpts_ip_fragment_static_table():
    table = l2_lpts_ip_fragment_static_table
    table_data = [
        {"ipv4_not_first_fragment": 0,  "ipv6_not_first_fragment": 0,  "ip_fragment": 0b00},
        {"ipv4_not_first_fragment": 0,  "ipv6_not_first_fragment": 1,  "ip_fragment": 0b01},
        {"ipv4_not_first_fragment": 1,  "ipv6_not_first_fragment": 0,  "ip_fragment": 0b10},
        {"ipv4_not_first_fragment": 1,  "ipv6_not_first_fragment": 1,  "ip_fragment": 0b11},
    ]
    for line in table_data:
        key = l2_lpts_ip_fragment_static_table_key_t(ipv4_not_first_fragment=line["ipv4_not_first_fragment"],
                                                     ipv6_not_first_fragment=line["ipv6_not_first_fragment"])
        value = l2_lpts_ip_fragment_static_table_value_t(ip_fragment=line["ip_fragment"])
        table.insert(NETWORK_CONTEXT, key, value)


def config_inject_down_select_ene_static_table():
    table = inject_down_select_ene_static_table
    table_data = [
        {
            "key": {"dsp_is_dma": 1,     "fwd_hdr": FWD_HEADER_TYPE_INJECT_DOWN, "inj_down": INJECT_DOWN_ENCAP_TYPE_TO_DMA, "pkt_size_4lsb": 0b1000},
            "mask":{"dsp_is_dma": ALL_1, "fwd_hdr": ALL_1,                       "inj_down": ALL_1,                         "pkt_size_4lsb": 0b1111},
            "payload": {"next_macro": ENE_DMA_16BYTES_HEADER_MACRO, "dma_decap_header_type": 0x10},
        },
        {
            "key": {"dsp_is_dma": 1,     "fwd_hdr": FWD_HEADER_TYPE_INJECT_DOWN, "inj_down": INJECT_DOWN_ENCAP_TYPE_TO_DMA, "pkt_size_4lsb": 0b0000},
            "mask":{"dsp_is_dma": ALL_1, "fwd_hdr": ALL_1,                       "inj_down": ALL_1,                         "pkt_size_4lsb": 0b1111},
            "payload": {"next_macro": ENE_DMA_8BYTES_HEADER_MACRO, "dma_decap_header_type": 0x8},
        },
        {
            "key": {"dsp_is_dma": 1,     "fwd_hdr": FWD_HEADER_TYPE_INJECT_DOWN, "inj_down": INJECT_DOWN_ENCAP_TYPE_TO_DMA, "pkt_size_4lsb": 0b1000},
            "mask":{"dsp_is_dma": ALL_1, "fwd_hdr": ALL_1,                       "inj_down": ALL_1,                         "pkt_size_4lsb": 0b1000},
            "payload": {"next_macro": ENE_DMA_8BYTES_HEADER_MACRO, "dma_decap_header_type": 0x8},
        },
        {
            "key": {"dsp_is_dma": 1,     "fwd_hdr": FWD_HEADER_TYPE_INJECT_DOWN, "inj_down": INJECT_DOWN_ENCAP_TYPE_TO_DMA, "pkt_size_4lsb": 0b0000},
            "mask":{"dsp_is_dma": ALL_1, "fwd_hdr": ALL_1,                       "inj_down": ALL_1,                         "pkt_size_4lsb": 0b1000},
            "payload": {"next_macro": ENE_DMA_16BYTES_HEADER_MACRO, "dma_decap_header_type": 0x10},
        },
        {
            "key": {"dsp_is_dma": DONT_CARE, "fwd_hdr": DONT_CARE, "inj_down": DONT_CARE, "pkt_size_4lsb": 0b0000},
            "mask":{"dsp_is_dma": DONT_CARE, "fwd_hdr": DONT_CARE, "inj_down": DONT_CARE, "pkt_size_4lsb": 0b0000},
            "payload": {"next_macro": ENE_NOP_MACRO, "dma_decap_header_type": 0x0},
        },
    ]

    location = 0
    for line in table_data:
        key = inject_down_select_ene_static_table_key_t(dsp_is_dma=line["key"]["dsp_is_dma"],
                                                        fwd_header_type=line["key"]["fwd_hdr"],
                                                        inject_down_encap=line["key"]["inj_down"],
                                                        pkt_size_4lsb=line["key"]["pkt_size_4lsb"])
        mask = inject_down_select_ene_static_table_key_t(dsp_is_dma=line["mask"]["dsp_is_dma"],
                                                         fwd_header_type=line["mask"]["fwd_hdr"],
                                                         inject_down_encap=line["mask"]["inj_down"],
                                                         pkt_size_4lsb=line["mask"]["pkt_size_4lsb"])
        value = inject_down_select_ene_static_table_value_t(line["payload"]["next_macro"],
                                                            line["payload"]["dma_decap_header_type"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1

# 1. OOB, Mgmt Relay IPC Packets are always sent from Ingress Switch to Egress Switch with Inject Down Header
#    and 8 bits of MAC DA prefix[7:0] as 0xFF. ipc_trap is set and those packets are punted to punt destination.
# 2. Network Control Packets like OSPF, BGP, CDP etc packets with known egress switch destination are sent from
#    Ingres Switch CPU to Egress Switch data port with Inject Down Header and 8 bits of MAC DA as other than 0xFF.
#    In this case, packets are processed as regular Inject Down packet and packets are sent to the destination
#    which are specified in the Inject Down header.
# 3. Network control packets like OSPF, BGP, CDP etc packets are receiving in the ingress standby switch data port are
#    processed in the ingress switch and those packets are sent to ingress switch with Punt Header.
#    In this case, these packets are processed in the egress active switch and are sent to CPU directly without setting any traps.
# 4. Any other control packets like ISIS, LACP etc received on the SVL port, protocol_trap is set and these packets are send to punt destination.
# 5. Any packets received with SVL ethernet type packets are processed as data packets.

#|type                | mac_da[7:0] | ipc_trap | protocol_trap |  macro                                  |  pl_inc
#|PROTOCOL_TYPE_INJECT|    0xFF     |    1     |      0        | rx_redirect_macro                       |  PL_INC_NONE
#|PROTOCOL_TYPE_INJECT|    *        |    0     |      0        | rx_inject_macro                         |  PL_INC_NONE
#|PROTOCOL_TYPE_PUNT  |    *        |    0     |      0        | outbound_mirror_rx_macro                |  PL_INC_NONE
#|PROTOCOL_TYPE_SVL   |    *        |    0     |      0        | npu_rx_nop_fwd_macro                    |  PL_INC_NONE
#| **                 |    *        |    0     |      1        | rx_redirect_macro                       |  PL_INC_NONE


def config_svl_next_macro_static_table():
    table = svl_next_macro_static_table
    table_data = [
        {
            "key":  {"type": PROTOCOL_TYPE_INJECT, "mac_da_prefix": 0xFF},
            "mask": {"type": ALL_1, "mac_da_prefix": ALL_1},
            "payload": {"ipc_trap": 0x1, "protocol_trap": 0x0, "pl_inc": PL_INC_NONE, "macro_id": RX_REDIRECT_MACRO},
        },
        {
            "key":  {"type": PROTOCOL_TYPE_INJECT, "mac_da_prefix": DONT_CARE},
            "mask": {"type": ALL_1, "mac_da_prefix": DONT_CARE},
            "payload": {"ipc_trap": 0x0, "protocol_trap": 0x0, "pl_inc": PL_INC_NONE, "macro_id": RX_INJECT_MACRO },
        },
        {
            "key":  {"type": PROTOCOL_TYPE_PUNT, "mac_da_prefix": DONT_CARE},
            "mask": {"type": ALL_1, "mac_da_prefix": DONT_CARE},
            "payload": {"ipc_trap": 0x0, "protocol_trap": 0x0, "pl_inc": PL_INC_NONE, "macro_id": OUTBOUND_MIRROR_RX_MACRO},
        },
        {
            "key":  {"type": PROTOCOL_TYPE_SVL, "mac_da_prefix": DONT_CARE},
            "mask": {"type": ALL_1, "mac_da_prefix": DONT_CARE},
            "payload": {"ipc_trap": 0x0, "protocol_trap": 0x0, "pl_inc": PL_INC_NONE, "macro_id": NPU_RX_NOP_FWD_MACRO},
        },
        {
            "key":  {"type": DONT_CARE, "mac_da_prefix": DONT_CARE},
            "mask": {"type": DONT_CARE, "mac_da_prefix": DONT_CARE},
            "payload": {"ipc_trap": 0x0, "protocol_trap": 0x1, "pl_inc": PL_INC_NONE, "macro_id": RX_REDIRECT_MACRO},
        },
    ]
    location = 0
    for line in table_data:
        key = svl_next_macro_static_table_key_t(type=line["key"]["type"],
                                                mac_da_prefix=line["key"]["mac_da_prefix"])
        mask = svl_next_macro_static_table_key_t(type=line["mask"]["type"],
                                                 mac_da_prefix=line["key"]["mac_da_prefix"])
        value = svl_next_macro_static_table_value_t(ipc_trap=line["payload"]["ipc_trap"],
                                                    protocol_trap=line["payload"]["protocol_trap"],
                                                    pl_inc=line["payload"]["pl_inc"],
                                                    macro_id=line["payload"]["macro_id"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


def config_is_pacific_b1_static_table():
    table = is_pacific_b1_static_table
    key   = 0
    value = is_pacific_b1_static_table_value_t(0)
    table.insert(NETWORK_CONTEXT, key, value)


# current_hdr_type|	next_hdr_type	|pd_tunnel_ipv4_next_stage|	pd_tunnel_ipv6_next_stage|	next_stage	  | fwd_layer	| rtf_stage	| acl_outer	     |   PL_inc|	macro_id
#-----------------|-----------------|-------------------------|--------------------------|----------------|-------------| ----------| ---------------|---------|----------------
# dont_care	  |  dont_care	    |  dont_care	          | dont_care               |	og	          | ip_FWD      | pre_fwd	|    1	         |  none   |	OG_macro
# dont_care	  |  dont_care	    |  dont_care	          | dont_care               |	pre_fwd_l2	  | ip_FWD      | pre_fwd	|    1	         |  none   |	eth_rtf
# 4	              |  dont_care	    |  dont_care	          | dont_care               |	pre_fwd_l3	  | ip_FWD      | pre_fwd	|    1	         |  none   |	ipv4_rtf
# 6	              |  dont_care	    |  dont_care	          | dont_care               |	pre_fwd_l3	  | ip_FWD      | pre_fwd	|    1	         |  none   |	ipv6_rtf
# dont_care	      |      4	        |  OG	                  |   dont_care	             |  dont_care     |  ip_FWD	    | pre_fwd	|        1	     |   once  |OG_macro
# dont_care	      |      4	        |  pre_fwd_l2	          |   dont_care	             |  dont_care     |  ip_FWD	    | pre_fwd	|        1	     |   once  |eth_macro
# dont_care	      |      4	        |  pre_fwd_l3	          |   dont_care	             |  dont_care     |  ip_FWD	    | pre_fwd	|        1	     |   once  |ipv4_rtf
# dont_care	      |      6	        |  dont_care	          |   OG       	             |  dont_care     |  ip_FWD	    | pre_fwd	|        1	     |   once  |OG_macro
# dont_care	      |      6	        |  dont_care	          |   pre_fwd_l2	         |  dont_care     |  ip_FWD	    | pre_fwd	|        1	     |   once  |eth_macro
# dont_care	      |      6	        |  dont_care	          |   pre_fwd_l3	         |  dont_care     |  ip_FWD	    | pre_fwd	|        1	     |   once  |ipv6_rtf
# dont_care	      |      dont_care	|  dont_care	          |   dont_care	             |  dont_care     |  ip_fwd	    | pre_fwd	|        1	     |   once  |ip_FWD
# dont_care	      |      dont_care	|  dont_care	          |   dont_care	             |     og	      | dont_care	| dont_care | 	dont_care	 |   none  |OG_macro
# dont_care	      |      dont_care	|  dont_care	          |   dont_care	             |     pre_fwd_l2 |	dont_care	| pre_fwd	|     dont_care  |	none   |eth_rtf
# 4	              |      dont_care	|  dont_care	          |   dont_care	             |     pre_fwd_l3 |	dont_care	| pre_fwd	|     dont_care  |	none   |ipv4_rtf
# 6	              |      dont_care	|  dont_care	          |   dont_care	             |     pre_fwd_l3 |	dont_care	| pre_fwd	|     dont_care  |	none   |ipv6_rtf
# dont_crae	      |      dont_care	|  dont_care	          |   dont_care	             |     dont_care  |	IP_FWD	    | pre_fwd	|     dont_care  |	none   |IP_FWD
# 4	              |      dont_care	|  dont_care	          |   dont_care	             |     dont_care  |	MAC_FWD	    | pre_fwd	|     dont_care  |	-1	   | mac_FWD
# 6	              |      dont_care	|  dont_care	          |   dont_care	             |     dont_care  |	MAC_FWD	    | pre_fwd	|     dont_care  |	-1	   | mac_FWD
# dont_care	      |      dont_care	|  dont_care	          |   dont_care	             |     dont_care  |	MAC_FWD	    | pre_fwd	|     dont_care  |	none   |mac_FWD
# dont_care	      |      dont_care	|  dont_care	          |   dont_care	             |     post_fwd_l2| dont_care	| post_fwd  |   dont_care	 |   none  |eth_macro
# 4	              |      dont_care	|  dont_care	          |   dont_care	             |     post_fwd_l3| dont_care	| post_fwd  |   dont_care	 |   none  |ipv4_rtf
# 6	              |      dont_care	|  dont_care	          |   dont_care	             |     post_fwd_l3| dont_care	| post_fwd  |   dont_care	 |   none  |ipv6_rtf
# dont_care	      |      dont_care	|  dont_care	          |   dont_care	             |     dont_care  |	IP_FWD	    | post_fwd  |   dont_care	 |   none  |resolution_macro
# 4	              |      dont_care	|  dont_care	          |   dont_care	             |     dont_care  |	MAC_FWD	    | post_fwd  |   dont_care	 |   -1    |  resolution_macro
# 6	              |      dont_care	|  dont_care	          |   dont_care	             |     dont_care  |	MAC_FWD	    | post_fwd  |   dont_care	 |   -1    |  resolution_macro
# dont_care	      |      dont_care	|  dont_care	          |   dont_care	             |     dont_care  |	MAC_FWD	    | post_fwd  |   dont_care	 |   none  |resolution_macro
# dont_care	      |      dont_care	|  dont_care	          |   dont_care	             |     rx_done_l2 |	dont_care	| rx_done	|     dont_care  |	none   |eth_macro
# 4	              |      dont_care	|  dont_care	          |   dont_care	             |     rx_done_l3 |	dont_care	| rx_done	|     dont_care  |	none   |ipv4_rtf
# 6	              |      dont_care	|  dont_care	          |   dont_care	             |     rx_done_l3 |	dont_care	| rx_done	|     dont_care  |	none   |ipv6_rtf
# dont_care	      |      dont_care	|  dont_care	          |   dont_care	             |     dont_care  |	dont_care	| rx_done	|     dont_care  |	none   |fwd_done
def config_rtf_next_macro_static_table():
    table_config = TcamTableConfig("rtf_next_macro_static_table")

    # curr_and_next_prot_type : current_proto_type, next_proto_type
    curr_is_dont_care__next_is_dont_care = Key(DONT_CARE<<4                 | DONT_CARE, mask=0b00000000)
    curr_is_v4__next_is_dont_care        = Key(PROTOCOL_TYPE_IPV4_SUFFIX<<4 | DONT_CARE, mask=0b11110000)
    curr_is_v6__next_is_dont_care        = Key(PROTOCOL_TYPE_IPV6_SUFFIX<<4 | DONT_CARE, mask=0b11110000)
    curr_is_dont_care__next_is_v4        = Key((DONT_CARE<<4                | PROTOCOL_TYPE_IPV4_SUFFIX), mask=0b00001111)
    curr_is_dont_care__next_is_v6        = Key((DONT_CARE<<4                | PROTOCOL_TYPE_IPV6_SUFFIX), mask=0b00001111)

    # pd_tunnel_ipv4_ipv6_init_rtf_stage: ipv4_next_init_stage, ipv6_next_init_stage
    og__dont_care         = Key(INIT_RTF_OG<<2         | DONT_CARE, mask=0b1100)
    pre_fwd_l2__dont_care = Key(INIT_RTF_PRE_FWD_L2<<2 | DONT_CARE, mask=0b1100)
    pre_fwd_l3__dont_care = Key(INIT_RTF_PRE_FWD_L3<<2 | DONT_CARE, mask=0b1100)
    dont_care__og         = Key(DONT_CARE<<2           | INIT_RTF_OG, mask=0b0011)
    dont_care__pre_fwd_l2 = Key(DONT_CARE<<2           | INIT_RTF_PRE_FWD_L2, mask=0b0011)
    dont_care__pre_fwd_l3 = Key(DONT_CARE<<2           | INIT_RTF_PRE_FWD_L3, mask=0b0011)
    dont_care__dont_care  = Key(DONT_CARE<<2           | DONT_CARE, mask=0b0000)

    # rtf_indications : pd.acl_outer, pd.fwd_layer, pd.rtf_stage
    fwd_layer_is_ip__pre_fwd__acl_outer          = Key((1 << 3         | (IP_FWD<<2)    | RTF_PRE_FWD), mask=0b1111)
    fwd_layer_is_ip__pre_fwd__dont_care          = Key((DONT_CARE << 3 | (IP_FWD<<2)    | RTF_PRE_FWD), mask=0b0111)
    fwd_layer_is_mac__pre_fwd__dont_care         = Key((DONT_CARE << 3 | (MAC_FWD<<2)   | RTF_PRE_FWD), mask=0b0111)
    fwd_layer_is_dont_care__dont_care__dont_care = Key((DONT_CARE << 3 | (DONT_CARE<<2) | DONT_CARE), mask=0b0000)
    fwd_layer_is_dont_care__pre_fwd__dont_care   = Key((DONT_CARE << 3 | (DONT_CARE<<2) | RTF_PRE_FWD), mask=0b0011)

    table_data = [
        {"key": ["curr_and_next_prot_type"           , "pd_tunnel_ipv4_ipv6_init_rtf_stage", "next_rtf_stage" ,"rtf_indications"                     ]       , "value": ["jump_to_fwd", "pl_inc"   ,    "macro_id"                        ]},
        {"key": [curr_is_dont_care__next_is_dont_care, dont_care__dont_care                , RTF_OG           , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [      0      , PL_INC_NONE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [curr_is_dont_care__next_is_dont_care, dont_care__dont_care                , RTF_PRE_FWD_L2   , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [      0      , PL_INC_NONE, NETWORK_RX_ETH_RTF_MACRO]},
        {"key": [curr_is_v4__next_is_dont_care       , dont_care__dont_care                , RTF_PRE_FWD_L3   , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [      0      , PL_INC_NONE, NETWORK_RX_IPV4_RTF_MACRO]},
        {"key": [curr_is_v6__next_is_dont_care       , dont_care__dont_care                , RTF_PRE_FWD_L3   , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [      0      , PL_INC_NONE, NETWORK_RX_IPV6_RTF_MACRO]},
        {"key": [curr_is_dont_care__next_is_v4       , og__dont_care                       , _DONT_CARE       , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [      0      , PL_INC_ONCE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [curr_is_dont_care__next_is_v4       , pre_fwd_l2__dont_care               , _DONT_CARE       , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [      0      , PL_INC_ONCE, NETWORK_RX_ETH_RTF_MACRO]},
        {"key": [curr_is_dont_care__next_is_v4       , pre_fwd_l3__dont_care               , _DONT_CARE       , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [      0      , PL_INC_ONCE, NETWORK_RX_IPV4_RTF_MACRO]},
        {"key": [curr_is_dont_care__next_is_v6       , dont_care__og                       , _DONT_CARE       , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [      0      , PL_INC_ONCE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [curr_is_dont_care__next_is_v6       , dont_care__pre_fwd_l2               , _DONT_CARE       , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [      0      , PL_INC_ONCE, NETWORK_RX_ETH_RTF_MACRO]},
        {"key": [curr_is_dont_care__next_is_v6       , dont_care__pre_fwd_l3               , _DONT_CARE       , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [      0      , PL_INC_ONCE, NETWORK_RX_IPV6_RTF_MACRO]},
        {"key": [curr_is_dont_care__next_is_dont_care, dont_care__dont_care                , _DONT_CARE       , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [      1      , PL_INC_ONCE, NETWORK_RX_IP_AF_AND_FORWARDING_MACRO]},
        {"key": [curr_is_dont_care__next_is_dont_care, dont_care__dont_care                , RTF_OG           , fwd_layer_is_dont_care__dont_care__dont_care], "value": [      0      , PL_INC_NONE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [curr_is_dont_care__next_is_dont_care, dont_care__dont_care                , RTF_PRE_FWD_L2   , fwd_layer_is_dont_care__pre_fwd__dont_care]  , "value": [      0      , PL_INC_NONE, NETWORK_RX_ETH_RTF_MACRO]},
        {"key": [curr_is_v4__next_is_dont_care       , dont_care__dont_care                , RTF_PRE_FWD_L3   , fwd_layer_is_dont_care__pre_fwd__dont_care]  , "value": [      0      , PL_INC_NONE, NETWORK_RX_IPV4_RTF_MACRO]},
        {"key": [curr_is_v6__next_is_dont_care       , dont_care__dont_care                , RTF_PRE_FWD_L3   , fwd_layer_is_dont_care__pre_fwd__dont_care]  , "value": [      0      , PL_INC_NONE, NETWORK_RX_IPV6_RTF_MACRO]},
        {"key": [curr_is_dont_care__next_is_dont_care, dont_care__dont_care                , _DONT_CARE       , fwd_layer_is_ip__pre_fwd__dont_care]         , "value": [      1      , PL_INC_NONE, NETWORK_RX_IP_AF_AND_FORWARDING_MACRO]},
        {"key": [curr_is_v4__next_is_dont_care       , dont_care__dont_care                , _DONT_CARE       , fwd_layer_is_mac__pre_fwd__dont_care]        , "value": [      1      , 3, NETWORK_RX_MAC_FORWARDING_MACRO]},
        {"key": [curr_is_v6__next_is_dont_care       , dont_care__dont_care                , _DONT_CARE       , fwd_layer_is_mac__pre_fwd__dont_care]        , "value": [      1      , 3, NETWORK_RX_MAC_FORWARDING_MACRO]},
        {"key": [curr_is_dont_care__next_is_dont_care, dont_care__dont_care                , _DONT_CARE       , fwd_layer_is_mac__pre_fwd__dont_care]        , "value": [      1      , PL_INC_NONE, NETWORK_RX_MAC_FORWARDING_MACRO]},
    ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


#  |  mc_termination_hit  |        ACTION                 |
#  |    1                 | USE_QOS_ID_FROM_L3_LAYER_ATTR |
#  |    0                 | USE_QOS_ID_FROM_L2_LP_ATTR    |
def config_ipv6_mc_select_qos_id():
    table = ipv6_mc_select_qos_id
    table_data = [
        {"mc_termination_hit": 1, "action": IPV6_MC_SELECT_QOS_ID_ACTION_USE_QOS_ID_FROM_L3_LAYER_ATTR},
        {"mc_termination_hit": 0, "action": IPV6_MC_SELECT_QOS_ID_ACTION_USE_QOS_ID_FROM_L2_LP_ATTR},
    ]

    for line in table_data:
        key = ipv6_mc_select_qos_id_key_t(mc_termination_hit=line["mc_termination_hit"])
        value = ipv6_mc_select_qos_id_value_t(action=line["action"])
        table.insert(NETWORK_CONTEXT, key, value)


# #
# # for pacific , align counter_0_offset to 3 bits
# #
# def config_write_acl_drop_offset_on_pd():
#     table_config = DirectTableConfig("write_acl_drop_offset_on_pd")
#     table_data = [{"key": [ "acl_drop_offset"] , "value": [ "counter_0_offset"]},
#                   {"key": [      0b00        ] , "value": [        0b000     ]},
#                   {"key": [      0b01        ] , "value": [        0b001     ]},
#                   {"key": [      0b10        ] , "value": [        0b010     ]},
#                   {"key": [      0b11        ] , "value": [        0b011     ]},
#                   ]
#     table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)
