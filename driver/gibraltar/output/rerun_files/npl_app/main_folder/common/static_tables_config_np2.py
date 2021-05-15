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
    config_mac_termination_next_macro_static_table()
    config_sgt_derivation_macro_static_table()
    config_sgacl_next_macro_static_table()
    config_svl_sgacl_next_macro_static_table()
    config_svl_sgacl_enable_static_table()
    config_sgacl_l4_protocol_select_table()
    config_fixup_destination_for_resolution_static_table()
    config_ip_proto_type_mux_static_table()
    config_gre_proto_static_table()
    config_inject_down_select_ene_static_table()
    config_eth_type_static_table()
    config_cong_level_ecn_remap_map_table()
    config_post_fwd_rtf_next_macro_static_table()
    config_rtf_next_macro_static_table()
    config_sgt_vxlan_termination_table()
    config_sgacl_ip_fragment_check_table()
    config_nh_macro_code_to_id_l6_static_table()
    config_learn_command_type_mapping_table()
    config_svl_next_macro_static_table()
    config_local_mc_fwd_next_macro_static_table()
    # config_write_acl_drop_offset_on_pd()


def config_nh_macro_code_to_id_l6_static_table() :
    table_config = TcamTableConfig("nh_macro_code_to_id_l6_static_table")
    table_data = [
        {"key": ["nh_ene_code"], "value": ["nh_ene_macro_id"]},
        {"key": [NH_ENE_MACRO_ETH],           "value": [NH_ETHERNET_NO_VLAN_ENE_MACRO]},
        {"key": [NH_ENE_MACRO_ETH_VLAN],      "value": [NH_ETHERNET_WITH_ONE_VLAN_ENE_MACRO]},
        {"key": [NH_ENE_MACRO_ETH_VLAN_VLAN], "value": [NH_ETHERNET_WITH_TWO_VLAN_ENE_MACRO]},
        {"key": [NH_ENE_MACRO_ETH],           "value": [NH_ETHERNET_NO_VLAN_ENE_MACRO]},
    ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


def config_nhlfe_type_mapping_static_table():
    table = nhlfe_type_mapping_static_table
    table_data = [

        #=========================================================================
        #   Key: nhlfe_type_e  |     Payload: nhlfe_type_attributes_t(encap_type, midpoint_nh_destination)
        #==============================================================================

        {"nhlfe_type": NHLFE_TYPE_MIDPOINT_SWAP, "encap_type": NPU_ENCAP_L3_HEADER_TYPE_ILM_LABEL, "midpoint_nh_destination": DESTINATION_MASK_L3_NH} ,
        {"nhlfe_type": NHLFE_TYPE_MIDPOINT_PHP,  "encap_type": NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH,   "midpoint_nh_destination": DESTINATION_MASK_L3_NH} ,
        {"nhlfe_type": NHLFE_TYPE_L2_ADJ_SID,    "encap_type": NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE_SR,    "midpoint_nh_destination": DESTINATION_MASK_DSP} ,
        {"nhlfe_type": NHLFE_TYPE_MIDPOINT_TUNNEL_PROTECTION_FULL,           "encap_type": NPU_ENCAP_L3_HEADER_TYPE_ILM_LABEL, "midpoint_nh_destination": DESTINATION_MASK_P_L3_NH} ,
        {"nhlfe_type": NHLFE_TYPE_MIDPOINT_TUNNEL_PROTECTION_IMPLICIT_SWP,   "encap_type": NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH,   "midpoint_nh_destination": DESTINATION_MASK_P_L3_NH} ,
        {"nhlfe_type": NHLFE_TYPE_MIDPOINT_TUNNEL_PROTECTION_IMPLICIT_MP,    "encap_type": NPU_ENCAP_L3_HEADER_TYPE_ILM_LABEL, "midpoint_nh_destination": DESTINATION_MASK_P_L3_NH} ,
        {"nhlfe_type": NHLFE_TYPE_MIDPOINT_TUNNEL_PROTECTION_IMPLICIT_MP_SWP,"encap_type": NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH,   "midpoint_nh_destination": DESTINATION_MASK_P_L3_NH} ,
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
            "key": {"type": PROTOCOL_TYPE_IPV4, "protocol": IPV4_PROTOCOL_UDP, "next_header": DONT_CARE, "dst_port":  UDP_BFD_SINGLE_HOP_PORT},
            "mask": {"type": 0b01111, "protocol": ALL_1, "next_header": DONT_CARE, "dst_port": ALL_1},
            "payload": {"bfd_valid": 1, "macro_id": RX_HANDLE_BFD_AND_LPTS_OG_MACRO, "pl_inc": PL_INC_NONE},
        },

        # IPv4 Echo dest port
        {
            "key": {"type": PROTOCOL_TYPE_IPV4, "protocol": IPV4_PROTOCOL_UDP, "next_header": DONT_CARE, "dst_port":  UDP_BFD_ECHO_PORT},
            "mask": {"type": 0b01111, "protocol": ALL_1, "next_header": DONT_CARE, "dst_port": ALL_1},
            "payload": {"bfd_valid": 1, "macro_id": RX_HANDLE_BFD_AND_LPTS_OG_MACRO, "pl_inc": PL_INC_NONE},
        },

        # IPv4 Multi hop dest port
        {
            "key": {"type": PROTOCOL_TYPE_IPV4, "protocol": IPV4_PROTOCOL_UDP, "next_header": DONT_CARE, "dst_port":  UDP_BFD_MULTI_HOP_PORT},
            "mask": {"type": 0b01111, "protocol": ALL_1, "next_header": DONT_CARE, "dst_port": ALL_1},
            "payload": {"bfd_valid": 1, "macro_id": RX_HANDLE_BFD_AND_LPTS_OG_MACRO, "pl_inc": PL_INC_NONE},
        },

        # IPv4 Micro BFD dest port
        {
            "key": {"type": PROTOCOL_TYPE_IPV4, "protocol": IPV4_PROTOCOL_UDP, "next_header": DONT_CARE, "dst_port":  UDP_BFD_MICRO_HOP_PORT},
            "mask": {"type": 0b01111, "protocol": ALL_1, "next_header": DONT_CARE, "dst_port": ALL_1},
            "payload": {"bfd_valid": 1, "macro_id": RX_HANDLE_BFD_AND_LPTS_OG_MACRO, "pl_inc": PL_INC_NONE},
        },

        # IPv6 Single hop dest port
        {
            "key": {"type": PROTOCOL_TYPE_IPV6, "protocol": DONT_CARE, "next_header": IPV4_PROTOCOL_UDP, "dst_port":  UDP_BFD_SINGLE_HOP_PORT},
            "mask": {"type": 0b01111, "protocol": DONT_CARE, "next_header": ALL_1, "dst_port": ALL_1},
            "payload": {"bfd_valid": 1, "macro_id": RX_HANDLE_BFD_AND_LPTS_OG_MACRO, "pl_inc": PL_INC_NONE},
        },

        # IPv6 Echo dest port
        {
            "key": {"type": PROTOCOL_TYPE_IPV6, "protocol": DONT_CARE, "next_header": IPV4_PROTOCOL_UDP, "dst_port":  UDP_BFD_ECHO_PORT},
            "mask": {"type": 0b01111, "protocol": DONT_CARE, "next_header": ALL_1, "dst_port": ALL_1},
            "payload": {"bfd_valid": 1, "macro_id": RX_HANDLE_BFD_AND_LPTS_OG_MACRO, "pl_inc": PL_INC_NONE},
        },

        # IPv6 Multi hop dest port
        {
            "key": {"type": PROTOCOL_TYPE_IPV6, "protocol": DONT_CARE, "next_header": IPV4_PROTOCOL_UDP, "dst_port":  UDP_BFD_MULTI_HOP_PORT},
            "mask": {"type": 0b01111, "protocol": DONT_CARE, "next_header": ALL_1, "dst_port": ALL_1},
            "payload": {"bfd_valid": 1, "macro_id": RX_HANDLE_BFD_AND_LPTS_OG_MACRO, "pl_inc": PL_INC_NONE},
        },

        # IPv6 Micro BFD dest port
        {
            "key": {"type": PROTOCOL_TYPE_IPV6, "protocol": DONT_CARE, "next_header": IPV4_PROTOCOL_UDP, "dst_port":  UDP_BFD_MICRO_HOP_PORT},
            "mask": {"type": 0b01111, "protocol": DONT_CARE, "next_header": ALL_1, "dst_port": ALL_1},
            "payload": {"bfd_valid": 1, "macro_id": RX_HANDLE_BFD_AND_LPTS_OG_MACRO, "pl_inc": PL_INC_NONE},
        },

        # Default entry
        {
            "key": {"type": DONT_CARE, "protocol": DONT_CARE, "next_header": DONT_CARE, "dst_port":  DONT_CARE},
            "mask": {"type": DONT_CARE, "protocol": DONT_CARE, "next_header": DONT_CARE, "dst_port":  DONT_CARE},
            "payload": {"bfd_valid": 0, "macro_id": RX_LPTS_REDIRECT_MACRO, "pl_inc": PL_INC_NONE},
        },
    ]
    location = 0
    for line in table_data:
        key = bfd_udp_port_map_static_table_key_t(packet_header_info_type=line["key"]["type"],
                                                  packet_ipv4_header_protocol=line["key"]["protocol"],
                                                  packet_ipv6_header_next_header=line["key"]["next_header"],
                                                  packet_header_1__udp_header_dst_port=line["key"]["dst_port"])
        mask = bfd_udp_port_map_static_table_key_t(packet_header_info_type=line["mask"]["type"],
                                                   packet_ipv4_header_protocol=line["mask"]["protocol"],
                                                   packet_ipv6_header_next_header=line["mask"]["next_header"],
                                                   packet_header_1__udp_header_dst_port=line["mask"]["dst_port"])
        value = bfd_udp_port_map_static_table_value_t(**line["payload"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


# If Packet is routed, we need to incr the current layer , when forwarding done.
# sgt_derivation_macro_static_table - Identify next macro
# +-----------------------+-------------+-------------------------------------------------+-----------------------------------------------+
# |  fwd_header_type      | enforcement |  valid_ip_sgt_derived  | macro_stage_vxlan_pack | macro_id, pl_inc, stage, sgacl_macro_enabled  |
# |                       |             |                        | (sgt_derivation_stage, |                                               |
# |                       |             |                        | vxlan_terminated, svl) |                                               |
# +-----------------------+--------------------------------------+------------------------+-----------------------------------------------+
# |     DONT_CARE         |  DONT_CARE  |        0               |        3'b000          |  SGT_DERIVATION, PL_INC_NONE, 1, 0x0          |
# +-----------------------+--------------------------------------+------------------------+-----------------------------------------------+
# |     ETHERNET          |     0       |      DONT_CARE         |        3'bxx1          |  SVL_MACRO, PL_INC_NONE, 0, 0x0                         |
# +-----------------------+--------------------------------------+------------------------+-----------------------------------------------+
# |     DONT_CARE         |     0       |      DONT_CARE         |        3'bxx1          |  SVL_MACRO, PL_INC_ONCE, 0, 0x0               |
# +-----------------------+--------------------------------------+------------------------+-----------------------------------------------+
# |     ETHERNET          |     0       |      DONT_CARE         |        DONT_CARE       |  FORWARDING_DONE, PL_INC_NONE, 0, 0x0                   |
# +-----------------------+--------------------------------------+------------------------+-----------------------------------------------+
# |     DONT_CARE         |     0       |      DONT_CARE         |        DONT_CARE       |  FORWARDING_DONE, PL_INC_ONCE, 0, 0x0         |
# +-----------------------+--------------------------------------+------------------------+-----------------------------------------------+
# |     DONT_CARE         |     1       |      DONT_CARE         |        DONT_CARE       |  SGACL_MACRO, PL_INC_NONE, 0, 0x1             |
# +---------------------------------------------------------------------------------------+-----------------------------------------------+


def config_sgt_derivation_macro_static_table():
    table = sgt_derivation_macro_static_table

    table_data = [
        {
            "key":  {"fwd_header_type": DONT_CARE, "enforcement": DONT_CARE, "valid_ip_sgt_derived": 0, "macro_stage_vxlan_svl_pack": 0b000},
            "mask": {"fwd_header_type": DONT_CARE ,"enforcement": DONT_CARE, "valid_ip_sgt_derived": ALL_1, "macro_stage_vxlan_svl_pack":0b110},
            "payload": {"macro_id": NETWORK_RX_IP_SGT_DERIVATION_MACRO, "pl_inc": PL_INC_NONE, "stage": 0x1, "next_macro_is_sgacl": 0x1}
        },
        {
            "key":  {"fwd_header_type": FWD_HEADER_TYPE_ETHERNET, "enforcement": 0, "valid_ip_sgt_derived": DONT_CARE, "macro_stage_vxlan_svl_pack":0b001},
            "mask": {"fwd_header_type": ALL_1,    "enforcement": ALL_1,             "valid_ip_sgt_derived": DONT_CARE, "macro_stage_vxlan_svl_pack":0b001},
            "payload": {"macro_id": NETWORK_RESOLVE_SVL_OR_LP_OVER_LAG_MACRO, "pl_inc": PL_INC_NONE, "stage": 0, "next_macro_is_sgacl": 0x0}
        },
        {
            "key":  {"fwd_header_type": DONT_CARE, "enforcement": 0, "valid_ip_sgt_derived": DONT_CARE, "macro_stage_vxlan_svl_pack":0b001},
            "mask": {"fwd_header_type": DONT_CARE, "enforcement": ALL_1, "valid_ip_sgt_derived": DONT_CARE, "macro_stage_vxlan_svl_pack":0b001},
            "payload": {"macro_id": NETWORK_RESOLVE_SVL_OR_LP_OVER_LAG_MACRO, "pl_inc": PL_INC_ONCE, "stage": 0, "next_macro_is_sgacl": 0x0}
        },
        {
            "key":  {"fwd_header_type": FWD_HEADER_TYPE_ETHERNET, "enforcement": 0, "valid_ip_sgt_derived": DONT_CARE, "macro_stage_vxlan_svl_pack":DONT_CARE},
            "mask": {"fwd_header_type": ALL_1,    "enforcement": ALL_1, "valid_ip_sgt_derived": DONT_CARE, "macro_stage_vxlan_svl_pack":DONT_CARE},
            "payload": {"macro_id": FORWARDING_DONE, "pl_inc": PL_INC_NONE, "stage": 0, "next_macro_is_sgacl": 0x0}
        },
        {
            "key":  {"fwd_header_type": DONT_CARE, "enforcement": 0,     "valid_ip_sgt_derived": DONT_CARE, "macro_stage_vxlan_svl_pack":DONT_CARE},
            "mask": {"fwd_header_type": DONT_CARE, "enforcement": ALL_1, "valid_ip_sgt_derived": DONT_CARE, "macro_stage_vxlan_svl_pack":DONT_CARE},
            "payload": {"macro_id": FORWARDING_DONE, "pl_inc": PL_INC_ONCE, "stage": 0, "next_macro_is_sgacl": 0x0}
        },
        {
            "key":  {"fwd_header_type": DONT_CARE, "enforcement": 1,     "valid_ip_sgt_derived": DONT_CARE, "macro_stage_vxlan_svl_pack":DONT_CARE},
            "mask": {"fwd_header_type": DONT_CARE, "enforcement": ALL_1, "valid_ip_sgt_derived": DONT_CARE, "macro_stage_vxlan_svl_pack":DONT_CARE},
            "payload": {"macro_id": NETWORK_RX_SGACL_MACRO, "pl_inc": PL_INC_NONE, "stage": 0, "next_macro_is_sgacl": 0x1}
        },
    ]

    location = 0
    for line in table_data:
        key = sgt_derivation_macro_static_table_key_t(**line["key"])
        mask = sgt_derivation_macro_static_table_key_t(**line["mask"])
        value = sgt_derivation_macro_static_table_value_t(**line["payload"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1

# sgacl_next_macro_static_table - Identify next macro
# +-----------------------+-------------+---------------------------------------+
# |  fwd_header_type      | sgacl_stage |     svl      |   pl_inc, macro_id     |
# +-----------------------+-----------------------------------------------------+
# |     _DONT_CARE        |      0      |  _DONT_CARE  |    NONE, SGACL_MACRO   |
# +-----------------------+-----------------------------------------------------+
# |     ETHERNET          |      1      |      1       |    NONE,  SVL_MACRO     |
# +-----------------------+-----------------------------------------------------+
# |     _DONT_CARE        |      1      |      1       |    ONCE, SVL_MACRO     |
# +-----------------------+-----------------------------------------------------+
# |     ETHERNET          |      1      |      0       |    NONE,  FWD_DONE      |
# +-----------------------+-----------------------------------------------------+
# |     _DONT_CARE        |      1      |      0       |    ONCE, FWD_DONE      |
# +-----------------------+-----------------------------------------------------+
# If Packet is routed, we need to increment the current layer , when forwarding done.


def config_sgacl_next_macro_static_table():
    table_config = TcamTableConfig("sgacl_next_macro_static_table")
    table_data = [
        {"key": ["fwd_header_type", "sgacl_stage", "svl"], "value": ["pl_inc" ,   "macro_id"]},
        {"key": [_DONT_CARE, 0, _DONT_CARE],      "value": [PL_INC_NONE, NETWORK_RX_SGACL_MACRO]},
        {"key": [FWD_HEADER_TYPE_ETHERNET, 1, 1], "value": [PL_INC_NONE, NETWORK_RESOLVE_SVL_OR_LP_OVER_LAG_MACRO]},
        {"key": [_DONT_CARE,               1, 1], "value": [PL_INC_ONCE, NETWORK_RESOLVE_SVL_OR_LP_OVER_LAG_MACRO]},
        {"key": [FWD_HEADER_TYPE_ETHERNET, 1, 0], "value": [PL_INC_NONE, FORWARDING_DONE]},
        {"key": [_DONT_CARE,               1, 0], "value": [PL_INC_ONCE, FORWARDING_DONE]},
    ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


# If Packet is routed, decrement current layer to point to layer before IP, so SGT macros can be optimized.
def config_svl_sgacl_next_macro_static_table():
    table_config = TcamTableConfig("svl_sgacl_next_macro_static_table")
    table_data = [
        {"key": ["fwd_header_type", "sda_fabric_enable", "next_header","svl_dest"], "value": ["pl_inc" ,   "macro_id"]},
        {"key": [FWD_HEADER_TYPE_ETHERNET, 1  , PROTOCOL_TYPE_IPV4,    _DONT_CARE], "value": [PL_INC_NONE, NETWORK_RX_IP_SGT_DERIVATION_MACRO]},
        {"key": [FWD_HEADER_TYPE_ETHERNET, 1  , PROTOCOL_TYPE_IPV6,    _DONT_CARE], "value": [PL_INC_NONE, NETWORK_RX_IP_SGT_DERIVATION_MACRO]},
        {"key": [FWD_HEADER_TYPE_ETHERNET, 1  , PROTOCOL_TYPE_IPV4_L4, _DONT_CARE], "value": [PL_INC_NONE, NETWORK_RX_IP_SGT_DERIVATION_MACRO]},
        {"key": [FWD_HEADER_TYPE_ETHERNET, 1  , PROTOCOL_TYPE_IPV6_L4, _DONT_CARE], "value": [PL_INC_NONE, NETWORK_RX_IP_SGT_DERIVATION_MACRO]},
        {"key": [FWD_HEADER_TYPE_IPV4,     1  , _DONT_CARE,            _DONT_CARE], "value": [3, NETWORK_RX_IP_SGT_DERIVATION_MACRO]},
        {"key": [FWD_HEADER_TYPE_IPV6,     1  , _DONT_CARE,            _DONT_CARE], "value": [3, NETWORK_RX_IP_SGT_DERIVATION_MACRO]},
        {"key": [_DONT_CARE,      _DONT_CARE  , _DONT_CARE,              1      ], "value": [PL_INC_NONE, NETWORK_RESOLVE_SVL_OR_LP_OVER_LAG_MACRO]}
    ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)

# If Packet is routed, decrement current layer to point before IP, so SGT macros can be optimized.


def config_svl_sgacl_enable_static_table():
    table_config = TcamTableConfig("svl_sgacl_enable_static_table")
    table_data = [
        {"key": ["fwd_header_type", "sda_fabric_enable", "next_header"], "value": ["sgt_macro_enabled"]},
        {"key": [FWD_HEADER_TYPE_ETHERNET, 1  , PROTOCOL_TYPE_IPV4], "value": [1]},
        {"key": [FWD_HEADER_TYPE_ETHERNET, 1  , PROTOCOL_TYPE_IPV6], "value": [1]},
        {"key": [FWD_HEADER_TYPE_ETHERNET, 1  , PROTOCOL_TYPE_IPV4_L4], "value": [1]},
        {"key": [FWD_HEADER_TYPE_ETHERNET, 1  , PROTOCOL_TYPE_IPV6_L4], "value": [1]},
        {"key": [FWD_HEADER_TYPE_IPV4,     1  , _DONT_CARE], "value": [1]},
        {"key": [FWD_HEADER_TYPE_IPV6,     1  , _DONT_CARE], "value": [1]},
        {"key": [_DONT_CARE,      _DONT_CARE  , _DONT_CARE], "value": [0]}
    ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)

#  |  is_ipv4    |    mapped_protocol_valid |            ACTION             |
#  |    0        |          0               |  UPDATE_IPV4_L4_PROTOCOL      |
#  |    0        |          1               |  UPDATE_IPV4_L4_PROTOCOL      |
#  |    1        |          0               |  UPDATE_IPV6_NEXT_L4_PROTOCOL |
#  |    1        |          1               |  UPDATE_IPV6_MAPPED_PROTOCOL  |


def config_sgacl_l4_protocol_select_table():
    table = sgacl_l4_protocol_select_table
    table_data = [
        {"is_ipv6": 0, "mapped_protocol_valid": 0, "action": SGACL_L4_PROTOCOL_SELECT_TABLE_ACTION_UPDATE_IPV4_L4_PROTOCOL},
        {"is_ipv6": 0, "mapped_protocol_valid": 1, "action": SGACL_L4_PROTOCOL_SELECT_TABLE_ACTION_UPDATE_IPV4_L4_PROTOCOL},
        {"is_ipv6": 1, "mapped_protocol_valid": 0, "action": SGACL_L4_PROTOCOL_SELECT_TABLE_ACTION_UPDATE_IPV6_NEXT_L4_PROTOCOL},
        {"is_ipv6": 1, "mapped_protocol_valid": 1, "action": SGACL_L4_PROTOCOL_SELECT_TABLE_ACTION_UPDATE_IPV6_MAPPED_PROTOCOL},
    ]

    for line in table_data:
        key = sgacl_l4_protocol_select_table_key_t(is_ipv6=line["is_ipv6"],
                                                   mapped_protocol_valid=line["mapped_protocol_valid"])
        value = sgacl_l4_protocol_select_table_value_t(action=line["action"])
        table.insert(NETWORK_CONTEXT, key, value)


# Used to remove class ID from HOST_MAC destinations and increase number of L2_DLP destinations.
# Class ID, when present, is in dest[11:8]
# Extra destination bit is put into dest[8] (DSP(A)) or dest[9] (L2 DLP) when class ID present,
# dest[12] (DSP(A)) or dest[13] (L2 DLP) when not.
# In host_mac, lp[13:12] is used to map to dest prefix and as dest[13:12].  zero out stray bits in
# dest[13:12] so that dest always starts at 0.
# +----------+--------+------------+---------+----------+----+-------------------------+-------------------------+
# | rtype    | prefix | with_class | lp13_12 | dest_bit |    | fixup_mask              | extra_dest              |
# +----------+--------+------------+---------+----------+----+-------------------------+-------------------------+
# | HOST_MAC | L2_DLP | 0          | *       | 0        | >  | 16'b1001_1111_1111_1111 | 16'b0000_0000_0000_0000 |
# | HOST_MAC | L2_DLP | 0          | *       | 1        | >  | 16'b1001_1111_1111_1111 | 16'b0010_0000_0000_0000 |
# | HOST_MAC | L2_DLP | 1          | 00      | 0        | >  | 16'b1000_0000_1111_1111 | 16'b0000_0000_0000_0000 |
# | HOST_MAC | L2_DLP | 1          | 00      | 1        | >  | 16'b1000_0000_1111_1111 | 16'b0000_0010_0000_0000 |
# | HOST_MAC | L2_DLP | 1          | 01      | 0        | >  | 16'b1000_0000_1111_1111 | 16'b0000_0001_0000_0000 |
# | HOST_MAC | L2_DLP | 1          | 01      | 1        | >  | 16'b1000_0000_1111_1111 | 16'b0000_0011_0000_0000 |
# | HOST_MAC | *      | 0          | *       | 0        | >  | 16'b1000_1111_1111_1111 | 16'b0000_0000_0000_0000 |
# | HOST_MAC | *      | 0          | *       | 1        | >  | 16'b1000_1111_1111_1111 | 16'b0001_0000_0000_0000 |
# | HOST_MAC | *      | 1          | *       | 0        | >  | 16'b1000_0000_1111_1111 | 16'b0000_0000_0000_0000 |
# | HOST_MAC | *      | 1          | *       | 1        | >  | 16'b1000_0000_1111_1111 | 16'b0000_0001_0000_0000 |
# | *        | *      | *          | *       | *        | >  | 16'b1111_1111_1111_1111 | 16'b0000_0000_0000_0000 |
# +----------+--------+------------+---------+----------+----+-------------------------+-------------------------+


def config_fixup_destination_for_resolution_static_table():
    table = fixup_destination_for_resolution_static_table

    def pcl(prefix, cls, lp13_12):
        return ((prefix & 0x1f) << 3) | ((cls & 0x1) << 2) | (lp13_12 & 0x3)

    HOST_MAC = IP_EM_LPM_RESULT_TYPE_HOST_MAC_AND_L3_DLP
    L2_DLP_PREFIX = (DESTINATION_MASK_L2_DLP >> 15)

    table_data = [
        {
            "key":  {"rtype": HOST_MAC, "prefix_class_lp13_12": pcl(L2_DLP_PREFIX, 0,     DONT_CARE), "dest_bit": 0},
            "mask": {"rtype": ALL_1,    "prefix_class_lp13_12": pcl(ALL_1,         ALL_1, DONT_CARE), "dest_bit": ALL_1},
            "payload": {"fixup_mask": 0b1001_1111_1111_1111, "extra_dest": (0 << 13)}
        },
        {
            "key":  {"rtype": HOST_MAC, "prefix_class_lp13_12": pcl(L2_DLP_PREFIX, 0,     DONT_CARE), "dest_bit": 1},
            "mask": {"rtype": ALL_1,    "prefix_class_lp13_12": pcl(ALL_1,         ALL_1, DONT_CARE), "dest_bit": ALL_1},
            "payload": {"fixup_mask": 0b1001_1111_1111_1111, "extra_dest": (1 << 13)}
        },
        {
            "key":  {"rtype": HOST_MAC, "prefix_class_lp13_12": pcl(L2_DLP_PREFIX, 1,     0b00),  "dest_bit": 0},
            "mask": {"rtype": ALL_1,    "prefix_class_lp13_12": pcl(ALL_1,         ALL_1, ALL_1), "dest_bit": ALL_1},
            "payload": {"fixup_mask": 0b1000_0000_1111_1111, "extra_dest": (0 << 8) | (0 << 9)}
        },
        {
            "key":  {"rtype": HOST_MAC, "prefix_class_lp13_12": pcl(L2_DLP_PREFIX, 1,     0b00),  "dest_bit": 1},
            "mask": {"rtype": ALL_1,    "prefix_class_lp13_12": pcl(ALL_1,         ALL_1, ALL_1), "dest_bit": ALL_1},
            "payload": {"fixup_mask": 0b1000_0000_1111_1111, "extra_dest": (0 << 8) | (1 << 9)}
        },
        {
            "key":  {"rtype": HOST_MAC, "prefix_class_lp13_12": pcl(L2_DLP_PREFIX, 1,     0b01),  "dest_bit": 0},
            "mask": {"rtype": ALL_1,    "prefix_class_lp13_12": pcl(ALL_1,         ALL_1, ALL_1), "dest_bit": ALL_1},
            "payload": {"fixup_mask": 0b1000_0000_1111_1111, "extra_dest": (1 << 8) | (0 << 9)}
        },
        {
            "key":  {"rtype": HOST_MAC, "prefix_class_lp13_12": pcl(L2_DLP_PREFIX, 1,     0b01),  "dest_bit": 1},
            "mask": {"rtype": ALL_1,    "prefix_class_lp13_12": pcl(ALL_1,         ALL_1, ALL_1), "dest_bit": ALL_1},
            "payload": {"fixup_mask": 0b1000_0000_1111_1111, "extra_dest": (1 << 8) | (1 << 9)}
        },
        {
            "key":  {"rtype": HOST_MAC, "prefix_class_lp13_12": pcl(DONT_CARE, 0,     DONT_CARE), "dest_bit": 0},
            "mask": {"rtype": ALL_1,    "prefix_class_lp13_12": pcl(DONT_CARE, ALL_1, DONT_CARE), "dest_bit": ALL_1},
            "payload": {"fixup_mask": 0b1000_1111_1111_1111, "extra_dest": (0 << 12)}
        },
        {
            "key":  {"rtype": HOST_MAC, "prefix_class_lp13_12": pcl(DONT_CARE, 0,     DONT_CARE), "dest_bit": 1},
            "mask": {"rtype": ALL_1,    "prefix_class_lp13_12": pcl(DONT_CARE, ALL_1, DONT_CARE), "dest_bit": ALL_1},
            "payload": {"fixup_mask": 0b1000_1111_1111_1111, "extra_dest": (1 << 12)}
        },
        {
            "key":  {"rtype": HOST_MAC, "prefix_class_lp13_12": pcl(DONT_CARE, 1,     DONT_CARE), "dest_bit": 0},
            "mask": {"rtype": ALL_1,    "prefix_class_lp13_12": pcl(DONT_CARE, ALL_1, DONT_CARE), "dest_bit": ALL_1},
            "payload": {"fixup_mask": 0b1000_0000_1111_1111, "extra_dest": (0 << 8)}
        },
        {
            "key":  {"rtype": HOST_MAC, "prefix_class_lp13_12": pcl(DONT_CARE, 1,     DONT_CARE), "dest_bit": 1},
            "mask": {"rtype": ALL_1,    "prefix_class_lp13_12": pcl(DONT_CARE, ALL_1, DONT_CARE), "dest_bit": ALL_1},
            "payload": {"fixup_mask": 0b1000_0000_1111_1111, "extra_dest": (1 << 8)}
        },
        {
            "key":  {"rtype": DONT_CARE, "prefix_class_lp13_12": pcl(DONT_CARE, DONT_CARE, DONT_CARE), "dest_bit": DONT_CARE},
            "mask": {"rtype": DONT_CARE, "prefix_class_lp13_12": pcl(DONT_CARE, DONT_CARE, DONT_CARE), "dest_bit": DONT_CARE},
            "payload": {"fixup_mask": 0b1111_1111_1111_1111, "extra_dest": 0}
        },
    ]

    location = 0
    for line in table_data:
        key = fixup_destination_for_resolution_static_table_key_t(**line["key"])
        mask = fixup_destination_for_resolution_static_table_key_t(**line["mask"])
        value = fixup_destination_for_resolution_static_table_value_t(**line["payload"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


# Used to set flags for the presence of L4 protocol types.
# This table optimizes the number of Key selection entries required for ip_fields_muxing_pack_table
#
# +-----------+----------+-----------+----+------------+------------+-------------------------+
# | ip_version| v4_proto | v6_proto  |    | is_gre_v4  | is_gre_v6  | is_udp  |  is_hop_by_hop|
# +-----------+----------+-----------+----+------------+------------+-------------------------+
# |     V6    |    *     |  GRE      | >  |    0       |      1     |   0     |        0      |
# |     V4    |   GRE    |   *       | >  |    1       |      0     |   0     |        0      |
# |     V6    |    *     |  UDP      | >  |    0       |      0     |   1     |        0      |
# |     V4    |   UDP    |   *       | >  |    0       |      0     |   1     |        0      |
# |     V6    |    *     |HOP_BY_HOP | >  |    0       |      0     |   0     |        1      |
# |     *     |    *     |   *       | >  |    0       |      0     |   0     |        0      |
# +----------+-----------+-----------+----+-------------------------+-------------------------+
def config_ip_proto_type_mux_static_table():
    table_config = TcamTableConfig("ip_proto_type_mux_static_table")
    table_data = [
        {"key": ["ip_version", "ipv4_proto", "ipv6_proto"], "value": ["is_gre_v4" , "is_gre_v6" ,  "is_udp", "is_hop_by_hop"]},
        {"key": [IP_VERSION_IPV6, _DONT_CARE,        IPV6_NEXT_HEADER_GRE],        "value": [0, 1, 0, 0]},
        {"key": [IP_VERSION_IPV4, IPV4_PROTOCOL_GRE, _DONT_CARE],                  "value": [1, 0, 0, 0]},
        {"key": [IP_VERSION_IPV6, _DONT_CARE,        IPV4_PROTOCOL_UDP],           "value": [0, 0, 1, 0]},
        {"key": [IP_VERSION_IPV4, IPV4_PROTOCOL_UDP, _DONT_CARE],                  "value": [0, 0, 1, 0]},
        {"key": [IP_VERSION_IPV6, _DONT_CARE,        IPV6_NEXT_HEADER_HOP_BY_HOP], "value": [0, 0, 0, 1]},
        {"key": [_DONT_CARE,      _DONT_CARE,        _DONT_CARE],                  "value": [0, 0, 0, 0]},
    ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)

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
        value = gre_proto_static_table_value_t( gre_proto=(line["gre_proto"] << 8))
        table.insert(NETWORK_CONTEXT, key, value)


def config_eth_type_static_table():
    table = eth_type_static_table
    key = 0
    value = eth_type_static_table_value_t((ETHER_TYPE_IPV6 << 16) | ETHER_TYPE_IPV4)
    table.insert(NETWORK_CONTEXT, key, value)


def config_cong_level_ecn_remap_map_table():
    table = cong_level_ecn_remap_map_table
    table_config = DirectTableConfig("cong_level_ecn_remap_map_table")
    table_data = [{"key": ["rand", "cong_level"] , "value": ["stat_cong_level_on"]}]
    rand_size, cong_level_size = 2**5, 2**4
    for rnd in range(0, rand_size):
        for cl in range(0, cong_level_size):
            if cl == cong_level_size - 1:
                table_data.append({"key": [rnd, cl], "value": [True]})
            else:
                table_data.append({"key": [rnd, cl], "value": [False]})
    table_config.create_table(table_data, NETWORK_CONTEXT)


# mac_next_macro_packed_data : is_ipv4_mc(1b), is_ipv6_mc(1b), packet.protocol_layer[next].type(5b), l2_lp_type(4)
#ipv4_ipv6_init_rtf_stage : ipv4_init_rtf_stage(2b), ipv6_init_rtf_stage(2b)
#
# |  mac_next_macro_packed_data             | ipv4_ipv6_init_rtf_stage | macro                                          |   INC
# |  10*********                            | *****                    | network_rx_mac_relay_ipv4_mc_termination_macro | PL_INC_NONE
# |  01*********                            | *****                    | network_rx_mac_relay_ipv6_mc_termination_macro | PL_INC_NONE
# |  00,****,L2_LP_TYPE_OVERLAY             | init_rtf_og**            | NETWORK_RX_IP_OBJECT_GROUPS_MACRO              | PL_DEC_ONCE
# |  00,****,L2_LP_TYPE_OVERLAY             | init_rtf_pre_fwd_l2**    | NETWORK_RX_ETH_RTF_MACRO                       | PL_DEC_ONCE
# |  00,****,L2_LP_TYPE_OVERLAY             | init_rtf_pre_fwd_l3**    | NETWORK_RX_IPV4_RTF_MACRO                      | PL_DEC_ONCE
# |  00,****,L2_LP_TYPE_OVERLAY             | ****                     | NETWORK_RX_IP_AF_AND_FORWARDING_MACRO          | PL_INC_ONCE
# |  00,PROTOCOL_TYPE_IPV4,L2_LP_TYPE_NPP   | ****                     | network_rx_ip_af_and_termination_macro         | PL_INC_ONCE
# |  00,PROTOCOL_TYPE_IPV6,L2_LP_TYPE_NPP   | ****                     | network_rx_ip_af_and_termination_macro         | PL_INC_ONCE
# |  00,PROTOCOL_TYPE_MPLS,L2_LP_TYPE_NPP   | ****                     | network_rx_mpls_af_and_termination_macro         | PL_INC_ONCE
def config_mac_termination_next_macro_static_table():
    table = mac_termination_next_macro_static_table
    table_data = [
        # IPv4 multicast termination
        {
            "key": {"mac_next_macro_packed_data": 0b10000000000, "ipv4_ipv6_init_rtf_stage": 0b0000},
            "mask":{"mac_next_macro_packed_data": 0b11000000000, "ipv4_ipv6_init_rtf_stage": 0b0000},
            "payload": {"pl_inc": PL_INC_NONE, "macro_id": NETWORK_RX_MAC_RELAY_IPV4_MC_TERMINATION_MACRO},
        },
        # IPv6 multicast termination
        {
            "key": {"mac_next_macro_packed_data": 0b01000000000, "ipv4_ipv6_init_rtf_stage": 0b0000},
            "mask":{"mac_next_macro_packed_data": 0b11000000000, "ipv4_ipv6_init_rtf_stage": 0b0000},
            "payload": {"pl_inc": PL_INC_NONE, "macro_id": NETWORK_RX_MAC_RELAY_IPV6_MC_TERMINATION_MACRO},
        },
        # VXLAN/NVGRE routing cases
        {
            "key": {"mac_next_macro_packed_data": (DONT_CARE << 4) | L2_LP_TYPE_OVERLAY, "ipv4_ipv6_init_rtf_stage": (INIT_RTF_OG << 2) | DONT_CARE},
            "mask":{"mac_next_macro_packed_data": 0b00000001111,                                   "ipv4_ipv6_init_rtf_stage": 0b1100},
            "payload": {"pl_inc": PL_DEC_ONCE, "macro_id": NETWORK_RX_IP_OBJECT_GROUPS_MACRO},
        },
        {
            "key": {"mac_next_macro_packed_data": (DONT_CARE << 4) | L2_LP_TYPE_OVERLAY, "ipv4_ipv6_init_rtf_stage": (INIT_RTF_PRE_FWD_L2 << 2) | DONT_CARE},
            "mask":{"mac_next_macro_packed_data": 0b00000001111,                                   "ipv4_ipv6_init_rtf_stage": 0b1100},
            "payload": {"pl_inc": PL_DEC_ONCE, "macro_id": NETWORK_RX_ETH_RTF_MACRO},
        },
        {
            "key": {"mac_next_macro_packed_data": (DONT_CARE << 4) | L2_LP_TYPE_OVERLAY, "ipv4_ipv6_init_rtf_stage": (INIT_RTF_PRE_FWD_L3 << 2) | DONT_CARE},
            "mask":{"mac_next_macro_packed_data": 0b00000001111,                                   "ipv4_ipv6_init_rtf_stage": 0b1100},
            "payload": {"pl_inc": PL_DEC_ONCE, "macro_id": NETWORK_RX_IPV4_RTF_MACRO},
        },
        # if no RTF is needed on the outer header
        {
            "key": {"mac_next_macro_packed_data": (DONT_CARE << 4) | L2_LP_TYPE_OVERLAY, "ipv4_ipv6_init_rtf_stage": DONT_CARE},
            "mask":{"mac_next_macro_packed_data": 0b00000001111,                                   "ipv4_ipv6_init_rtf_stage": 0b0000},
            "payload": {"pl_inc": PL_INC_ONCE, "macro_id": NETWORK_RX_IP_AF_AND_FORWARDING_MACRO},
        },
        # IPv4 unicast tunnel termination
        {
            "key": {"mac_next_macro_packed_data": (PROTOCOL_TYPE_IPV4 << 4) | L2_LP_TYPE_NPP, "ipv4_ipv6_init_rtf_stage": DONT_CARE},
            "mask":{"mac_next_macro_packed_data": 0b00011111111,                                   "ipv4_ipv6_init_rtf_stage": 0b0000},
            "payload": {"pl_inc": PL_INC_ONCE, "macro_id": NETWORK_RX_IP_AF_AND_TERMINATION_MACRO},
        },
        {
            "key": {"mac_next_macro_packed_data": (PROTOCOL_TYPE_IPV6 << 4) | L2_LP_TYPE_NPP, "ipv4_ipv6_init_rtf_stage": DONT_CARE},
            "mask":{"mac_next_macro_packed_data": 0b00011111111,                                   "ipv4_ipv6_init_rtf_stage": 0b0000},
            "payload": {"pl_inc": PL_INC_ONCE, "macro_id": NETWORK_RX_IP_AF_AND_TERMINATION_MACRO},
        },
        {
            "key": {"mac_next_macro_packed_data": (PROTOCOL_TYPE_MPLS << 4) | L2_LP_TYPE_NPP, "ipv4_ipv6_init_rtf_stage": DONT_CARE},
            "mask":{"mac_next_macro_packed_data": 0b00111111111,                                   "ipv4_ipv6_init_rtf_stage": 0b0000},
            "payload": {"pl_inc": PL_INC_ONCE, "macro_id": NETWORK_RX_MPLS_AF_AND_TERMINATION_MACRO},
        },
    ]

    location = 0
    for line in table_data:
        key = mac_termination_next_macro_static_table_key_t(mac_relay_local_vars_mac_next_macro_packed_data=line["key"]["mac_next_macro_packed_data"],
                                                            ipv4_ipv6_init_rtf_stage=line["key"]["ipv4_ipv6_init_rtf_stage"])
        mask = mac_termination_next_macro_static_table_key_t(mac_relay_local_vars_mac_next_macro_packed_data=line["mask"]["mac_next_macro_packed_data"],
                                                             ipv4_ipv6_init_rtf_stage=line["mask"]["ipv4_ipv6_init_rtf_stage"])
        value = mac_termination_next_macro_static_table_value_t(pl_inc=line["payload"]["pl_inc"],
                                                                macro_id=line["payload"]["macro_id"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


def config_inject_down_select_ene_static_table():
    table = inject_down_select_ene_static_table
    table_data = [
        {
            "key": {"dsp_is_dma": 1,     "fwd_hdr": FWD_HEADER_TYPE_INJECT_DOWN, "inj_down": INJECT_DOWN_ENCAP_TYPE_TO_DMA},
            "mask":{"dsp_is_dma": ALL_1, "fwd_hdr": ALL_1,                       "inj_down": ALL_1,                       },
            "payload": {"next_macro": ENE_DMA_8BYTES_HEADER_MACRO, "dma_decap_header_type": 0x8},
        },
        {
            "key": {"dsp_is_dma": DONT_CARE, "fwd_hdr": DONT_CARE, "inj_down": DONT_CARE},
            "mask":{"dsp_is_dma": DONT_CARE, "fwd_hdr": DONT_CARE, "inj_down": DONT_CARE},
            "payload": {"next_macro": ENE_NOP_MACRO, "dma_decap_header_type": 0x0},
        },
    ]

    location = 0
    for line in table_data:
        key = inject_down_select_ene_static_table_key_t(dsp_is_dma=line["key"]["dsp_is_dma"],
                                                        fwd_header_type=line["key"]["fwd_hdr"],
                                                        inject_down_encap=line["key"]["inj_down"])
        mask = inject_down_select_ene_static_table_key_t(dsp_is_dma=line["mask"]["dsp_is_dma"],
                                                         fwd_header_type=line["mask"]["fwd_hdr"],
                                                         inject_down_encap=line["mask"]["inj_down"])
        value = inject_down_select_ene_static_table_value_t(line["payload"]["next_macro"],
                                                            line["payload"]["dma_decap_header_type"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


# current_ip_version|	post_fwd_rtf_stage|	next_hdr_type|	eth_rtf_stage	|fwd_layer|	rtf_stage	 |  PL_inc| 	macro_id
#-------------------|---------------------|--------------|------------------|---------|--------------|--------| -------------
# dont_care	        |          OG         | dont_care	 |     dont_care	|ip_fwd	  |   dont_care |	none  | 	OG_macro
# dont_care	        |          post_fwd_l2|	dont_care	 |     dont_care	|ip_fwd	  |   post_fwd	 |   none | 	ETH_rtf
# 4	                |          post_fwd_l3|	dont_care	 |     dont_care	|ip_fwd	  |   post_fwd	 |   none | 	ipv4_rtf
# 6	                |          post_fwd_l3|	dont_care	 |     dont_care	|ip_fwd	  |   post_fwd	 |   none | 	ipv6_rtf
# dont_care	        |          dont_care |	dont_care	 |     dont_care	|ip_fwd	  |   post_fwd	 |   none | 	resolution
# dont_care	        |          rx_done_l2 |	dont_care	 |     dont_care	|ip_fwd	  |   rx_done	 |   none | 	eth_rtf
# 4	                |          rx_done_l3 |	dont_care	 |     dont_care	|ip_fwd	  |   rx_done	 |   none | 	ipv4_rtf
# 6	                |          rx_done_l3 |	dont_care	 |     dont_care	|ip_fwd	  |   rx_done	 |   none | 	ipv6_rtf
# dont_care	        |          dont_care |	dont_care	 |     dont_care	|ip_fwd	  |   rx_done	 |   none | 	fwd_done
# dont_care	        |          OG	      |    4	     |     dont_care	|mac_fwd  |	  dont_care |	once  | 	OG_macro
# dont_care	        |          OG	      |    6	     |     dont_care	|mac_fwd  |	  dont_care |	once  | 	OG_macro
# dont_care	        |          post_fwd_l2|	  4	         |     dont_care	|mac_fwd  |	  post_fwd	 |   once | 	ETH_RTF
# dont_care	        |          post_fwd_l3|	  4	         |     dont_care	|mac_fwd  |	  post_fwd	 |   once | 	ipv4_rtf
# dont_care	        |          post_fwd_l2|	  6	         |     dont_care	|mac_fwd  |	  post_fwd	 |   once | 	ETH_RTF
# dont_care	        |          post_fwd_l3|	  6	         |     dont_care	|mac_fwd  |	  post_fwd	 |   once | 	ipv6_rtf
# dont_care	        |          dont_care |	dont_care	 |     post_fwd_l2	|mac_fwd  |   post_fwd	 |   none | 	eth_rtf
# dont_care	        |          dont_care |	dont_care	 |     dont_care	|mac_fwd  |	  post_fwd	 |   none | 	resolution
# dont_care	        |          rx_done_l2 |	  4	         |     dont_care	|mac_fwd  |	  rx_done	 |   once | 	eth_rtf
# dont_care	        |          rx_done_l3 |	  4	         |     dont_care	|mac_fwd  |	  rx_done	 |   once | 	ipv4_rtf
# dont_care	        |          rx_done_l2 |	  6	         |     dont_care	|mac_fwd  |	  rx_done	 |   once | 	eth_rtf
# dont_care	        |          rx_done_l3 |	  6	         |     dont_care	|mac_fwd  |	  rx_done	 |   once | 	ipv6_rtf
# dont_care	        |          dont_care |	dont_care	 |     rx_done_l2	|mac_fwd  |   rx_done	 |   none | 	eth_rtf
# dont_care	        |          dont_care |	dont_care	 |     dont_care	|mac_fwd  |   rx_done	 |   none | 	fwd_done

def config_post_fwd_rtf_next_macro_static_table():
    table = post_fwd_rtf_next_macro_static_table
    table_config = TcamTableConfig("post_fwd_rtf_next_macro_static_table")

    # ip_ver_and_post_fwd_stage: ip_ver, post_fwd_stage
    ver_is_dont_care__post_fwd_stage_is_og          = Key(DONT_CARE <<3 | RTF_OG, mask=0b0111)
    ver_is_dont_care__post_fwd_stage_is_post_fwd_l2 = Key(DONT_CARE <<3 | RTF_POST_FWD_L2, mask=0b0111)
    ver_is_dont_care__post_fwd_stage_is_post_fwd_l3 = Key(DONT_CARE <<3 | RTF_POST_FWD_L3, mask=0b0111)
    ver_is_dont_care__post_fwd_stage_is_rx_done_l2  = Key(DONT_CARE <<3 | RTF_RX_DONE_L2, mask=0b0111)
    ver_is_dont_care__post_fwd_stage_is_rx_done_l3  = Key(DONT_CARE <<3 | RTF_RX_DONE_L3, mask=0b0111)
    ver_is_dont_care__post_fwd_stage_is_dont_care   = Key(DONT_CARE <<3 | DONT_CARE, mask=0b0000)
    ver_is_v4__post_fwd_stage_is_post_fwd_l3        = Key(IP_VERSION_IPV4 <<3 | RTF_POST_FWD_L3, mask=0b1111)
    ver_is_v6__post_fwd_stage_is_post_fwd_l3        = Key(IP_VERSION_IPV6 <<3 | RTF_POST_FWD_L3, mask=0b1111)
    ver_is_v4__post_fwd_stage_is_rx_done_l3         = Key(IP_VERSION_IPV4 <<3 | RTF_RX_DONE_L3, mask=0b1111)
    ver_is_v6__post_fwd_stage_is_rx_done_l3         = Key(IP_VERSION_IPV6 <<3 | RTF_RX_DONE_L3, mask=0b1111)

    # fwd_layer_and_rtf_stage:
    fwd_is_ip__rtf_stage_is_dont_care  = Key(IP_FWD<<2 | DONT_CARE, mask=0b100)
    fwd_is_ip__rtf_stage_is_post_fwd   = Key(IP_FWD<<2 | RTF_POST_FWD, mask=0b111)
    fwd_is_ip__rtf_stage_is_rx_done    = Key(IP_FWD<<2 | RTF_RX_DONE, mask=0b111)
    fwd_is_mac__rtf_stage_is_dont_care = Key(MAC_FWD<<2 | DONT_CARE, mask=0b100)
    fwd_is_mac__rtf_stage_is_post_fwd  = Key(MAC_FWD<<2 | RTF_POST_FWD, mask=0b111)
    fwd_is_mac__rtf_stage_is_rx_done   = Key(MAC_FWD<<2 | RTF_RX_DONE, mask=0b111)

    table_data = [
        {"key": ["ip_ver_and_post_fwd_stage"                    , "next_proto_type"        , "eth_rtf_stage", "fwd_layer_and_rtf_stage"         ], "value": ["pl_inc"    ,   "macro_id"      ]},
        #IP FWD
        {"key": [ver_is_dont_care__post_fwd_stage_is_og         , _DONT_CARE               , _DONT_CARE     ,
                 fwd_is_ip__rtf_stage_is_dont_care ], "value": [PL_INC_NONE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [ver_is_dont_care__post_fwd_stage_is_post_fwd_l2, _DONT_CARE               , _DONT_CARE     , fwd_is_ip__rtf_stage_is_post_fwd  ], "value": [PL_INC_NONE, NETWORK_RX_ETH_RTF_MACRO]},
        {"key": [ver_is_v4__post_fwd_stage_is_post_fwd_l3       , _DONT_CARE               , _DONT_CARE     , fwd_is_ip__rtf_stage_is_post_fwd  ], "value": [PL_INC_NONE, NETWORK_RX_IPV4_RTF_MACRO]},
        {"key": [ver_is_v6__post_fwd_stage_is_post_fwd_l3       , _DONT_CARE               , _DONT_CARE     , fwd_is_ip__rtf_stage_is_post_fwd  ], "value": [PL_INC_NONE, NETWORK_RX_IPV6_RTF_MACRO]},
        {"key": [ver_is_dont_care__post_fwd_stage_is_dont_care  , _DONT_CARE               , _DONT_CARE     , fwd_is_ip__rtf_stage_is_post_fwd  ], "value": [PL_INC_NONE, RESOLUTION_MACRO]},
        {"key": [ver_is_dont_care__post_fwd_stage_is_rx_done_l2 , _DONT_CARE               , _DONT_CARE     , fwd_is_ip__rtf_stage_is_rx_done   ], "value": [PL_INC_NONE, NETWORK_RX_ETH_RTF_MACRO]},
        {"key": [ver_is_v4__post_fwd_stage_is_rx_done_l3        , _DONT_CARE               , _DONT_CARE     , fwd_is_ip__rtf_stage_is_rx_done   ], "value": [PL_INC_NONE, NETWORK_RX_IPV4_RTF_MACRO]},
        {"key": [ver_is_v6__post_fwd_stage_is_rx_done_l3        , _DONT_CARE               , _DONT_CARE     , fwd_is_ip__rtf_stage_is_rx_done   ], "value": [PL_INC_NONE, NETWORK_RX_IPV6_RTF_MACRO]},
        {"key": [ver_is_dont_care__post_fwd_stage_is_dont_care  , _DONT_CARE               , _DONT_CARE     , fwd_is_ip__rtf_stage_is_rx_done   ], "value": [PL_INC_NONE, FORWARDING_DONE]},
        # MAC FWD
        {"key": [ver_is_dont_care__post_fwd_stage_is_og         , PROTOCOL_TYPE_IPV4_SUFFIX, _DONT_CARE     ,
                 fwd_is_mac__rtf_stage_is_dont_care], "value": [PL_INC_ONCE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [ver_is_dont_care__post_fwd_stage_is_og         , PROTOCOL_TYPE_IPV6_SUFFIX, _DONT_CARE     ,
                 fwd_is_mac__rtf_stage_is_dont_care], "value": [PL_INC_ONCE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [ver_is_dont_care__post_fwd_stage_is_post_fwd_l2, PROTOCOL_TYPE_IPV4_SUFFIX, _DONT_CARE     , fwd_is_mac__rtf_stage_is_post_fwd ], "value": [PL_INC_ONCE, NETWORK_RX_ETH_RTF_MACRO]},
        {"key": [ver_is_dont_care__post_fwd_stage_is_post_fwd_l3, PROTOCOL_TYPE_IPV4_SUFFIX, _DONT_CARE     , fwd_is_mac__rtf_stage_is_post_fwd ], "value": [PL_INC_ONCE, NETWORK_RX_IPV4_RTF_MACRO]},
        # if next prot is v4 but ipv4 ACL sequence is empty at current stage
        {"key": [ver_is_dont_care__post_fwd_stage_is_dont_care  , PROTOCOL_TYPE_IPV4_SUFFIX, _DONT_CARE     , fwd_is_mac__rtf_stage_is_post_fwd ], "value": [PL_INC_NONE, RESOLUTION_MACRO]},

        {"key": [ver_is_dont_care__post_fwd_stage_is_post_fwd_l2, PROTOCOL_TYPE_IPV6_SUFFIX, _DONT_CARE     , fwd_is_mac__rtf_stage_is_post_fwd ], "value": [PL_INC_ONCE, NETWORK_RX_ETH_RTF_MACRO]},
        {"key": [ver_is_dont_care__post_fwd_stage_is_post_fwd_l3, PROTOCOL_TYPE_IPV6_SUFFIX, _DONT_CARE     , fwd_is_mac__rtf_stage_is_post_fwd ], "value": [PL_INC_ONCE, NETWORK_RX_IPV6_RTF_MACRO]},
        # if next prot is v6 but ipv6 ACL sequence is empty at current stage
        {"key": [ver_is_dont_care__post_fwd_stage_is_dont_care  , PROTOCOL_TYPE_IPV6_SUFFIX, _DONT_CARE     , fwd_is_mac__rtf_stage_is_post_fwd ], "value": [PL_INC_NONE, RESOLUTION_MACRO]},

        # ETH ACL seq
        {"key": [ver_is_dont_care__post_fwd_stage_is_dont_care  , _DONT_CARE               , RTF_POST_FWD_L2, fwd_is_mac__rtf_stage_is_post_fwd ], "value": [PL_INC_NONE, NETWORK_RX_ETH_RTF_MACRO]},
        # default when current stage is post fwd
        {"key": [ver_is_dont_care__post_fwd_stage_is_dont_care  , _DONT_CARE               , _DONT_CARE     , fwd_is_mac__rtf_stage_is_post_fwd ], "value": [PL_INC_NONE, RESOLUTION_MACRO]},
        {"key": [ver_is_dont_care__post_fwd_stage_is_rx_done_l2 , PROTOCOL_TYPE_IPV4_SUFFIX, _DONT_CARE     , fwd_is_mac__rtf_stage_is_rx_done  ], "value": [PL_INC_ONCE, NETWORK_RX_ETH_RTF_MACRO]},
        {"key": [ver_is_dont_care__post_fwd_stage_is_rx_done_l3 , PROTOCOL_TYPE_IPV4_SUFFIX, _DONT_CARE     , fwd_is_mac__rtf_stage_is_rx_done  ], "value": [PL_INC_ONCE, NETWORK_RX_IPV4_RTF_MACRO]},
        {"key": [ver_is_dont_care__post_fwd_stage_is_dont_care  , PROTOCOL_TYPE_IPV4_SUFFIX, _DONT_CARE     , fwd_is_mac__rtf_stage_is_rx_done  ], "value": [PL_INC_NONE, FORWARDING_DONE]},

        {"key": [ver_is_dont_care__post_fwd_stage_is_rx_done_l2 , PROTOCOL_TYPE_IPV6_SUFFIX, _DONT_CARE     , fwd_is_mac__rtf_stage_is_rx_done  ], "value": [PL_INC_ONCE, NETWORK_RX_ETH_RTF_MACRO]},
        {"key": [ver_is_dont_care__post_fwd_stage_is_rx_done_l3 , PROTOCOL_TYPE_IPV6_SUFFIX, _DONT_CARE     , fwd_is_mac__rtf_stage_is_rx_done  ], "value": [PL_INC_ONCE, NETWORK_RX_IPV6_RTF_MACRO]},
        {"key": [ver_is_dont_care__post_fwd_stage_is_dont_care  , PROTOCOL_TYPE_IPV6_SUFFIX, _DONT_CARE     , fwd_is_mac__rtf_stage_is_rx_done  ], "value": [PL_INC_NONE, FORWARDING_DONE]},

        # ETH ACL seq
        {"key": [ver_is_dont_care__post_fwd_stage_is_dont_care  , _DONT_CARE               , RTF_RX_DONE_L2 , fwd_is_mac__rtf_stage_is_rx_done  ], "value": [PL_INC_ONCE, NETWORK_RX_ETH_RTF_MACRO]},
        # default when current stage is rx_done
        {"key": [ver_is_dont_care__post_fwd_stage_is_dont_care  , _DONT_CARE               , _DONT_CARE     , fwd_is_mac__rtf_stage_is_rx_done  ], "value": [PL_INC_NONE, FORWARDING_DONE]},
    ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)

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
    fwd_layer_is_ip__post_fwd__dont_care         = Key((DONT_CARE << 3 | (IP_FWD<<2)    | RTF_POST_FWD), mask=0b0111)
    fwd_layer_is_mac__pre_fwd__dont_care         = Key((DONT_CARE << 3 | (MAC_FWD<<2)   | RTF_PRE_FWD), mask=0b0111)
    fwd_layer_is_mac__rx_done__dont_care         = Key((DONT_CARE << 3 | (MAC_FWD<<2)   | RTF_RX_DONE), mask=0b0111)
    fwd_layer_is_mac__post_fwd__dont_care        = Key((DONT_CARE << 3 | (MAC_FWD<<2)   | RTF_POST_FWD), mask=0b0111)
    fwd_layer_is_dont_care__dont_care__dont_care = Key((DONT_CARE << 3 | (DONT_CARE<<2) | DONT_CARE), mask=0b0000)
    fwd_layer_is_dont_care__pre_fwd__dont_care   = Key((DONT_CARE << 3 | (DONT_CARE<<2) | RTF_PRE_FWD), mask=0b0011)
    fwd_layer_is_dont_care__post_fwd__dont_care  = Key((DONT_CARE << 3 | (DONT_CARE<<2) | RTF_POST_FWD), mask=0b0011)
    fwd_layer_is_dont_care__rx_done__dont_care   = Key((DONT_CARE << 3 | (DONT_CARE<<2) | RTF_RX_DONE), mask=0b0011)

    table_data = [
        {"key": ["curr_and_next_prot_type"           , "pd_tunnel_ipv4_ipv6_init_rtf_stage", "next_rtf_stage" ,"rtf_indications"                     ]       , "value": ["jump_to_fwd", "pl_inc"   ,    "macro_id"                        ]},
        {"key": [curr_is_dont_care__next_is_dont_care, dont_care__dont_care                , RTF_OG           , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [     0       , PL_INC_NONE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [curr_is_dont_care__next_is_dont_care, dont_care__dont_care                , RTF_PRE_FWD_L2   , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [     0       , PL_INC_NONE, NETWORK_RX_ETH_RTF_MACRO]},
        {"key": [curr_is_v4__next_is_dont_care       , dont_care__dont_care                , RTF_PRE_FWD_L3   , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [     0       , PL_INC_NONE, NETWORK_RX_IPV4_RTF_MACRO]},
        {"key": [curr_is_v6__next_is_dont_care       , dont_care__dont_care                , RTF_PRE_FWD_L3   , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [     0       , PL_INC_NONE, NETWORK_RX_IPV6_RTF_MACRO]},
        {"key": [curr_is_dont_care__next_is_v4       , og__dont_care                       , _DONT_CARE       , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [     0       , PL_INC_ONCE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [curr_is_dont_care__next_is_v4       , pre_fwd_l2__dont_care               , _DONT_CARE       , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [     0       , PL_INC_ONCE, NETWORK_RX_ETH_RTF_MACRO]},
        {"key": [curr_is_dont_care__next_is_v4       , pre_fwd_l3__dont_care               , _DONT_CARE       , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [     0       , PL_INC_ONCE, NETWORK_RX_IPV4_RTF_MACRO]},
        {"key": [curr_is_dont_care__next_is_v6       , dont_care__og                       , _DONT_CARE       , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [     0       , PL_INC_ONCE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [curr_is_dont_care__next_is_v6       , dont_care__pre_fwd_l2               , _DONT_CARE       , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [     0       , PL_INC_ONCE, NETWORK_RX_ETH_RTF_MACRO]},
        {"key": [curr_is_dont_care__next_is_v6       , dont_care__pre_fwd_l3               , _DONT_CARE       , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [     0       , PL_INC_ONCE, NETWORK_RX_IPV6_RTF_MACRO]},
        {"key": [curr_is_dont_care__next_is_dont_care, dont_care__dont_care                , _DONT_CARE       , fwd_layer_is_ip__pre_fwd__acl_outer]         , "value": [     1       , PL_INC_ONCE, NETWORK_RX_IP_AF_AND_FORWARDING_MACRO]},
        {"key": [curr_is_dont_care__next_is_dont_care, dont_care__dont_care                , RTF_OG           , fwd_layer_is_dont_care__dont_care__dont_care], "value": [     0       , PL_INC_NONE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [curr_is_dont_care__next_is_dont_care, dont_care__dont_care                , RTF_PRE_FWD_L2   , fwd_layer_is_dont_care__pre_fwd__dont_care]  , "value": [     0       , PL_INC_NONE, NETWORK_RX_ETH_RTF_MACRO]},
        {"key": [curr_is_v4__next_is_dont_care       , dont_care__dont_care                , RTF_PRE_FWD_L3   , fwd_layer_is_dont_care__pre_fwd__dont_care]  , "value": [     0       , PL_INC_NONE, NETWORK_RX_IPV4_RTF_MACRO]},
        {"key": [curr_is_v6__next_is_dont_care       , dont_care__dont_care                , RTF_PRE_FWD_L3   , fwd_layer_is_dont_care__pre_fwd__dont_care]  , "value": [     0       , PL_INC_NONE, NETWORK_RX_IPV6_RTF_MACRO]},
        {"key": [curr_is_dont_care__next_is_dont_care, dont_care__dont_care                , _DONT_CARE       , fwd_layer_is_ip__pre_fwd__dont_care]         , "value": [     1       , PL_INC_NONE, NETWORK_RX_IP_AF_AND_FORWARDING_MACRO]},
        {"key": [curr_is_v4__next_is_dont_care       , dont_care__dont_care                , _DONT_CARE       , fwd_layer_is_mac__pre_fwd__dont_care]        , "value": [     1       , 3, NETWORK_RX_MAC_FORWARDING_MACRO]},
        {"key": [curr_is_v6__next_is_dont_care       , dont_care__dont_care                , _DONT_CARE       , fwd_layer_is_mac__pre_fwd__dont_care]        , "value": [     1       , 3, NETWORK_RX_MAC_FORWARDING_MACRO]},
        {"key": [curr_is_dont_care__next_is_dont_care, dont_care__dont_care                , _DONT_CARE       , fwd_layer_is_mac__pre_fwd__dont_care]        , "value": [     1       , PL_INC_NONE, NETWORK_RX_MAC_FORWARDING_MACRO]},
        {"key": [curr_is_dont_care__next_is_dont_care, dont_care__dont_care                , RTF_POST_FWD_L2  , fwd_layer_is_dont_care__post_fwd__dont_care] , "value": [     0       , PL_INC_NONE, NETWORK_RX_ETH_RTF_MACRO]},
        {"key": [curr_is_v4__next_is_dont_care       , dont_care__dont_care                , RTF_POST_FWD_L3  , fwd_layer_is_dont_care__post_fwd__dont_care] , "value": [     0       , PL_INC_NONE, NETWORK_RX_IPV4_RTF_MACRO]},
        {"key": [curr_is_v6__next_is_dont_care       , dont_care__dont_care                , RTF_POST_FWD_L3  , fwd_layer_is_dont_care__post_fwd__dont_care] , "value": [     0       , PL_INC_NONE, NETWORK_RX_IPV6_RTF_MACRO]},
        {"key": [curr_is_dont_care__next_is_dont_care, dont_care__dont_care                , _DONT_CARE       , fwd_layer_is_ip__post_fwd__dont_care]        , "value": [     0       , PL_INC_NONE, RESOLUTION_MACRO]},
        {"key": [curr_is_v4__next_is_dont_care       , dont_care__dont_care                , _DONT_CARE       , fwd_layer_is_mac__post_fwd__dont_care]       , "value": [     0       , 3, RESOLUTION_MACRO]},
        {"key": [curr_is_v6__next_is_dont_care       , dont_care__dont_care                , _DONT_CARE       , fwd_layer_is_mac__post_fwd__dont_care]       , "value": [     0       , 3, RESOLUTION_MACRO]},
        {"key": [curr_is_dont_care__next_is_dont_care, dont_care__dont_care                , _DONT_CARE       , fwd_layer_is_mac__post_fwd__dont_care]       , "value": [     0       , PL_INC_NONE, RESOLUTION_MACRO]},
        {"key": [curr_is_dont_care__next_is_dont_care, dont_care__dont_care                , RTF_RX_DONE_L2   , fwd_layer_is_dont_care__rx_done__dont_care]  , "value": [     0       , PL_INC_NONE, NETWORK_RX_ETH_RTF_MACRO]},
        {"key": [curr_is_v4__next_is_dont_care       , dont_care__dont_care                , RTF_RX_DONE_L3   , fwd_layer_is_dont_care__rx_done__dont_care]  , "value": [     0       , PL_INC_NONE, NETWORK_RX_IPV4_RTF_MACRO]},
        {"key": [curr_is_v6__next_is_dont_care       , dont_care__dont_care                , RTF_RX_DONE_L3   , fwd_layer_is_dont_care__rx_done__dont_care]  , "value": [     0       , PL_INC_NONE, NETWORK_RX_IPV6_RTF_MACRO]},
        {"key": [curr_is_v4__next_is_dont_care       , dont_care__dont_care                , _DONT_CARE       , fwd_layer_is_mac__rx_done__dont_care]        , "value": [     0       , 3, FORWARDING_DONE]},
        {"key": [curr_is_v6__next_is_dont_care       , dont_care__dont_care                , _DONT_CARE       , fwd_layer_is_mac__rx_done__dont_care]        , "value": [     0       , 3, FORWARDING_DONE]},
        {"key": [curr_is_dont_care__next_is_dont_care, dont_care__dont_care                , _DONT_CARE       , fwd_layer_is_dont_care__rx_done__dont_care]  , "value": [     0       , PL_INC_NONE, FORWARDING_DONE]},
    ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


def config_cong_level_ecn_remap_map_table():
    table = cong_level_ecn_remap_map_table
    table_config = DirectTableConfig("cong_level_ecn_remap_map_table")
    table_data = [{"key": ["rand", "cong_level"] , "value": ["stat_cong_level_on"]}]
    rand_size, cong_level_size = 2**5, 2**4
    for rnd in range(0, rand_size):
        for cl in range(0, cong_level_size):
            if cl == cong_level_size - 1:
                table_data.append({"key": [rnd, cl], "value": [True]})
            else:
                table_data.append({"key": [rnd, cl], "value": [False]})
    table_config.create_table(table_data, NETWORK_CONTEXT)


def config_sgt_vxlan_termination_table():
    table_config = TcamTableConfig("sgt_vxlan_termination_table")
    table_data = [
        {"key": ["hdr_type_2", "policy_flag"], "value": ["vxlan_terminated"]},
        {"key": [PROTOCOL_TYPE_VXLAN, 0],      "value": [1]},
        {"key": [_DONT_CARE, _DONT_CARE], "value": [0]},
    ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


def config_sgacl_ip_fragment_check_table():
    table_config = TcamTableConfig("sgacl_ip_fragment_check_table")
    table_data = [
        {"key": ["ip_version", "v6_not_first_frag", "v4_frag_offset"], "value": ["first_fragment"]},
        {"key": [IP_VERSION_IPV6, 0, _DONT_CARE],  "value": [1]},
        {"key": [IP_VERSION_IPV4, _DONT_CARE , 0], "value": [1]},
        {"key": [_DONT_CARE, _DONT_CARE, _DONT_CARE], "value": [0]}
    ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


def config_learn_command_type_mapping_table():
    table = learn_command_type_mapping_table
    table_config = DirectTableConfig("learn_command_type_mapping_table")
    for learn_type in range(1, 15):
        key = learn_type
        result = learn_command_type_mapping_table_result_t(key_header_field_shift = 4,
                                                           key_header_field_mask = 12,
                                                           key_data_shift = 52,
                                                           key_data_mask = 14,
                                                           key_data_offset = 142,
                                                           key_db_profile_mask = 4,
                                                           key_db_profile = CENTRAL_EM_LDB_MAC_RELAY_DA,
                                                           key_header_field_offset = 12)
        value = learn_command_type_mapping_table_value_t(learn_command_type_mapping_table_result = result)
        table.insert(NETWORK_CONTEXT, key, value)

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
#|PROTOCOL_TYPE_SVL   |    *        |    0     |      0        | network_resolve_svl_or_lp_over_lag_macro|  PL_INC_NONE
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
            "payload": {"ipc_trap": 0x0, "protocol_trap": 0x0, "pl_inc": PL_INC_NONE, "macro_id": NETWORK_RESOLVE_SVL_OR_LP_OVER_LAG_MACRO},
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

# +------------------+----------------------+-------------------+-------------------+----+----------+---------------------------------+
# |   post_fwd_stage |   current_proto_type |   next_proto_type |   fwd_header_type |    |   pl_inc |       macro_id                  |
# |------------------+----------------------+-------------------+-------------------+----+----------+---------------------------------|
# |                1 |                      |                   |                 0 | >  |        0 |NETWORK_RX_IP_OBJECT_GROUPS_MACRO|
# |                4 |                      |                   |                 0 | >  |        0 |NETWORK_RX_ETH_RTF_MACRO         |
# |                6 |                      |                   |                 0 | >  |        0 |NETWORK_RX_ETH_RTF_MACRO         |
# |                5 |                    4 |                   |                 0 | >  |        0 |NETWORK_RX_IPV4_RTF_MACRO        |
# |                5 |                    6 |                   |                 0 | >  |        0 |NETWORK_RX_IPV6_RTF_MACRO        |
# |                7 |                    4 |                   |                 0 | >  |        0 |NETWORK_RX_IPV4_RTF_MACRO        |
# |                7 |                    6 |                   |                 0 | >  |        0 |NETWORK_RX_IPV6_RTF_MACRO        |
# |                  |                      |                   |                 0 | >  |        0 |FORWARDING_DONE                  |
# |                1 |                      |                   |                   | >  |        1 |NETWORK_RX_IP_OBJECT_GROUPS_MACRO|
# |                4 |                      |                   |                   | >  |        1 |NETWORK_RX_ETH_RTF_MACRO         |
# |                5 |                      |                 4 |                   | >  |        1 |NETWORK_RX_IPV4_RTF_MACRO        |
# |                5 |                      |                 6 |                   | >  |        1 |NETWORK_RX_IPV6_RTF_MACRO        |
# |                  |                      |                   |                   | >  |        1 |RESOLUTION_MACRO                 |
# +------------------+----------------------+-------------------+-------------------+----+----------+---------------------------------+


def config_local_mc_fwd_next_macro_static_table():
    table = local_mc_fwd_next_macro_static_table
    table_config = TcamTableConfig("local_mc_fwd_next_macro_static_table")

    table_data = [
        {"key": ["post_fwd_stage", "current_proto_type"     , "next_proto_type"        , "fwd_header_type"       ], "value": ["pl_inc"    ,   "macro_id"                    ]},
        # FWD header is ETHERNET
        {"key": [  RTF_OG        , _DONT_CARE               , _DONT_CARE               , FWD_HEADER_TYPE_ETHERNET], "value": [PL_INC_NONE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [RTF_POST_FWD_L2 , _DONT_CARE               , _DONT_CARE               , FWD_HEADER_TYPE_ETHERNET], "value": [PL_INC_NONE, NETWORK_RX_ETH_RTF_MACRO         ]},
        {"key": [RTF_RX_DONE_L2  , _DONT_CARE               , _DONT_CARE               , FWD_HEADER_TYPE_ETHERNET], "value": [PL_INC_NONE, NETWORK_RX_ETH_RTF_MACRO         ]},
        {"key": [RTF_POST_FWD_L3 , PROTOCOL_TYPE_IPV4_SUFFIX, _DONT_CARE               , FWD_HEADER_TYPE_ETHERNET], "value": [PL_INC_NONE, NETWORK_RX_IPV4_RTF_MACRO        ]},
        {"key": [RTF_POST_FWD_L3 , PROTOCOL_TYPE_IPV6_SUFFIX, _DONT_CARE               , FWD_HEADER_TYPE_ETHERNET], "value": [PL_INC_NONE, NETWORK_RX_IPV6_RTF_MACRO        ]},
        {"key": [RTF_RX_DONE_L3  , PROTOCOL_TYPE_IPV4_SUFFIX, _DONT_CARE               , FWD_HEADER_TYPE_ETHERNET], "value": [PL_INC_NONE, NETWORK_RX_IPV4_RTF_MACRO        ]},
        {"key": [RTF_RX_DONE_L3  , PROTOCOL_TYPE_IPV6_SUFFIX, _DONT_CARE               , FWD_HEADER_TYPE_ETHERNET], "value": [PL_INC_NONE, NETWORK_RX_IPV6_RTF_MACRO        ]},
        {"key": [_DONT_CARE      , _DONT_CARE               , _DONT_CARE               , FWD_HEADER_TYPE_ETHERNET], "value": [PL_INC_NONE, FORWARDING_DONE                  ]},
        # FWD header is different than ETHERNET - need to inc PL
        {"key": [  RTF_OG        , _DONT_CARE               , _DONT_CARE               , _DONT_CARE              ], "value": [PL_INC_ONCE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [RTF_POST_FWD_L2 , _DONT_CARE               , _DONT_CARE               , _DONT_CARE              ], "value": [PL_INC_ONCE, NETWORK_RX_ETH_RTF_MACRO         ]},
        {"key": [RTF_POST_FWD_L3 , _DONT_CARE               , PROTOCOL_TYPE_IPV4_SUFFIX, _DONT_CARE              ], "value": [PL_INC_ONCE, NETWORK_RX_IPV4_RTF_MACRO        ]},
        {"key": [RTF_POST_FWD_L3 , _DONT_CARE               , PROTOCOL_TYPE_IPV6_SUFFIX, _DONT_CARE              ], "value": [PL_INC_ONCE, NETWORK_RX_IPV6_RTF_MACRO        ]},
        {"key": [_DONT_CARE      , _DONT_CARE               , _DONT_CARE               , _DONT_CARE              ], "value": [PL_INC_ONCE, RESOLUTION_MACRO                 ]},
    ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


# #
# # for NP2 devices , align counter_0_offset to 4 bits
# #
# def config_write_acl_drop_offset_on_pd():
#     table_config = DirectTableConfig("write_acl_drop_offset_on_pd")
#     table_data = [{"key": [ "acl_drop_offset"] , "value": [ "counter_0_offset"]},
#                   {"key": [      0b00        ] , "value": [        0b0000     ]},
#                   {"key": [      0b01        ] , "value": [        0b0001     ]},
#                   {"key": [      0b10        ] , "value": [        0b0010     ]},
#                   {"key": [      0b11        ] , "value": [        0b0011     ]},
#                   ]
#     table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)
