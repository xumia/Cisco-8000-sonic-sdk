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
# pep8_extra_args "--ignore=E2,E5,W2"

from config_tables_utils import *

ENE_END_MACRO = 0
DONT_CARE = 0
_DONT_CARE = Key(value=0, mask=0)
ALL_1 = (1 << 128) - 1


def config_tables():
    config_select_inject_next_macro_static_table()
    config_map_tx_punt_next_macro_static_table()
    config_punt_select_nw_ene_static_table()

    config_map_recyle_tx_to_rx_data_on_pd_static_table()

    config_map_ene_subcode_to8bit_static_table()
    config_mpls_encap_control_static_table()

    config_ip_fwd_header_mapping_to_ethtype_static_table()
    config_mpls_lsp_labels_config_static_table()
    config_mpls_labels_1_to_4_jump_offset_static_table()
    config_first_ene_static_table()
    config_second_ene_static_table()

    config_mpls_vpn_enabled_static_table()
    config_map_more_labels_static_table()
    config_mpls_resolve_service_labels_static_table()
    config_ip_mc_next_macro_static_table()

    config_ecn_remark_static_table()

    config_rx_redirect_next_macro_static_table()
    config_mac_ethernet_rate_limit_type_static_table()

    config_punt_ethertype_static_table()
    config_og_next_macro_static_table()

    config_pfc_offset_from_vector_static_table()
    config_map_inject_ccm_macro_static_table()
    config_acl_map_fi_header_type_to_protocol_number_table()
    config_ipv4_acl_map_protocol_type_to_protocol_number_table()

    config_ip_ver_mc_static_table()
    config_rx_ip_p_counter_offset_static_table()
    config_ip_ingress_cmp_mcid_static_table()

    config_fabric_scaled_mc_map_to_netork_slice_static_table()
    config_nw_smcid_threshold_table()
    config_eve_to_ethernet_ene_static_table()
    config_ene_macro_code_tpid_profile_static_table()
    config_ip_mc_local_inject_type_static_table()
    config_tunnel_qos_static_table()

    config_acl_sport_static_tables()
    config_mpls_l3_lsp_static_table()
    config_mpls_header_offset_in_bytes_static_table()

    config_ipv6_first_fragment_static_table()
    config_obm_next_macro_static_table()
    config_mldp_protection_enabled_static_table()
    config_map_tx_punt_rcy_next_macro_static_table()
    config_l3_tunnel_termination_next_macro_static_table()
    config_l3_termination_next_macro_static_table()
    config_l2_termination_next_macro_static_table()
    config_l2_tunnel_term_next_macro_static_table()
    config_get_ingress_ptp_info_and_is_slp_dm_static_table()
    config_ip_rx_global_counter_table()
    config_get_non_comp_mc_value_static_table()

    config_next_header_1_is_l4_over_ipv4_static_table()
    config_l2_lpts_next_macro_static_table()
    config_null_rtf_next_macro_static_table()
    config_l2_lpts_ctrl_fields_static_table()
    config_urpf_ipsa_dest_is_lpts_static_table()
    config_l2_lpts_skip_p2p_static_table()
    config_oamp_drop_destination_static_table()


def config_select_inject_next_macro_static_table():
    table = select_inject_next_macro_static_table
    table_data = [
        {
            "key"     : {"local_inject_type_7_0_": INJECT_HEADER_TYPE_DOWN,               "protocol": DONT_CARE},
            "mask"    : {"local_inject_type_7_0_": ALL_1,                                 "protocol": DONT_CARE},
            "payload" : {"next_macro": RX_INJECT_POST_PROCESS_MACRO,                      "inc": PL_INC_NONE}
        },
        {
            "key"     : {"local_inject_type_7_0_": INJECT_HEADER_TYPE_DOWN_RX_COUNT,      "protocol": DONT_CARE},
            "mask"    : {"local_inject_type_7_0_": ALL_1,                                 "protocol": DONT_CARE},
            "payload" : {"next_macro": RX_INJECT_POST_PROCESS_MACRO,                      "inc": PL_INC_NONE}
        },
        {
            "key"     : {"local_inject_type_7_0_": INJECT_HEADER_TYPE_TX_REDIRECT_DOWN,   "protocol": DONT_CARE},
            "mask"    : {"local_inject_type_7_0_": ALL_1,                                 "protocol": DONT_CARE},
            "payload" : {"next_macro": RX_INJECT_POST_PROCESS_MACRO,                      "inc": PL_INC_NONE}
        },
        {
            "key"     : {"local_inject_type_7_0_": INJECT_HEADER_TYPE_UP_ETH,             "protocol": DONT_CARE},
            "mask"    : {"local_inject_type_7_0_": ALL_1,                                 "protocol": DONT_CARE},
            "payload" : {"next_macro": NETWORK_RX_MAC_AF_AND_TERMINATION_MACRO,           "inc": PL_INC_NONE}
        },
        {
            "key"     : {"local_inject_type_7_0_": INJECT_HEADER_TYPE_UP_DESTINATION_OVERRIDE,  "protocol": DONT_CARE},
            "mask"    : {"local_inject_type_7_0_": ALL_1,                                       "protocol": DONT_CARE},
            "payload" : {"next_macro": NETWORK_RX_MAC_AF_AND_TERMINATION_MACRO,                 "inc": PL_INC_NONE}
        },
        {
            "key"     : {"local_inject_type_7_0_": INJECT_HEADER_TYPE_UP_IP,              "protocol": DONT_CARE},
            "mask"    : {"local_inject_type_7_0_": ALL_1,                                 "protocol": DONT_CARE},
            "payload" : {"next_macro": NPU_RX_NOP_FWD_MACRO,                              "inc": PL_INC_NONE}
        },
        {
            "key"     : {"local_inject_type_7_0_": INJECT_HEADER_TYPE_UP_MC_VXLAN,        "protocol": DONT_CARE},
            "mask"    : {"local_inject_type_7_0_": ALL_1,                                 "protocol": DONT_CARE},
            "payload" : {"next_macro": NPU_RX_NOP_FWD_MACRO,                              "inc": PL_INC_NONE}
        },
        {
            "key"     : {"local_inject_type_7_0_": INJECT_HEADER_TYPE_UP_STD_PROCESS,     "protocol": DONT_CARE},
            "mask"    : {"local_inject_type_7_0_": ALL_1,                                 "protocol": DONT_CARE},
            "payload" : {"next_macro": NETWORK_RX_MAC_AF_AND_TERMINATION_MACRO,           "inc": PL_INC_NONE}
        },
        {
            "key"     : {"local_inject_type_7_0_": INJECT_HEADER_TYPE_UP_LEARN_RECORD,    "protocol": DONT_CARE},
            "mask"    : {"local_inject_type_7_0_": ALL_1,                                 "protocol": DONT_CARE},
            "payload" : {"next_macro": NETWORK_RX_MAC_LEARN_SET_TRAP_MACRO,               "inc": PL_INC_NONE}
        },
        {
            "key"     : {"local_inject_type_7_0_": INJECT_HEADER_TYPE_UP_IP_LOCAL_MC_ETH, "protocol": PROTOCOL_TYPE_ETHERNET},
            "mask"    : {"local_inject_type_7_0_": ALL_1,                                 "protocol": ALL_1},
            "payload" : {"next_macro": NETWORK_RX_LOCAL_MC_FORWARDING_MACRO,              "inc": PL_INC_ONCE}
        },
        {
            "key"     : {"local_inject_type_7_0_": INJECT_HEADER_TYPE_UP_IP_LOCAL_MC_V4,  "protocol": PROTOCOL_TYPE_ETHERNET},
            "mask"    : {"local_inject_type_7_0_": ALL_1,                                 "protocol": ALL_1},
            "payload" : {"next_macro": NETWORK_RX_LOCAL_MC_FORWARDING_MACRO,              "inc": PL_INC_ONCE}
        },
        {
            "key"     : {"local_inject_type_7_0_": INJECT_HEADER_TYPE_UP_IP_LOCAL_MC_V6,  "protocol": PROTOCOL_TYPE_ETHERNET},
            "mask"    : {"local_inject_type_7_0_": ALL_1,                                 "protocol": ALL_1},
            "payload" : {"next_macro": NETWORK_RX_LOCAL_MC_FORWARDING_MACRO,              "inc": PL_INC_ONCE}
        },
        {
            "key"     : {"local_inject_type_7_0_": INJECT_HEADER_TYPE_UP_IP_LOCAL_MC_ETH, "protocol": DONT_CARE},
            "mask"    : {"local_inject_type_7_0_": ALL_1,                                 "protocol": DONT_CARE},
            "payload" : {"next_macro": NETWORK_RX_LOCAL_MC_FORWARDING_MACRO,              "inc": PL_INC_NONE}
        },
        {
            "key"     : {"local_inject_type_7_0_": INJECT_HEADER_TYPE_UP_IP_LOCAL_MC_V4,  "protocol": DONT_CARE},
            "mask"    : {"local_inject_type_7_0_": ALL_1,                                 "protocol": DONT_CARE},
            "payload" : {"next_macro": NETWORK_RX_LOCAL_MC_FORWARDING_MACRO,              "inc": PL_INC_NONE}
        },
        {
            "key"     : {"local_inject_type_7_0_": INJECT_HEADER_TYPE_UP_IP_LOCAL_MC_V6,  "protocol": DONT_CARE},
            "mask"    : {"local_inject_type_7_0_": ALL_1,                                 "protocol": DONT_CARE},
            "payload" : {"next_macro": NETWORK_RX_LOCAL_MC_FORWARDING_MACRO,              "inc": PL_INC_NONE}
        }
    ]

    location = 0
    for line in table_data:
        key = select_inject_next_macro_static_table_key_t(local_inject_type_7_0_=line["key"]["local_inject_type_7_0_"],
                                                          protocol=line["key"]["protocol"])
        mask = select_inject_next_macro_static_table_key_t(local_inject_type_7_0_=line["mask"]["local_inject_type_7_0_"],
                                                           protocol=line["mask"]["protocol"])
        value = select_inject_next_macro_static_table_value_t(macro_id=line["payload"]["next_macro"],
                                                              pl_inc=line["payload"]["inc"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


def config_ip_mc_local_inject_type_static_table():
    table = ip_mc_local_inject_type_static_table
    table_data = [
        #=========================================================================================================================
        #       Key                                |           Payload                                                           |
        #=========================================================================================================================
        {"key": PROTOCOL_TYPE_ETHERNET, "inject_header_type": INJECT_HEADER_TYPE_UP_IP_LOCAL_MC_ETH},
        {"key": PROTOCOL_TYPE_ETHERNET_VLAN, "inject_header_type": INJECT_HEADER_TYPE_UP_IP_LOCAL_MC_ETH},
        {"key": PROTOCOL_TYPE_IPV4,     "inject_header_type": INJECT_HEADER_TYPE_UP_IP_LOCAL_MC_V4},
        {"key": PROTOCOL_TYPE_IPV4_L4,     "inject_header_type": INJECT_HEADER_TYPE_UP_IP_LOCAL_MC_V4},
        {"key": PROTOCOL_TYPE_IPV6,     "inject_header_type": INJECT_HEADER_TYPE_UP_IP_LOCAL_MC_V6},
        {"key": PROTOCOL_TYPE_IPV6_L4,     "inject_header_type": INJECT_HEADER_TYPE_UP_IP_LOCAL_MC_V6},
        #========================================================================================================================
    ]

    # Init all entries, to avoid uninitialized memory access errors.
    for key in range(0, 32):
        value = ip_mc_local_inject_type_static_table_value_t(pd_ene_encap_data_inject_header_type=INJECT_HEADER_TYPE_UP_IP_LOCAL_MC_ETH)
        table.insert(NETWORK_CONTEXT, key, value)

    for line in table_data:
        key = ip_mc_local_inject_type_static_table_key_t(line["key"])
        value = ip_mc_local_inject_type_static_table_value_t(pd_ene_encap_data_inject_header_type=line["inject_header_type"])
        table.insert(NETWORK_CONTEXT, key, value)


# + --------------------------|------------------------------|-----------------------------------|===========================================|==================|
# |     cud_type              |    encap type                |    encap format                   |         next macro                        |ene_bytes_added   |
# + --------------------------|------------------------------|-----------------------------------|===========================================|==================|
# | PUNT_CUD_TYPE_MC_LPTS     |     DONT_CARE                |     DONT_CARE                     | {tx_punt_transport_macro, PL_INC_NONE}    |   0              |
# | PUNT_CUD_TYPE_MC_IBM      |     DONT_CARE                |     DONT_CARE                     | {tx_punt_macro, PL_INC_NONE}              |   0              |
# | PUNT_CUD_TYPE_MC_ROUTABLE |     DONT_CARE                |     DONT_CARE                     | {tx_punt_rcy_macro, PL_INC_NONE}          |   0              |
# |    DONT_CARE              | PUNT_NW_IP_TUNNEL_ENCAP_TYPE | PUNT_HEADER_FORMAT_TYPE_ERSPAN_II | {tx_punt_transport_macro, PL_INC_NONE}    | 12+4+2+24+4+8    |
# |    DONT_CARE              | PUNT_NW_IP_TUNNEL_NO_VLAN... | PUNT_HEADER_FORMAT_TYPE_ERSPAN_II | {tx_punt_transport_macro, PL_INC_NONE}    | 12+  2+24+4+8    |
# |    DONT_CARE              |     DONT_CARE                | PUNT_HEADER_FORMAT_TYPE_ERSPAN_II | {erspan_II_header_ene_macro, PL_INC_NONE} |   0              |
# | PUNT_CUD_TYPE_IBM         | PUNT_NW_NO_ENCAP_TYPE        |     DONT_CARE                     | {tx_punt_transport_macro, PL_INC_NONE}    |   0              |
# | PUNT_CUD_TYPE_IBM         | PUNT_NW_ETH_ENCAP_TYPE       |     DONT_CARE                     | {tx_punt_transport_macro, PL_INC_NONE}    | 12+4+2+28        |
# | PUNT_CUD_TYPE_IBM         | PUNT_NW_ETH_NO_VLAN_ENCAP... |     DONT_CARE                     | {tx_punt_transport_macro, PL_INC_NONE}    | 12+  2+28        |
# | PUNT_CUD_TYPE_OBM         | PUNT_NW_NO_ENCAP_TYPE        |     DONT_CARE                     | {tx_punt_transport_macro, PL_INC_NONE}    |   0              |
# | PUNT_CUD_TYPE_OBM         | PUNT_NW_ETH_ENCAP_TYPE       |     DONT_CARE                     | {tx_punt_transport_macro, PL_INC_NONE}    | 12+4+2+28        |
# | PUNT_CUD_TYPE_OBM         | PUNT_NW_ETH_NO_VLAN_ENCAP... |     DONT_CARE                     | {tx_punt_transport_macro, PL_INC_NONE}    | 12+  2+28        |
# |    DONT_CARE              | PUNT_PFC_ENCAP_TYPE          |     DONT_CARE                     | {tx_punt_rcy_macro, PL_INC_NONE}          |   0              |
# on miss: {tx_punt_header_ene_macro, PL_INC_NONE}
# + --------------------------|------------------------------|-----------------------------------|===========================================|==================|


def config_map_tx_punt_next_macro_static_table():
    table = map_tx_punt_next_macro_static_table
    table_data = [
        {
            "key": {"cud_type": PUNT_CUD_TYPE_MC_LPTS, "punt_encap_type": 0,         "punt_format": 0},
            "mask":{"cud_type": ALL_1,                 "punt_encap_type": DONT_CARE, "punt_format": DONT_CARE},
            "payload": {"next_macro": TX_PUNT_TRANSPORT_MACRO, "inc": PL_INC_NONE, "ene_bytes_added":0 }
        },
        {
            "key": {"cud_type": PUNT_CUD_TYPE_MC_IBM,   "punt_encap_type": 0,         "punt_format": 0},
            "mask":{"cud_type": ALL_1,                  "punt_encap_type": DONT_CARE, "punt_format": DONT_CARE},
            "payload": {"next_macro": TX_PUNT_MACRO, "inc": PL_INC_NONE, "ene_bytes_added":0 }
        },
        {
            "key": {"cud_type": PUNT_CUD_TYPE_MC_ROUTABLE, "punt_encap_type": 0,         "punt_format": 0},
            "mask":{"cud_type": ALL_1,                     "punt_encap_type": DONT_CARE, "punt_format": DONT_CARE},
            "payload": {"next_macro": TX_PUNT_RCY_MACRO, "inc": PL_INC_NONE, "ene_bytes_added":0 }
        },

        {
            "key": {"cud_type": 0,         "punt_encap_type": PUNT_NW_IP_TUNNEL_ENCAP_TYPE,         "punt_format": PUNT_HEADER_FORMAT_TYPE_ERSPAN_II},
            "mask":{"cud_type": DONT_CARE, "punt_encap_type": ALL_1,                                "punt_format": ALL_1},
            "payload": {"next_macro": TX_PUNT_TRANSPORT_MACRO, "inc": PL_INC_NONE,              "ene_bytes_added":(12+4+2+24+4+8)} #MAC+VLAN+IPV4+GRE(with sn)+ERSPAN
        },
        {
            "key": {"cud_type": 0,         "punt_encap_type": PUNT_NW_IP_TUNNEL_NO_VLAN_ENCAP_TYPE, "punt_format": PUNT_HEADER_FORMAT_TYPE_ERSPAN_II},
            "mask":{"cud_type": DONT_CARE, "punt_encap_type": ALL_1,                                "punt_format": ALL_1},
            "payload": {"next_macro": TX_PUNT_TRANSPORT_MACRO, "inc": PL_INC_NONE,              "ene_bytes_added":(12+2+24+4+8)}   #MAC+IPV4+GRE(with sn)+ERSPAN
        },

        {
            "key": {"cud_type": 0,         "punt_encap_type": PUNT_NW_IPV6_TUNNEL_ENCAP_TYPE,       "punt_format": PUNT_HEADER_FORMAT_TYPE_ERSPAN_II},
            "mask":{"cud_type": DONT_CARE, "punt_encap_type": ALL_1,                                "punt_format": ALL_1},
            "payload": {"next_macro": TX_PUNT_TRANSPORT_MACRO, "inc": PL_INC_NONE,              "ene_bytes_added":(12+4+2+44+4+8)} #MAC+VLAN+IPV6+GRE(with sn)+ERSPAN
        },
        {
            "key": {"cud_type": 0,         "punt_encap_type": PUNT_NW_IPV6_TUNNEL_NO_VLAN_ENCAP_TYPE, "punt_format": PUNT_HEADER_FORMAT_TYPE_ERSPAN_II},
            "mask":{"cud_type": DONT_CARE, "punt_encap_type": ALL_1,                                "punt_format": ALL_1},
            "payload": {"next_macro": TX_PUNT_TRANSPORT_MACRO, "inc": PL_INC_NONE,              "ene_bytes_added":(12+2+44+4+8)}   #MAC+IPV6+GRE(with sn)+ERSPAN
        },
        {
            "key": {"cud_type": 0,         "punt_encap_type": 0,                                       "punt_format": PUNT_HEADER_FORMAT_TYPE_ERSPAN_II},
            "mask":{"cud_type": DONT_CARE, "punt_encap_type": DONT_CARE,                               "punt_format": ALL_1},
            "payload": {"next_macro": ERSPAN_II_HEADER_ENE_MACRO, "inc": PL_INC_NONE,              "ene_bytes_added":0}
        },

        {
            "key": {"cud_type": 0,         "punt_encap_type": PUNT_NW_IP_UDP_ENCAP_TYPE,         "punt_format": PUNT_HEADER_FORMAT_TYPE_UDP},
            "mask":{"cud_type": DONT_CARE, "punt_encap_type": ALL_1,                                "punt_format": ALL_1},
            "payload": {"next_macro": TX_PUNT_TRANSPORT_MACRO, "inc": PL_INC_NONE,              "ene_bytes_added":(12+4+2+20+8+28)} #MAC+VLAN+IPV4+UDP+Punt
        },
        {
            "key": {"cud_type": 0,         "punt_encap_type": PUNT_NW_IP_UDP_NO_VLAN_ENCAP_TYPE, "punt_format": PUNT_HEADER_FORMAT_TYPE_UDP},
            "mask":{"cud_type": DONT_CARE, "punt_encap_type": ALL_1,                                "punt_format": ALL_1},
            "payload": {"next_macro": TX_PUNT_TRANSPORT_MACRO, "inc": PL_INC_NONE,              "ene_bytes_added":(12+2+20+8+28)}   #MAC+IPV4+UDP+Punt
        },

        {
            "key": {"cud_type": 0,         "punt_encap_type": PUNT_NW_IPV6_UDP_ENCAP_TYPE,         "punt_format": PUNT_HEADER_FORMAT_TYPE_UDP},
            "mask":{"cud_type": DONT_CARE, "punt_encap_type": ALL_1,                                "punt_format": ALL_1},
            "payload": {"next_macro": TX_PUNT_TRANSPORT_MACRO, "inc": PL_INC_NONE,              "ene_bytes_added":(12+4+2+20+8+28)} #MAC+VLAN+IPV4+UDP+Punt
        },
        {
            "key": {"cud_type": 0,         "punt_encap_type": PUNT_NW_IPV6_UDP_NO_VLAN_ENCAP_TYPE, "punt_format": PUNT_HEADER_FORMAT_TYPE_UDP},
            "mask":{"cud_type": DONT_CARE, "punt_encap_type": ALL_1,                                "punt_format": ALL_1},
            "payload": {"next_macro": TX_PUNT_TRANSPORT_MACRO, "inc": PL_INC_NONE,              "ene_bytes_added":(12+2+20+8+28)}   #MAC+IPV4+UDP+Punt
        },

        {
            "key": {"cud_type": PUNT_CUD_TYPE_IBM,   "punt_encap_type": PUNT_NW_NO_ENCAP_TYPE,    "punt_format": 0},
            "mask":{"cud_type": ALL_1,               "punt_encap_type": ALL_1,                    "punt_format": DONT_CARE},
            "payload": {"next_macro": TX_PUNT_TRANSPORT_MACRO, "inc": PL_INC_NONE,            "ene_bytes_added": (0)}  #RAW packet
        },
        {
            "key": {"cud_type": PUNT_CUD_TYPE_IBM,   "punt_encap_type": PUNT_NW_ETH_ENCAP_TYPE,    "punt_format": 0},
            "mask":{"cud_type": ALL_1,               "punt_encap_type": ALL_1,                    "punt_format": DONT_CARE},
            "payload": {"next_macro": TX_PUNT_TRANSPORT_MACRO, "inc": PL_INC_NONE,            "ene_bytes_added": (12+4+2+28)} #MAC+VLAN+PUNT_HDR
        },
        {
            "key": {"cud_type": PUNT_CUD_TYPE_IBM,   "punt_encap_type": PUNT_NW_ETH_NO_VLAN_ENCAP_TYPE,    "punt_format": 0},
            "mask":{"cud_type": ALL_1,               "punt_encap_type": ALL_1,                    "punt_format": DONT_CARE},
            "payload": {"next_macro": TX_PUNT_TRANSPORT_MACRO, "inc": PL_INC_NONE,            "ene_bytes_added": (12+2+28)}  #MAC+PUNT-HDR
        },

        {
            "key": {"cud_type": PUNT_CUD_TYPE_OBM,   "punt_encap_type": PUNT_NW_NO_ENCAP_TYPE,    "punt_format": 0},
            "mask":{"cud_type": ALL_1,               "punt_encap_type": ALL_1,                    "punt_format": DONT_CARE},
            "payload": {"next_macro": TX_PUNT_TRANSPORT_MACRO, "inc": PL_INC_NONE,            "ene_bytes_added": (0)}
        },
        {
            "key": {"cud_type": PUNT_CUD_TYPE_OBM,   "punt_encap_type": PUNT_NW_ETH_ENCAP_TYPE,    "punt_format": 0},
            "mask":{"cud_type": ALL_1,               "punt_encap_type": ALL_1,                    "punt_format": DONT_CARE},
            "payload": {"next_macro": TX_PUNT_TRANSPORT_MACRO, "inc": PL_INC_NONE,            "ene_bytes_added": (12+4+2+28)}
        },
        {
            "key": {"cud_type": PUNT_CUD_TYPE_OBM,   "punt_encap_type": PUNT_NW_ETH_NO_VLAN_ENCAP_TYPE,    "punt_format": 0},
            "mask":{"cud_type": ALL_1,               "punt_encap_type": ALL_1,                    "punt_format": DONT_CARE},
            "payload": {"next_macro": TX_PUNT_TRANSPORT_MACRO, "inc": PL_INC_NONE,            "ene_bytes_added": (12+2+28)}
        },

        {
            "key": {"cud_type": 0, "punt_encap_type": PUNT_NW_PFC_ENCAP_TYPE, "punt_format": 0},
            "mask":{"cud_type": DONT_CARE, "punt_encap_type": ALL_1, "punt_format": DONT_CARE},
            "payload": {"next_macro": TX_PUNT_RCY_MACRO, "inc": PL_INC_NONE, "ene_bytes_added":0}
        }
    ]

    location = 0
    for line in table_data:
        key = map_tx_punt_next_macro_static_table_key_t(cud_type=line["key"]["cud_type"],
                                                        punt_encap_type=line["key"]["punt_encap_type"],
                                                        punt_format=line["key"]["punt_format"])
        mask = map_tx_punt_next_macro_static_table_key_t(cud_type=line["mask"]["cud_type"],
                                                         punt_encap_type=line["mask"]["punt_encap_type"],
                                                         punt_format=line["mask"]["punt_format"])
        value = map_tx_punt_next_macro_static_table_value_t(pl_inc=line["payload"]["inc"], macro_id=line["payload"]["next_macro"], ene_bytes_added=line["payload"]["ene_bytes_added"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


def config_punt_select_nw_ene_static_table():
    table_config = DirectTableConfig("punt_select_nw_ene_static_table")
    table_data = [{"key": [ "is_punt_rcy", "punt_nw_encap_type"                 ], "value": [ "first_ene_macro"       , "ene_macro_0"                    , "ene_macro_1"         , "ene_macro_2"]},
                  {"key": [    0         , PUNT_NW_NO_ENCAP_TYPE                ], "value": [ ENE_NOP_MACRO           , ENE_END_MACRO                    , ENE_END_MACRO         , ENE_END_MACRO]},
                  {"key": [    0         , PUNT_NW_ETH_ENCAP_TYPE               ], "value": [ TX_PUNT_HEADER_ENE_MACRO, TX_PUNT_ETH_ENE_MACRO            , ENE_NOP_MACRO         , ENE_END_MACRO]},
                  {"key": [    0         , PUNT_NW_ETH_NO_VLAN_ENCAP_TYPE       ], "value": [ TX_PUNT_HEADER_ENE_MACRO, TX_PUNT_ETH_NO_VLAN_ENE_MACRO    , ENE_NOP_MACRO         , ENE_END_MACRO]},
                  {"key": [    0         , PUNT_NW_IP_TUNNEL_ENCAP_TYPE         ], "value": [ TX_PUNT_HEADER_ENE_MACRO, GRE_NO_KEY_ENE_MACRO             , IPV4_ENE_MACRO        , TX_PUNT_ETH_ENE_MACRO]},
                  {"key": [    0         , PUNT_NW_IP_TUNNEL_NO_VLAN_ENCAP_TYPE ], "value": [ TX_PUNT_HEADER_ENE_MACRO, GRE_NO_KEY_ENE_MACRO             , IPV4_ENE_MACRO        , TX_PUNT_ETH_NO_VLAN_ENE_MACRO]},
                  {"key": [    0         , PUNT_NW_IPV6_TUNNEL_ENCAP_TYPE         ], "value": [ TX_PUNT_HEADER_ENE_MACRO, GRE_NO_KEY_ENE_MACRO           , IPV6_ENE_MACRO        , TX_PUNT_ETH_ENE_MACRO]},
                  {"key": [    0         , PUNT_NW_IPV6_TUNNEL_NO_VLAN_ENCAP_TYPE ], "value": [ TX_PUNT_HEADER_ENE_MACRO, GRE_NO_KEY_ENE_MACRO           , IPV6_ENE_MACRO        , TX_PUNT_ETH_NO_VLAN_ENE_MACRO]},
                  {"key": [    0         , PUNT_NW_IP_UDP_ENCAP_TYPE], "value": [ TX_PUNT_METADATA_ENE_MACRO, UDP_ENE_MACRO, IPV4_ENE_MACRO, TX_PUNT_ETH_ENE_MACRO]},
                  {"key": [    0         , PUNT_NW_IP_UDP_NO_VLAN_ENCAP_TYPE], "value": [ TX_PUNT_METADATA_ENE_MACRO, UDP_ENE_MACRO, IPV4_ENE_MACRO, TX_PUNT_ETH_NO_VLAN_ENE_MACRO]},
                  {"key": [    0         , PUNT_NW_IPV6_UDP_ENCAP_TYPE], "value": [ TX_PUNT_METADATA_ENE_MACRO, UDP_ENE_MACRO, IPV6_ENE_MACRO, TX_PUNT_ETH_ENE_MACRO]},
                  {"key": [    0         , PUNT_NW_IPV6_UDP_NO_VLAN_ENCAP_TYPE], "value": [ TX_PUNT_METADATA_ENE_MACRO, UDP_ENE_MACRO, IPV6_ENE_MACRO, TX_PUNT_ETH_NO_VLAN_ENE_MACRO]},
                  {"key": [    0         , PUNT_NW_NPU_HOST_ENCAP_TYPE          ], "value": [ TX_PUNT_HEADER_ENE_MACRO, TX_PUNT_NPU_HOST_HEADER_ENE_MACRO, ENE_END_MACRO         , ENE_END_MACRO]},
                  {"key": [    0         , PUNT_NW_PFC_ENCAP_TYPE               ], "value": [ TX_PUNT_HEADER_ENE_MACRO, TX_PUNT_NPU_HOST_HEADER_ENE_MACRO, TX_INJECT_HEADER_AND_ETH_HEADER_ENE_MACRO, PUNT_VLAN_ENE_MACRO]},
                  {"key": [    1         , PUNT_NW_NO_ENCAP_TYPE                ], "value": [ ENE_END_MACRO           , ENE_END_MACRO                    , ENE_END_MACRO         , ENE_END_MACRO]},
                  {"key": [    1         , PUNT_NW_ETH_ENCAP_TYPE               ], "value": [ TX_PUNT_HEADER_ENE_MACRO, TX_PUNT_ETH_ENE_MACRO            , TX_INJECT_HEADER_AND_ETH_HEADER_ENE_MACRO, PUNT_VLAN_ENE_MACRO]},
                  {"key": [    1         , PUNT_NW_ETH_NO_VLAN_ENCAP_TYPE       ], "value": [ TX_PUNT_HEADER_ENE_MACRO, TX_PUNT_ETH_NO_VLAN_ENE_MACRO    , ENE_NOP_MACRO         , ENE_END_MACRO]},
                  {"key": [    1         , PUNT_NW_IP_TUNNEL_ENCAP_TYPE         ], "value": [ TX_PUNT_HEADER_ENE_MACRO, GRE_NO_KEY_ENE_MACRO             , IPV4_ENE_MACRO        , TX_PUNT_ETH_ENE_MACRO]},
                  {"key": [    1         , PUNT_NW_IP_TUNNEL_NO_VLAN_ENCAP_TYPE ], "value": [ TX_PUNT_HEADER_ENE_MACRO, GRE_NO_KEY_ENE_MACRO             , IPV4_ENE_MACRO        , TX_PUNT_ETH_NO_VLAN_ENE_MACRO]},
                  {"key": [    1         , PUNT_NW_IPV6_TUNNEL_ENCAP_TYPE         ], "value": [ TX_PUNT_HEADER_ENE_MACRO, GRE_NO_KEY_ENE_MACRO           , IPV6_ENE_MACRO        , TX_PUNT_ETH_ENE_MACRO]},
                  {"key": [    1         , PUNT_NW_IPV6_TUNNEL_NO_VLAN_ENCAP_TYPE ], "value": [ TX_PUNT_HEADER_ENE_MACRO, GRE_NO_KEY_ENE_MACRO           , IPV6_ENE_MACRO        , TX_PUNT_ETH_NO_VLAN_ENE_MACRO]},
                  {"key": [    1         , PUNT_NW_IP_UDP_ENCAP_TYPE], "value": [ TX_PUNT_METADATA_ENE_MACRO, UDP_ENE_MACRO, IPV4_ENE_MACRO, TX_PUNT_ETH_ENE_MACRO]},
                  {"key": [    1         , PUNT_NW_IP_UDP_NO_VLAN_ENCAP_TYPE], "value": [ TX_PUNT_METADATA_ENE_MACRO, UDP_ENE_MACRO, IPV4_ENE_MACRO, TX_PUNT_ETH_NO_VLAN_ENE_MACRO]},
                  {"key": [    1         , PUNT_NW_IPV6_UDP_ENCAP_TYPE], "value": [ TX_PUNT_METADATA_ENE_MACRO, UDP_ENE_MACRO, IPV6_ENE_MACRO, TX_PUNT_ETH_ENE_MACRO]},
                  {"key": [    1         , PUNT_NW_IPV6_UDP_NO_VLAN_ENCAP_TYPE], "value": [ TX_PUNT_METADATA_ENE_MACRO, UDP_ENE_MACRO, IPV6_ENE_MACRO, TX_PUNT_ETH_NO_VLAN_ENE_MACRO]},
                  {"key": [    1         , PUNT_NW_NPU_HOST_ENCAP_TYPE          ], "value": [ TX_PUNT_HEADER_ENE_MACRO, TX_PUNT_NPU_HOST_HEADER_ENE_MACRO, TX_INJECT_HEADER_AND_ETH_HEADER_ENE_MACRO, PUNT_VLAN_ENE_MACRO]},
                  {"key": [    1         , PUNT_NW_PFC_ENCAP_TYPE               ], "value": [ TX_PUNT_HEADER_ENE_MACRO, TX_PUNT_NPU_HOST_HEADER_ENE_MACRO, TX_INJECT_HEADER_AND_ETH_HEADER_ENE_MACRO, PUNT_VLAN_ENE_MACRO]},
                  ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


def config_map_recyle_tx_to_rx_data_on_pd_static_table():
    table = map_recyle_tx_to_rx_data_on_pd_static_table
    table_data = [
        #========================================================================================================================
        #               Key                          |                  Payload                                                 |
        #========================================================================================================================
        {"dsp_punt_rcy": 0, "dsp_is_scheduled_rcy": 0, "tx_to_rx_rcy_data": TX_NULL_MIRROR_CODE},
        {"dsp_punt_rcy": 0, "dsp_is_scheduled_rcy": 1, "tx_to_rx_rcy_data": TX_NULL_MIRROR_CODE},
        {"dsp_punt_rcy": 1, "dsp_is_scheduled_rcy": 0, "tx_to_rx_rcy_data": TX2RX_RCY_DATA_INJECT_DOWN_TO_DMA_PORT},
        {"dsp_punt_rcy": 1, "dsp_is_scheduled_rcy": 1, "tx_to_rx_rcy_data": TX2RX_RCY_DATA_INJECT_DOWN_TO_SCHEDULED_RCY_DMA_PORT}
        #========================================================================================================================
    ]

    for line in table_data:
        key_data = dsp_map_info_t (dsp_punt_rcy=line["dsp_punt_rcy"],dsp_is_scheduled_rcy=line["dsp_is_scheduled_rcy"])

        key = map_recyle_tx_to_rx_data_on_pd_static_table_key_t (dsp_map_dma_info=key_data)
        value = map_recyle_tx_to_rx_data_on_pd_static_table_value_t(line["tx_to_rx_rcy_data"])
        table.insert(NETWORK_CONTEXT, key, value)


def config_mac_to_vxlan_next_nw_macro_static_table():
    table = mac_to_vxlan_next_nw_macro_static_table
    table_data = [
        #=================================================================================
        #     Key    |                  Payload                                          |
        #=================================================================================
        {"lp_set": 0, "pl_inc": PL_INC_NONE, "macro_id": NETWORK_TX_QOS_MACRO},
        {"lp_set": 1, "pl_inc": PL_INC_NONE, "macro_id": NETWORK_TX_MAC_AC_AND_ACL_MACRO},
        #=================================================================================
    ]

    for line in table_data:
        key = mac_to_vxlan_next_nw_macro_static_table_key_t(l2_dlp_attributes_vxlan_lp_set=line["lp_set"])
        value = mac_to_vxlan_next_nw_macro_static_table_value_t(pl_inc=line["pl_inc"], macro_id=line["macro_id"])
        table.insert(NETWORK_CONTEXT, key, value)


def config_mac_tx_to_pwe_first_ene_macro_static_table():
    table = mac_tx_to_pwe_first_ene_macro_static_table
    # This is currently mapped to TCAM because of lack of SRAM in level 6, so configuring it like
    # sram table. setting mask hard coded to 1 in both fields
    table_data = [
        #=========================================================================
        #     Key                 |                  Payload                     |
        #=========================================================================
        {"pwe_cw": 1, "pwe_fat": 1, "first_ene_macro": ENE_NOP_MACRO},  # We do not support PWE fat yet
        {"pwe_cw": 1, "pwe_fat": 0, "first_ene_macro": ENE_NOP_MACRO},
        {"pwe_cw": 0, "pwe_fat": 1, "first_ene_macro": ENE_NOP_MACRO},  # We do not support PWE fat yet
        {"pwe_cw": 0, "pwe_fat": 0, "first_ene_macro": ENE_NOP_MACRO},
        #=========================================================================
    ]

    location = 0
    mask = mac_tx_to_pwe_first_ene_macro_static_table_key_t(l2_dlp_attributes_pwe_cw=0b1, l2_dlp_attributes_pwe_fat=0b1)
    for line in table_data:
        key = mac_tx_to_pwe_first_ene_macro_static_table_key_t(
            l2_dlp_attributes_pwe_cw=line["pwe_cw"],
            l2_dlp_attributes_pwe_fat=line["pwe_fat"])
        value = mac_tx_to_pwe_first_ene_macro_static_table_value_t(pd_first_ene_macro=line["first_ene_macro"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


def config_map_ene_subcode_to8bit_static_table():
    table = map_ene_subcode_to8bit_static_table
    location = 0
    for encap_format in range(0, 2):
        for lpts_flow_type in range(0, 16):
            key = map_ene_subcode_to8bit_static_table_key_t(
                tx_npu_header_encap_punt_mc_expand_encap_lpts_flow_type=lpts_flow_type,
                tx_npu_header_ingress_punt_encap_data_mirror_local_encap_format=encap_format)
            if (encap_format == 0):
                value = map_ene_subcode_to8bit_static_table_value_t(lpts_flow_type)
            else:
                value = map_ene_subcode_to8bit_static_table_value_t(0)
            table.insert(NETWORK_CONTEXT, key, value)
            location += 1


def config_mpls_encap_control_static_table():
    table = mpls_encap_control_static_table

    for lsp_type in range(0,4):
        asbr = int(lsp_type & 0b01 == 0b01)
        vpn = int(lsp_type & 0b10 == 0b10)
        for encap_type in range(0,16):
            is_midpoint = encap_type == NPU_ENCAP_L3_HEADER_TYPE_ILM_LABEL or encap_type == NPU_ENCAP_L3_HEADER_TYPE_ILM_TUNNEL
            is_ldpote   = encap_type == NPU_ENCAP_L3_HEADER_TYPE_LDP_OVER_TE
            is_asbr     = asbr and not is_midpoint
            is_headend  = encap_type & 0b1000 == 0b1000
            is_backup_tunnel = encap_type == NPU_ENCAP_L3_HEADER_TYPE_ILM_TUNNEL

            mpls_labels_lookup  = int(is_headend or is_backup_tunnel)
            is_asbr_or_ldpote   = int(is_ldpote or is_asbr)
            mpls_encap_control_bits = is_midpoint <<2 | mpls_labels_lookup <<1 | is_asbr_or_ldpote

            key = mpls_encap_control_static_table_key_t(lsp_type=lsp_type, encap_type=encap_type)
            value = mpls_encap_control_static_table_value_t(
                mpls_encap_control_bits = mpls_encap_control_bits,
                is_vpn                  = int(vpn and not is_midpoint),
                is_asbr                 = int(is_asbr))

            table.insert(NETWORK_CONTEXT, key, value)


def config_ip_fwd_header_mapping_to_ethtype_static_table():
    table = ip_fwd_header_mapping_to_ethtype_static_table

    table_data = [
        {"fwd_header_type": FWD_HEADER_TYPE_IPV4,              "is_mpls_fwd": 0, "is_underlying_ip_proto": 1, "is_v4":1},
        {"fwd_header_type": FWD_HEADER_TYPE_IPV4_COLLAPSED_MC, "is_mpls_fwd": 0, "is_underlying_ip_proto": 1, "is_v4":1},
        {"fwd_header_type": FWD_HEADER_TYPE_IPV6,              "is_mpls_fwd": 0, "is_underlying_ip_proto": 1, "is_v4":0},
        {"fwd_header_type": FWD_HEADER_TYPE_IPV6_COLLAPSED_MC, "is_mpls_fwd": 0, "is_underlying_ip_proto": 1, "is_v4":0},
        {"fwd_header_type": FWD_HEADER_TYPE_MPLS_NO_BOS,       "is_mpls_fwd": 1, "is_underlying_ip_proto": 0, "is_v4":0},
        {"fwd_header_type": FWD_HEADER_TYPE_MPLS_BOS_ETHERNET, "is_mpls_fwd": 1, "is_underlying_ip_proto": 0, "is_v4":0},
        {"fwd_header_type": FWD_HEADER_TYPE_MPLS_BOS_IPV4,     "is_mpls_fwd": 1, "is_underlying_ip_proto": 1, "is_v4":1},
        {"fwd_header_type": FWD_HEADER_TYPE_MPLS_BOS_IPV6,     "is_mpls_fwd": 1, "is_underlying_ip_proto": 1, "is_v4":0}
    ]

    for fwd_header_type in range(0,16):
        key = ip_fwd_header_mapping_to_ethtype_static_table_key_t(tx_npu_header_fwd_header_type=fwd_header_type)
        value = ip_fwd_header_mapping_to_ethtype_static_table_value_t(
            local_tx_ip_mapping=local_tx_ip_mapping_t(is_mpls_fwd=0, is_underlying_ip_proto=0, is_mapped_v4=0))
        table.insert(NETWORK_CONTEXT, key, value)

    for line in table_data:
        key = ip_fwd_header_mapping_to_ethtype_static_table_key_t(tx_npu_header_fwd_header_type=line["fwd_header_type"])
        value = ip_fwd_header_mapping_to_ethtype_static_table_value_t(
            local_tx_ip_mapping=local_tx_ip_mapping_t(line["is_mpls_fwd"], line["is_underlying_ip_proto"], line["is_v4"]))
        table.insert(NETWORK_CONTEXT, key, value)


# |     first_macro_code    |                ene_macro                 |
# | QOS_ENE_MACRO_NOP       | ENE_NOP_MACRO                            |
# | QOS_ENE_MACRO_L3_VPN    | VPN_OR_6PE_LABEL_ENE_MACRO               |
# | QOS_ENE_MACRO_EL        | ENE_NOP_MACRO                            |
# | QOS_ENE_MACRO_L3_VPN_EL | VPN_OR_6PE_LABEL_ENE_MACRO               |
# | QOS_ENE_MACRO_L2_VPN    | VPN_OR_6PE_LABEL_ENE_MACRO               |
def config_first_ene_static_table():
    table_config = DirectTableConfig("first_ene_static_table")
    table_data = [{"key": [ "first_macro_code"    ] , "value": [ "first_ene_macro"]},
                  {"key": [QOS_ENE_MACRO_NOP      ] , "value": [ENE_NOP_MACRO]},
                  {"key": [QOS_ENE_MACRO_L3_VPN   ] , "value": [VPN_OR_6PE_LABEL_ENE_MACRO]},
                  {"key": [QOS_ENE_MACRO_EL       ] , "value": [ENE_NOP_MACRO]},
                  {"key": [QOS_ENE_MACRO_L3_VPN_EL] , "value": [VPN_OR_6PE_LABEL_ENE_MACRO]},
                  {"key": [QOS_ENE_MACRO_L2_VPN   ] , "value": [VPN_OR_6PE_LABEL_ENE_MACRO]},
                  ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


def config_second_ene_static_table():
    table = second_ene_static_table

    table_data = [
        {"second_ene_macro_code": SECOND_ENE_NOP,        "second_ene_macro": ENE_NOP_MACRO},
        {"second_ene_macro_code": SECOND_ENE_1TO4,       "second_ene_macro": MPLS_IMPOSE_1_TO_4_FIRST_LABELS_ENE_MACRO},
        {"second_ene_macro_code": SECOND_ENE_INNER,      "second_ene_macro": MPLS_IMPOSE_INNER_LABEL_ENE_MACRO},
        {"second_ene_macro_code": SECOND_ENE_1TO4_INNER, "second_ene_macro": MPLS_IMPOSE_INNER_AND_1_TO_4_LABELS_ENE_MACRO},
    ]

    location = 0
    for line in table_data:
        key = second_ene_static_table_key_t(
            second_ene_macro_code=line["second_ene_macro_code"])
        mask = second_ene_static_table_key_t(
            second_ene_macro_code=ALL_1)
        value = second_ene_static_table_value_t(
            second_ene_macro=line["second_ene_macro"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


def config_mpls_labels_1_to_4_jump_offset_static_table():
    table = mpls_labels_1_to_4_jump_offset_static_table

    table_data = [
        {"jump_offset": ENE_JUMP_OFFSET_0, "offsets": [ENE_JUMP_OFFSET_DO_NOT_JUMP,
                                                       ENE_JUMP_OFFSET_DO_NOT_JUMP]},
        {"jump_offset": ENE_JUMP_OFFSET_1, "offsets": [ENE_JUMP_OFFSET_MPLS_IMPOSED_FIRST_LABEL,
                                                       ENE_JUMP_OFFSET_DO_NOT_JUMP]},
        {"jump_offset": ENE_JUMP_OFFSET_2, "offsets": [ENE_JUMP_OFFSET_DO_NOT_JUMP,
                                                       ENE_JUMP_OFFSET_MPLS_IMPOSED_SECOND_LABEL]},
        {"jump_offset": ENE_JUMP_OFFSET_3, "offsets": [ENE_JUMP_OFFSET_DO_NOT_JUMP,
                                                       ENE_JUMP_OFFSET_DO_NOT_JUMP]}   # not actually used
    ]

    for line in table_data:
        key = mpls_labels_1_to_4_jump_offset_static_table_key_t(jump_offset_code=line["jump_offset"])

        first_two_labels_offset = lsp_impose_2_mpls_labels_ene_offset_t (
            lsp_two_labels_ene_jump_offset=line["offsets"][1],
            lsp_one_label_ene_jump_offset=line["offsets"][0],
        )
        jump_offset = lsp_impose_mpls_labels_ene_offset_t(
            first_two_labels_offset)

        value = mpls_labels_1_to_4_jump_offset_static_table_value_t(jump_offsets=jump_offset)
        table.insert(NETWORK_CONTEXT, key, value)


def config_mpls_lsp_labels_config_static_table():
    table = mpls_lsp_labels_config_static_table

    for num_labels in range(0,16):
        for is_3_label in [0,1]:
            actual_outer_labels = 3 if is_3_label == 1 else num_labels
            for inner in [0, 1]:
                macro = ENE_END_MACRO
                if inner == 0 and actual_outer_labels == 0:
                    macro = SECOND_ENE_NOP
                elif inner == 0 and actual_outer_labels <= 8:
                    macro = SECOND_ENE_1TO4
                elif inner == 1 and actual_outer_labels == 0:
                    macro = SECOND_ENE_INNER
                elif inner == 1 and actual_outer_labels <= 8:
                    macro = SECOND_ENE_1TO4_INNER

                offsets = ENE_JUMP_OFFSET_0
                if actual_outer_labels == 1:
                    offsets = ENE_JUMP_OFFSET_1
                elif actual_outer_labels > 1 and actual_outer_labels <=8:
                    offsets = ENE_JUMP_OFFSET_2

                if is_3_label == 1:
                    offsets = ENE_JUMP_OFFSET_3

                key = mpls_lsp_labels_config_static_table_key_t(
                    num_outer_transport_labels   = (num_labels << 1) + is_3_label,
                    inner_transport_labels_exist = inner)

                value = mpls_lsp_labels_config_static_table_value_t(
                    num_labels_is_8              = int(actual_outer_labels == 8),
                    outer_transport_labels_exist = int(actual_outer_labels > 0),
                    additional_labels_exist      = int(actual_outer_labels > 2 and int(is_3_label == 0)),
                    transport_labels_size        = (actual_outer_labels + inner) * 4,
                    second_ene_macro_code        = macro,
                    jump_offset_code             = offsets)

                table.insert(NETWORK_CONTEXT, key, value)


# te_headend_lsp_counter_offset_table
#   is_mc   fwd_hdr_type  l3_encap_type  > counter_offset       | comments
#0. X       IPV6          MPLS_HE_SR     >              1       | ipv6=1
#1. X       MPLS          MPLS_HE_SR     >              2       | mpls=2
#2. default                              >              0       | ipv4=0, all others=0 too

def config_te_headend_lsp_counter_offset_table():
    table = te_headend_lsp_counter_offset_table
    table_data = [
        {
            "key":  {"is_mc": 0,         "fwd_header_type": FWD_HEADER_TYPE_IPV6, "l3_encap_type": NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE_SR},
            "mask": {"is_mc": DONT_CARE, "fwd_header_type": 0b1110,               "l3_encap_type": ALL_1},
            "payload": {"counter_offset": 1}
        },
        {
            "key":  {"is_mc": 0,         "fwd_header_type": FWD_HEADER_TYPE_MPLS_NO_BOS, "l3_encap_type": NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE_SR},
            "mask": {"is_mc": DONT_CARE, "fwd_header_type": 0b1100,                      "l3_encap_type": ALL_1},
            "payload": {"counter_offset": 2}
        },
    ]

    location = 0
    for line in table_data:
        key = te_headend_lsp_counter_offset_table_key_t(
            l3_encap_type=line["key"]["l3_encap_type"],
            fwd_header_type=line["key"]["fwd_header_type"],
            is_mc=line["key"]["is_mc"] )
        key = te_headend_lsp_counter_offset_table_key_t(       # BUD: should this be mask= ??????
            l3_encap_type=line["mask"]["l3_encap_type"],
            fwd_header_type=line["mask"]["fwd_header_type"],
            is_mc=line["mask"]["is_mc"] )
        value = te_headend_lsp_counter_offset_table_value_t(
            lsp_counter_offset=line["payload"]["counter_offset"] )
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


#   | is_vpn | fwd_hdr_type |  relay_id | ip_prefix_id |   >  | vpn_enabled | is_l2_vpn |               comments                          |
# 0.|    1   |     MPLS     |     0     |       X      |   >  |      0      |     0     | No VPN for MPLS in global vrf                   |
# 1.|    1   |     IPV4     |     0     |       X      |   >  |      0      |     0     | No VPN for v4 in global vrf                     |
# 2.|    1   |      X       |     X     |       X      |   >  |      1      |     0     | VPN label is L3-VPN/6VPE                        |
# 3.|    X   |      X       |     X     |       1      |   >  |      1      |     0     | VPN label is L3-VPN/6VPE (ip_prefix_id implied) |
# 4.|    X   |  Ethernet    |     X     |       X      |   >  |      1      |     1     | VPN label is L2-VPN (PWE)                       |
# 5.| -----------Default  Entry -----------------------|   >  |      0      |     0     | No VPN                                          |

def config_mpls_vpn_enabled_static_table():
    table = mpls_vpn_enabled_static_table
    table_data = [
        {
            "key":  {"is_vpn": 1,         "fwd_hdr_type": FWD_HEADER_TYPE_MPLS_NO_BOS, "relay_id": 0,         "is_prefix_id": 0},
            "mask": {"is_vpn": 1,         "fwd_hdr_type": 0b1100,                      "relay_id": ALL_1,     "is_prefix_id": DONT_CARE},
            "payload": {"is_l2_vpn": 0, "vpn_enabled": 0}
        },
        {
            "key":  {"is_vpn": 1,         "fwd_hdr_type": FWD_HEADER_TYPE_IPV4,        "relay_id": 0,         "is_prefix_id": 0},
            "mask": {"is_vpn": 1,         "fwd_hdr_type": 0b1110,                      "relay_id": ALL_1,     "is_prefix_id": DONT_CARE},
            "payload": {"is_l2_vpn": 0, "vpn_enabled": 0}
        },
        {
            "key":  {"is_vpn": 1,         "fwd_hdr_type": 0,                           "relay_id": 0,         "is_prefix_id": 0},
            "mask": {"is_vpn": 1,         "fwd_hdr_type": DONT_CARE,                   "relay_id": DONT_CARE, "is_prefix_id": DONT_CARE},
            "payload": {"is_l2_vpn": 0, "vpn_enabled": 1}
        },
        {
            "key":  {"is_vpn": 0,         "fwd_hdr_type": FWD_HEADER_TYPE_ETHERNET,    "relay_id": 0,         "is_prefix_id": 0},
            "mask": {"is_vpn": DONT_CARE, "fwd_hdr_type": ALL_1,                       "relay_id": DONT_CARE, "is_prefix_id": DONT_CARE},
            "payload": {"is_l2_vpn": 1, "vpn_enabled": 1}
        },
        {
            "key":  {"is_vpn": 0,         "fwd_hdr_type": 0,                           "relay_id": 0,         "is_prefix_id": DESTINATION_IP_PREFIX_ID_PREFIX},
            "mask": {"is_vpn": DONT_CARE, "fwd_hdr_type": DONT_CARE,                   "relay_id": DONT_CARE, "is_prefix_id": ALL_1},
            "payload": {"is_l2_vpn": 0, "vpn_enabled": 1}
        },
        {
            "key":  {"is_vpn": 0,         "fwd_hdr_type": 0,                           "relay_id": 0,         "is_prefix_id": 0},
            "mask": {"is_vpn": DONT_CARE, "fwd_hdr_type": DONT_CARE,                   "relay_id": DONT_CARE, "is_prefix_id": DONT_CARE},
            "payload": {"is_l2_vpn": 0, "vpn_enabled": 0}
        }
    ]

    location = 0
    for line in table_data:
        key = mpls_vpn_enabled_static_table_key_t(
            is_prefix_id=line["key"]["is_prefix_id"],
            l3_relay_id=line["key"]["relay_id"],
            fwd_header_type=line["key"]["fwd_hdr_type"],
            is_vpn=line["key"]["is_vpn"] )
        mask = mpls_vpn_enabled_static_table_key_t(
            is_prefix_id=line["mask"]["is_prefix_id"],
            l3_relay_id=line["mask"]["relay_id"],
            fwd_header_type=line["mask"]["fwd_hdr_type"],
            is_vpn=line["mask"]["is_vpn"] )
        value = mpls_vpn_enabled_static_table_value_t(
            vpn_enabled=line["payload"]["vpn_enabled"],
            is_l2_vpn=line["payload"]["is_l2_vpn"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


def config_map_more_labels_static_table():
    table = map_more_labels_static_table

    # Note that for 3, 4, and 5 labels, the jump offset for five labels is always set up
    # Also, the 4-bit key msb indicates if the number of labels is 8 or not, so values 8-15 all mean 8 labels
    table_data = [
        {"num_labels_is_8": 0, "num_labels": 0,  "jump_offset_3_labels": 0, "jump_offset_4_labels": 0, "jump_offset_5_labels": 0,
            "jump_offset_6_labels": 0, "jump_offset_7_labels": 0},
        {"num_labels_is_8": 0, "num_labels": 1,  "jump_offset_3_labels": 0, "jump_offset_4_labels": 0, "jump_offset_5_labels": 0,
            "jump_offset_6_labels": 0, "jump_offset_7_labels": 0},
        {"num_labels_is_8": 0, "num_labels": 2,  "jump_offset_3_labels": 0, "jump_offset_4_labels": 0, "jump_offset_5_labels": 0,
            "jump_offset_6_labels": 0, "jump_offset_7_labels": 0},
        {"num_labels_is_8": 0, "num_labels": 3,  "jump_offset_3_labels": ENE_JUMP_OFFSET_MPLS_IMPOSED_THIRD_LABEL, "jump_offset_4_labels": 0,
            "jump_offset_5_labels": ENE_JUMP_OFFSET_MPLS_IMPOSED_FIFTH_LABEL, "jump_offset_6_labels": 0, "jump_offset_7_labels": 0},
        {"num_labels_is_8": 0, "num_labels": 4,  "jump_offset_3_labels": 0, "jump_offset_4_labels": ENE_JUMP_OFFSET_MPLS_IMPOSED_FOURTH_LABEL,
            "jump_offset_5_labels": ENE_JUMP_OFFSET_MPLS_IMPOSED_FIFTH_LABEL, "jump_offset_6_labels": 0, "jump_offset_7_labels": 0},
        {"num_labels_is_8": 0, "num_labels": 5,  "jump_offset_3_labels": 0, "jump_offset_4_labels": 0,
            "jump_offset_5_labels": ENE_JUMP_OFFSET_MPLS_IMPOSED_FIFTH_LABEL, "jump_offset_6_labels": 0, "jump_offset_7_labels": 0},
        {"num_labels_is_8": 0, "num_labels": 6,  "jump_offset_3_labels": 0, "jump_offset_4_labels": 0, "jump_offset_5_labels": 0,
            "jump_offset_6_labels": ENE_JUMP_OFFSET_MPLS_IMPOSED_SIXTH_LABEL, "jump_offset_7_labels": 0},
        {"num_labels_is_8": 0, "num_labels": 7,  "jump_offset_3_labels": 0, "jump_offset_4_labels": 0, "jump_offset_5_labels": 0,
            "jump_offset_6_labels": 0, "jump_offset_7_labels": ENE_JUMP_OFFSET_MPLS_IMPOSED_SEVENTH_LABEL},
        {"num_labels_is_8": 1, "num_labels": 0,  "jump_offset_3_labels": 0, "jump_offset_4_labels": 0, "jump_offset_5_labels": 0,
            "jump_offset_6_labels": 0, "jump_offset_7_labels": 0},
        {"num_labels_is_8": 1, "num_labels": 1,  "jump_offset_3_labels": 0, "jump_offset_4_labels": 0, "jump_offset_5_labels": 0,
            "jump_offset_6_labels": 0, "jump_offset_7_labels": 0},
        {"num_labels_is_8": 1, "num_labels": 2,  "jump_offset_3_labels": 0, "jump_offset_4_labels": 0, "jump_offset_5_labels": 0,
            "jump_offset_6_labels": 0, "jump_offset_7_labels": 0},
        {"num_labels_is_8": 1, "num_labels": 3,  "jump_offset_3_labels": 0, "jump_offset_4_labels": 0, "jump_offset_5_labels": 0,
            "jump_offset_6_labels": 0, "jump_offset_7_labels": 0},
        {"num_labels_is_8": 1, "num_labels": 4,  "jump_offset_3_labels": 0, "jump_offset_4_labels": 0, "jump_offset_5_labels": 0,
            "jump_offset_6_labels": 0, "jump_offset_7_labels": 0},
        {"num_labels_is_8": 1, "num_labels": 5,  "jump_offset_3_labels": 0, "jump_offset_4_labels": 0, "jump_offset_5_labels": 0,
            "jump_offset_6_labels": 0, "jump_offset_7_labels": 0},
        {"num_labels_is_8": 1, "num_labels": 6,  "jump_offset_3_labels": 0, "jump_offset_4_labels": 0, "jump_offset_5_labels": 0,
            "jump_offset_6_labels": 0, "jump_offset_7_labels": 0},
        {"num_labels_is_8": 1, "num_labels": 7,  "jump_offset_3_labels": 0, "jump_offset_4_labels": 0, "jump_offset_5_labels": 0,
            "jump_offset_6_labels": 0, "jump_offset_7_labels": 0},
        # 9-15 are initialized with all zeros, like for 8
    ]

    for line in table_data:
        key = map_more_labels_static_table_key_t(num_labels_is_8 = line["num_labels_is_8"], num_labels = line["num_labels"])
        value = map_more_labels_static_table_value_t(
            additional_mpls_labels_offset_t(line["jump_offset_3_labels"], line["jump_offset_4_labels"], line["jump_offset_5_labels"], line["jump_offset_6_labels"], line["jump_offset_7_labels"],))
        table.insert(NETWORK_CONTEXT, key, value)


# invalid_flags indicates whether exp_null and entropy are valid.
# if they are not valid, then by definition they have the value 0, because num_labels_is_3 would not be set otherwise
#   invalid_flags expl_null  vpn_enabled  fwd_hdr_type  entropy  >  add_v6_null  skip_first_macro  macro    labels  | comments
#0. 0             X          1            XXXX          0        >  0            0                 vpn      1       | L3VPN/6PE
#1. 0             X          1            XXXX          1        >  0            0                 vpn+EL   3       | L3VPN/6PE + ENTROPY
#2. 0             1          0            IPV6          0        >  1            0                 vpn      1       | Explicit NULL via LSP/LDP
#3. 0             1          0            IPV6          1        >  1            0                 vpn+EL   3       | Explicit NULL via LSP/LDP
#4. 0             0          0            XXXX          1        >  0            0                 EL       2       | ENTROPY only
#5. 1             X          1            XXXX          X        >  0            0                 vpn      1       | L3VPN/6PE
#6. Default                                                      >  0            1                 ene_nop  0       | default, no service labels.
#
# The lsp flags are: {push_entropy_label, add_ipv6_explicit_null, 4'num_labels, num_labels_is_3}
# num_labels_is_3 means the other flags are invalid so treat them as having the value 0
# num_labels is not used in this table and so those 4 bits are always masked out
# Gibraltar can only have 4 keys, so we combine two of the flags into one key
#
def lsp_flags(is_3_label=False, el=None, v6en=None):
    I3L  = 1 << 3
    V6EN = 1 << 8
    EL   = 1 << 9
    mask=0
    if is_3_label is not None:
        mask |= I3L
    if v6en is not None:
        mask |= V6EN
    if el is not None:
        mask |= EL
    key=0
    if is_3_label:
        key |= I3L
    if v6en:
        key |= V6EN
    if el:
        key |= EL
    return Key(key, mask=mask)


#   |ivf| expl_null |  vpn_enabled |  fwd_hdr_type | entropy |  >  | vpn_label_exists |  skip_first_macro |  macro  | labels | comments
# 0.| X |     X     |      1       |     ETHERNET  |     X   |  >  |     1            |        0          |  l2vpn  |   1    | L2 VPN PWE with optional FAT, CW
# 1.| 0 |     X     |      1       |      XXXX     |     0   |  >  |     1            |        0          |  vpn    |   1    | L3VPN/6PE
# 2.| 0 |     X     |      1       |      XXXX     |     1   |  >  |     1            |        0          |  vpn+EL |   3    | L3VPN/6PE + ENTROPY
# 3.| 0 |     1     |      0       |      IPV6     |     0   |  >  |     1            |        0          |  vpn    |   1    | Explicit NULL via LSP/LDP
# 4.| 0 |     1     |      0       |      IPV6     |     1   |  >  |     1            |        0          |  vpn+EL |   3    | Explicit NULL via LSP/LDP
# 5.| 0 |     0     |      0       |      XXXX     |     1   |  >  |     0            |        0          |   EL    |   2    | ENTROPY only
# 6.| 1 |     X     |      1       |      XXXX     |     X   |  >  |     1            |        0          |   vpn   |   1    | L3VPN/6PE
# 7.|-------------------------- Default ---------------------|  >  |     0            |        1          | ene_nop |   0    | default, no service labels
def config_mpls_resolve_service_labels_static_table():
    # short renames
    VPN_LOOKUP    = 1 << 3
    NO_ENE        = 1 << 4
    FIRST_ENE_NOP       = QOS_ENE_MACRO_NOP       | NO_ENE
    FIRST_ENE_V6NULL    = QOS_ENE_MACRO_L3_VPN
    FIRST_ENE_V6NULL_EL = QOS_ENE_MACRO_L3_VPN_EL
    FIRST_ENE_VPN       = QOS_ENE_MACRO_L3_VPN    | VPN_LOOKUP
    FIRST_ENE_VPN_EL    = QOS_ENE_MACRO_L3_VPN_EL | VPN_LOOKUP
    FIRST_ENE_EL        = QOS_ENE_MACRO_EL
    FIRST_ENE_PWE       = QOS_ENE_MACRO_L2_VPN    | VPN_LOOKUP
    V6_HEADER = Key(FWD_HEADER_TYPE_IPV6, mask=0b1110)
    ETH_HDR   = Key(FWD_HEADER_TYPE_ETHERNET, mask=0b1111)

    table_config = TcamTableConfig("mpls_resolve_service_labels_static_table")

    table_data = [
        {"key": ["lsp_flags"                    , "vpn_enabled", "fwd_hdr_type"], "value": ["vpn_label_exists", "sizeof_labels", "mpls_first_ene_macro_control"]},
        {"key": [_DONT_CARE                     ,       1      , ETH_HDR       ], "value": [       1                ,       12        ,  FIRST_ENE_PWE ]},
        {"key": [lsp_flags(is_3_label=True)     ,       1      , _DONT_CARE    ], "value": [       1                ,       4        ,   FIRST_ENE_VPN ]},
        {"key": [lsp_flags(el=False)            ,       1      , _DONT_CARE    ], "value": [       1                ,       4        ,   FIRST_ENE_VPN ]},
        {"key": [lsp_flags(el=True)             ,       1      , _DONT_CARE    ], "value": [       1                ,       12       ,   FIRST_ENE_VPN_EL ]},
        {"key": [lsp_flags(el=False, v6en=True) ,       0      , V6_HEADER     ], "value": [       1                ,       4        ,   FIRST_ENE_V6NULL ]},
        {"key": [lsp_flags(el=True, v6en=True)  ,       0      , V6_HEADER     ], "value": [       1                ,       12       ,   FIRST_ENE_V6NULL_EL ]},
        {"key": [lsp_flags(el=True, v6en=False) ,       0      , _DONT_CARE    ], "value": [       0                ,       8        ,   FIRST_ENE_EL ]},
        {"key": [_DONT_CARE                     ,  _DONT_CARE  , _DONT_CARE    ], "value": [       0                ,       0        ,   FIRST_ENE_NOP ]} ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


# +--------------+--------------+--------------+----------------------------------------+
# | same l3 intf | collapsed_mc | pl_inc       |    next_macro/action                   |
# +--------------+--------------+--------------+----------------------------------------+
# |       0      |      0       | PL_INC_NONE  |  network_tx_ip_to_nh_uc_and_acl_macro  |
# +--------------+--------------+--------------+----------------------------------------+
# |       0      |      1       | PL_INC_ONCE  |  network_tx_ip_to_nh_uc_and_acl_macro  |
# +--------------+--------------+--------------+----------------------------------------+
# |       1      |      0       | PL_INC_NONE  |  network_tx_ip_to_nh_uc_and_acl_macro  |
# +--------------+--------------+--------------+----------------------------------------+
# |       1      |      1       | PL_INC_NONE  |  network_tx_mac_ac_and_acl_macro       |
# +--------------+--------------+--------------+----------------------------------------+
def config_ip_mc_next_macro_static_table():
    table = ip_mc_next_macro_static_table
    table_data = [
        {"same_l3_int": 0,  "collapsed_mc": 0, "npe_macro_id": NETWORK_TX_IP_TO_NH_UC_AND_ACL_MACRO, "pl_inc": PL_INC_NONE},
        {"same_l3_int": 0,  "collapsed_mc": 1, "npe_macro_id": NETWORK_TX_IP_TO_NH_UC_AND_ACL_MACRO, "pl_inc": PL_INC_NONE},
        {"same_l3_int": 1,  "collapsed_mc": 0, "npe_macro_id": NETWORK_TX_IP_TO_NH_UC_AND_ACL_MACRO, "pl_inc": PL_INC_NONE},
        {"same_l3_int": 1,  "collapsed_mc": 1, "npe_macro_id": NETWORK_TX_MAC_AC_AND_ACL_MACRO, "pl_inc": PL_INC_NONE}
    ]
    for line in table_data:
        key   = ip_mc_next_macro_static_table_key_t  (same_l3_int = line["same_l3_int"], collapsed_mc = line["collapsed_mc"])
        value = ip_mc_next_macro_static_table_value_t(npe_macro_id = line["npe_macro_id"], pl_inc = line["pl_inc"])
        table.insert(NETWORK_CONTEXT, key, value)


def config_map_destination_prefix_to_rpf_check_type_static_table() :
    table = map_destination_prefix_to_rpf_check_type_static_table
    table_data = [
        {
            "key":  {"rpf_mode": RPF_MODE_STRICT, "dest_prefix": DESTINATION_L3_DLP_SUBNET_PREFIX << 1}, # L3_DLP_SUBNET is 4 bit while key is 5b
            "mask":  {"rpf_mode": ALL_1, "dest_prefix": 0xe},  # Pacific HW WA: ignore MSB as it is used to signal MSB. LSB is ignored as prefix len is 4
            "payload": { "enabled": 1, "simple": 1, "complex": 0, "error": 0}
        },
        {
            "key":  {"rpf_mode": RPF_MODE_STRICT, "dest_prefix": DESTINATION_LPTS_PREFIX},
            "mask":  {"rpf_mode": ALL_1, "dest_prefix": ALL_1},
            "payload": { "enabled": 1, "simple": 0, "complex": 0, "error": 1}
        },
        {
            "key":  {"rpf_mode": RPF_MODE_LOOSE, "dest_prefix": DESTINATION_LPTS_PREFIX},
            "mask":  {"rpf_mode": ALL_1, "dest_prefix": ALL_1},
            "payload": { "enabled": 1, "simple": 0, "complex": 0, "error": 1}
        },
        {
            "key":  {"rpf_mode": RPF_MODE_STRICT, "dest_prefix": 0},
            "mask":  {"rpf_mode": ALL_1, "dest_prefix": DONT_CARE},
            "payload": { "enabled": 1, "simple": 0, "complex": 1, "error": 0}
        },
        {
            "key":  {"rpf_mode": RPF_MODE_LOOSE, "dest_prefix": 0},
            "mask":  {"rpf_mode": ALL_1, "dest_prefix": DONT_CARE},
            "payload": { "enabled": 1, "simple": 0, "complex": 0, "error": 0}
        },
        {
            "key":  {"rpf_mode": RPF_MODE_NONE, "dest_prefix": 0},
            "mask":  {"rpf_mode": DONT_CARE, "dest_prefix": DONT_CARE},
            "payload": { "enabled": 0, "simple": 0, "complex": 0, "error": 0}
        },
    ]
    location = 0
    for line in table_data:
        key = map_destination_prefix_to_rpf_check_type_static_table_key_t(
            ip_rx_local_vars_uc_rpf_result_destination_19_15_=line["key"]["dest_prefix"],
            pd_layer_vars_uc_rpf_mode=line["key"]["rpf_mode"])
        mask = map_destination_prefix_to_rpf_check_type_static_table_key_t(
            ip_rx_local_vars_uc_rpf_result_destination_19_15_=line["mask"]["dest_prefix"],
            pd_layer_vars_uc_rpf_mode=line["mask"]["rpf_mode"])
        value = map_destination_prefix_to_rpf_check_type_static_table_value_t(ip_rx_local_vars_rpf_check_type=rpf_check_type_t(
            enabled=line["payload"]["enabled"], is_simple=line["payload"]["simple"], is_complex=line["payload"]["complex"], error=line["payload"]["error"]) )
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


def config_ecn_remark_static_table():
    table = ecn_remark_static_table
    HEADER_TYPE_IP_HEADERS_PREFIX_1 = 0b111
    table_data = [
        # This table is a TCAM so the order matters
        # IPv4
        {
            # An IPv4 that doesn't support ECN (ip.ecn == b'00) should ignore congestion
            "key":   {"cong_on": 0,         "fwd_header_type": HEADER_TYPE_IPV4_HEADERS_PREFIX << 1,    "ipv4_ecn": 0b00,      "ipv6_ecn": 0        },
            "mask":  {"cong_on": DONT_CARE, "fwd_header_type": HEADER_TYPE_IP_HEADERS_PREFIX_1 << 1,    "ipv4_ecn": ALL_1,     "ipv6_ecn": DONT_CARE},
            "payload": { "new_ecn": 0b00, "en_ecn_counting": 0b0}
        },
        {
            # An IPv4 that supports ECN (ip.ecn == b'01), without congestion should preserve its value
            "key":   {"cong_on": 0,         "fwd_header_type": HEADER_TYPE_IPV4_HEADERS_PREFIX << 1,    "ipv4_ecn": 0b01,      "ipv6_ecn": 0        },
            "mask":  {"cong_on": ALL_1,     "fwd_header_type": HEADER_TYPE_IP_HEADERS_PREFIX_1 << 1,    "ipv4_ecn": ALL_1,     "ipv6_ecn": DONT_CARE},
            "payload": { "new_ecn": 0b01, "en_ecn_counting": 0b0}
        },
        {
            # An IPv4 that supports ECN (ip.ecn == b'10), without congestion should preserve its value
            "key":   {"cong_on": 0,         "fwd_header_type": HEADER_TYPE_IPV4_HEADERS_PREFIX << 1,    "ipv4_ecn": 0b10,      "ipv6_ecn": 0        },
            "mask":  {"cong_on": ALL_1,     "fwd_header_type": HEADER_TYPE_IP_HEADERS_PREFIX_1 << 1,    "ipv4_ecn": ALL_1,     "ipv6_ecn": DONT_CARE},
            "payload": { "new_ecn": 0b10, "en_ecn_counting": 0b0}
        },
        {
            # - An IPv4 that supports ECN (ip.ecn == b'11), without congestion should preserve its value
            "key":   {"cong_on": 0,         "fwd_header_type": HEADER_TYPE_IPV4_HEADERS_PREFIX << 1,    "ipv4_ecn": 0,         "ipv6_ecn": 0        },
            "mask":  {"cong_on": ALL_1, "fwd_header_type": HEADER_TYPE_IP_HEADERS_PREFIX_1 << 1,    "ipv4_ecn": DONT_CARE, "ipv6_ecn": DONT_CARE},
            "payload": { "new_ecn": 0b11, "en_ecn_counting": 0b0}
        },
        {
            # - An IPv4 with congestion should indicate congestion (b'11), enable ecn packets counting in this case
            "key":   {"cong_on": 1,         "fwd_header_type": HEADER_TYPE_IPV4_HEADERS_PREFIX << 1,    "ipv4_ecn": 0,         "ipv6_ecn": 0        },
            "mask":  {"cong_on": ALL_1, "fwd_header_type": HEADER_TYPE_IP_HEADERS_PREFIX_1 << 1,    "ipv4_ecn": DONT_CARE, "ipv6_ecn": DONT_CARE},
            "payload": { "new_ecn": 0b11, "en_ecn_counting": 0b1}
        },
        # IPv6
        {
            # An IPv6 that doesn't support ECN (ip.ecn == b'00) should ignore congestion
            "key":   {"cong_on": 0,         "fwd_header_type": HEADER_TYPE_IPV6_HEADERS_PREFIX << 1,    "ipv4_ecn": 0,         "ipv6_ecn": 0b00     },
            "mask":  {"cong_on": DONT_CARE, "fwd_header_type": HEADER_TYPE_IP_HEADERS_PREFIX_1 << 1,    "ipv4_ecn": DONT_CARE, "ipv6_ecn": ALL_1    },
            "payload": { "new_ecn": 0b00, "en_ecn_counting": 0b0}
        },
        {
            # An IPv6 that supports ECN (ip.ecn == b'01), without congestion should preserve its value
            "key":   {"cong_on": 0,         "fwd_header_type": HEADER_TYPE_IPV6_HEADERS_PREFIX << 1,    "ipv4_ecn": 0,         "ipv6_ecn": 0b01     },
            "mask":  {"cong_on": ALL_1,     "fwd_header_type": HEADER_TYPE_IP_HEADERS_PREFIX_1 << 1,    "ipv4_ecn": DONT_CARE, "ipv6_ecn": ALL_1    },
            "payload": { "new_ecn": 0b01, "en_ecn_counting": 0b0}
        },
        {
            # An IPv6 that supports ECN (ip.ecn == b'10), without congestion should preserve its value
            "key":   {"cong_on": 0,         "fwd_header_type": HEADER_TYPE_IPV6_HEADERS_PREFIX << 1,    "ipv4_ecn": 0,         "ipv6_ecn": 0b10     },
            "mask":  {"cong_on": ALL_1,     "fwd_header_type": HEADER_TYPE_IP_HEADERS_PREFIX_1 << 1,    "ipv4_ecn": DONT_CARE, "ipv6_ecn": ALL_1    },
            "payload": { "new_ecn": 0b10, "en_ecn_counting": 0b0}
        },
        {
            # - An IPv6 that supports ECN (ip.ecn == b'11), without congestion should preserve its value
            "key":   {"cong_on": 0,         "fwd_header_type": HEADER_TYPE_IPV6_HEADERS_PREFIX << 1,    "ipv4_ecn": 0,         "ipv6_ecn": 0        },
            "mask":  {"cong_on": ALL_1, "fwd_header_type": HEADER_TYPE_IP_HEADERS_PREFIX_1 << 1,    "ipv4_ecn": DONT_CARE, "ipv6_ecn": DONT_CARE},
            "payload": { "new_ecn": 0b11, "en_ecn_counting": 0b0}
        },
        {
            # - An IPv6 with congestion should indicate congestion (b'11), enable ecn packets counting in this case
            "key":   {"cong_on": 1,         "fwd_header_type": HEADER_TYPE_IPV6_HEADERS_PREFIX << 1,    "ipv4_ecn": 0,         "ipv6_ecn": 0        },
            "mask":  {"cong_on": ALL_1, "fwd_header_type": HEADER_TYPE_IP_HEADERS_PREFIX_1 << 1,    "ipv4_ecn": DONT_CARE, "ipv6_ecn": DONT_CARE},
            "payload": { "new_ecn": 0b11, "en_ecn_counting": 0b1}
        }
    ]

    def ecn_to_tos(ecn):
        tos = ecn & 0b11
        return tos

    location = 0

    for line in table_data:
        key = ecn_remark_static_table_key_t(
            pd_cong_on = line["key"]["cong_on"],
            tx_npu_header_fwd_header_type = line["key"]["fwd_header_type"],
            packet_ipv4_header_tos_3_0_ = ecn_to_tos(line["key"]["ipv4_ecn"]),
            packet_ipv6_header_tos_3_0_ = ecn_to_tos(line["key"]["ipv6_ecn"]))
        mask = ecn_remark_static_table_key_t(
            pd_cong_on = line["mask"]["cong_on"],
            tx_npu_header_fwd_header_type = line["mask"]["fwd_header_type"],
            packet_ipv4_header_tos_3_0_ = ecn_to_tos(line["mask"]["ipv4_ecn"]),
            packet_ipv6_header_tos_3_0_ = ecn_to_tos(line["mask"]["ipv6_ecn"]))
        value = ecn_remark_static_table_value_t(line["payload"]["new_ecn"], line["payload"]["en_ecn_counting"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


def config_rx_fwd_p_counter_offset_static_table():
    table = rx_fwd_p_counter_offset_static_table
    table_data = [
        {
            "key":  {"ip_version": 1,     "ipv4_mc_prefix": IPV4_MULTICAST_PREFIX, "ipv6_mc_prefix": 0,         "demux": 1},
            "mask": {"ip_version": ALL_1, "ipv4_mc_prefix": ALL_1,                 "ipv6_mc_prefix": DONT_CARE, "demux": ALL_1},
            "payload": { "offset": P_COUNT_OFFSET_IPV4_MC}
        },
        {
            "key":  {"ip_version": 1,     "ipv4_mc_prefix": 0,         "ipv6_mc_prefix": 0,         "demux": 1},
            "mask": {"ip_version": ALL_1, "ipv4_mc_prefix": DONT_CARE, "ipv6_mc_prefix": DONT_CARE, "demux": ALL_1},
            "payload": { "offset": P_COUNT_OFFSET_IPV4_UC}
        },
        {
            "key":  {"ip_version": 0,     "ipv4_mc_prefix": 0,         "ipv6_mc_prefix": IPV6_MULTICAST_PREFIX, "demux": 1},
            "mask": {"ip_version": ALL_1, "ipv4_mc_prefix": DONT_CARE, "ipv6_mc_prefix": ALL_1,                 "demux": ALL_1},
            "payload": { "offset": P_COUNT_OFFSET_IPV6_MC}
        },
        {
            "key":  {"ip_version": 0,     "ipv4_mc_prefix": 0,         "ipv6_mc_prefix": 0,         "demux": 1},
            "mask": {"ip_version": ALL_1, "ipv4_mc_prefix": DONT_CARE, "ipv6_mc_prefix": DONT_CARE, "demux": ALL_1},
            "payload": { "offset": P_COUNT_OFFSET_IPV6_UC}
        }
    ]

    location = 0
    for line in table_data:
        key = rx_fwd_p_counter_offset_static_table_key_t(
            ip_version     = line["key"]["ip_version"],
            ipv4_mc_prefix = line["key"]["ipv4_mc_prefix"],
            ipv6_mc_prefix = line["key"]["ipv6_mc_prefix"],
            demux          = line["key"]["demux"])
        mask = rx_fwd_p_counter_offset_static_table_key_t(
            ip_version     = line["mask"]["ip_version"],
            ipv4_mc_prefix = line["mask"]["ipv4_mc_prefix"],
            ipv6_mc_prefix = line["mask"]["ipv6_mc_prefix"],
            demux          = line["mask"]["demux"])
        value = rx_fwd_p_counter_offset_static_table_value_t(line["payload"]["offset"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


def config_rx_redirect_next_macro_static_table():
    table=rx_redirect_next_macro_static_table
    table_data = [
        {
            "key":  {"cud_type": PUNT_CUD_TYPE_OBM, "redirect_code": 0,         "protocol_type": 0,          "next_protocol_type": 0},
            "mask": {"cud_type": ALL_1,             "redirect_code": DONT_CARE, "protocol_type": DONT_CARE,  "next_protocol_type": DONT_CARE},
            "payload": { "macro": FORWARDING_DONE,                          "pl_inc": PL_INC_NONE, "is_last_rx_macro": 1}
        },
        # MLDP decap PIMS all routers case. next protocol covering v4/v6
        {
            "key":  {"cud_type": 0,         "redirect_code": REDIRECT_CODE_LPTS_PREFIX << 1, "protocol_type": PROTOCOL_TYPE_MPLS, "next_protocol_type": PROTOCOL_TYPE_IPV4},
            "mask": {"cud_type": DONT_CARE, "redirect_code": 0xfe,                           "protocol_type": 0b11111,              "next_protocol_type": 0b11101},
            "payload": { "macro": RX_HANDLE_BFD_AND_LPTS_OG_MACRO, "pl_inc": PL_INC_ONCE, "is_last_rx_macro": 0}
        },
        # covering both IPv4 and IPV6 as next protocol for IP over IPV4.
        {
            "key":  {"cud_type": 0,         "redirect_code": REDIRECT_CODE_LPTS_PREFIX << 1, "protocol_type": PROTOCOL_TYPE_IPV4, "next_protocol_type": PROTOCOL_TYPE_IPV4},
            "mask": {"cud_type": DONT_CARE, "redirect_code": 0xfe,                           "protocol_type": 0b01111,              "next_protocol_type": 0b11101},
            "payload": { "macro": RX_HANDLE_BFD_AND_LPTS_OG_MACRO, "pl_inc": PL_INC_ONCE, "is_last_rx_macro": 0}
        },
        {
            "key":  {"cud_type": 0,         "redirect_code": REDIRECT_CODE_LPTS_PREFIX << 1, "protocol_type": PROTOCOL_TYPE_ETHERNET, "next_protocol_type": 0},
            "mask": {"cud_type": DONT_CARE, "redirect_code": 0xfe,                           "protocol_type": 0b01111,                  "next_protocol_type": DONT_CARE},
            "payload": { "macro": RX_HANDLE_BFD_AND_LPTS_OG_MACRO, "pl_inc": PL_INC_ONCE, "is_last_rx_macro": 0}
        },
        {
            "key":  {"cud_type": 0,         "redirect_code": REDIRECT_CODE_LPTS_PREFIX << 1, "protocol_type": 0,          "next_protocol_type": 0},
            "mask": {"cud_type": DONT_CARE, "redirect_code": 0xfe,                           "protocol_type": DONT_CARE,  "next_protocol_type": DONT_CARE},
            "payload": { "macro": RX_HANDLE_BFD_AND_LPTS_OG_MACRO, "pl_inc": PL_INC_NONE, "is_last_rx_macro": 0}
        },
        {
            "key":  {"cud_type": 0,         "redirect_code": 0,         "protocol_type": 0,          "next_protocol_type": 0},
            "mask": {"cud_type": DONT_CARE, "redirect_code": DONT_CARE, "protocol_type": DONT_CARE,  "next_protocol_type": DONT_CARE},
            "payload": { "macro": FORWARDING_DONE,                 "pl_inc": PL_INC_NONE, "is_last_rx_macro": 1}
        }
    ]

    location = 0
    for line in table_data:
        key = rx_redirect_next_macro_static_table_key_t(
            cud_type           = line["key"]["cud_type"],
            redirect_code      = line["key"]["redirect_code"],
            protocol_type      = line["key"]["protocol_type"],
            next_protocol_type = line["key"]["next_protocol_type"])
        mask = rx_redirect_next_macro_static_table_key_t(
            cud_type           = line["mask"]["cud_type"],
            redirect_code      = line["mask"]["redirect_code"],
            protocol_type      = line["mask"]["protocol_type"],
            next_protocol_type = line["mask"]["next_protocol_type"])
        value = rx_redirect_next_macro_static_table_value_t(macro_id = line["payload"]["macro"], pl_inc = line["payload"]["pl_inc"],
                                                            is_last_rx_macro =  line["payload"]["is_last_rx_macro"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


def config_mac_ethernet_rate_limit_type_static_table():
    table=mac_ethernet_rate_limit_type_static_table
    table_data = [
        {
            "key":  {"is_bc": 1,         "is_mc": 0,         "mac_forwarding_hit": 0        },
            "mask": {"is_bc": ALL_1,     "is_mc": DONT_CARE, "mac_forwarding_hit": DONT_CARE},
            "payload": { "ethernet_rate_limiter_type": ETH_RATE_LIMITER_BC}
        },
        {
            "key":  {"is_bc": 0,         "is_mc": 1,         "mac_forwarding_hit": 1        },
            "mask": {"is_bc": DONT_CARE, "is_mc": ALL_1,     "mac_forwarding_hit": ALL_1    },
            "payload": { "ethernet_rate_limiter_type": ETH_RATE_LIMITER_KNOWN_MC}
        },
        {
            "key":  {"is_bc": 0,         "is_mc": 0,         "mac_forwarding_hit": 1        },
            "mask": {"is_bc": DONT_CARE, "is_mc": DONT_CARE, "mac_forwarding_hit": ALL_1    },
            "payload": { "ethernet_rate_limiter_type": ETH_RATE_LIMITER_KNOWN_UC}
        },
        {
            "key":  {"is_bc": 0,         "is_mc": 1,         "mac_forwarding_hit": 0        },
            "mask": {"is_bc": DONT_CARE, "is_mc": ALL_1,     "mac_forwarding_hit": ALL_1    },
            "payload": { "ethernet_rate_limiter_type": ETH_RATE_LIMITER_UNKNOWN_MC}
        },
        {
            "key":  {"is_bc": 0,         "is_mc": 0,         "mac_forwarding_hit": 0        },
            "mask": {"is_bc": DONT_CARE, "is_mc": DONT_CARE, "mac_forwarding_hit": ALL_1    },
            "payload": { "ethernet_rate_limiter_type": ETH_RATE_LIMITER_UNKNOWN_UC}
        }
    ]

    location = 0
    for line in table_data:
        key = mac_ethernet_rate_limit_type_static_table_key_t(
            is_bc                = line["key"]["is_bc"],
            is_mc                = line["key"]["is_mc"],
            mac_forwarding_hit   = line["key"]["mac_forwarding_hit"])
        mask = mac_ethernet_rate_limit_type_static_table_key_t(
            is_bc                = line["mask"]["is_bc"],
            is_mc                = line["mask"]["is_mc"],
            mac_forwarding_hit   = line["mask"]["mac_forwarding_hit"])
        value = mac_ethernet_rate_limit_type_static_table_value_t(
            ethernet_rate_limiter_type = line["payload"]["ethernet_rate_limiter_type"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


def config_punt_ethertype_static_table():
    table = punt_ethertype_static_table
    table_data = [
        {
            "key":  {"punt_nw_encap_type": 0, "punt_format": PUNT_HEADER_FORMAT_TYPE_ERSPAN_II},
            "mask": {"punt_nw_encap_type": DONT_CARE, "punt_format": ALL_1},
            "payload": { "ethertype": ETHER_TYPE_ERSPAN_II}
        },
        {
            "key":  {"punt_nw_encap_type": CONST_PUNT_NW_IP_UDP_ENCAP_TYPE, "punt_format": PUNT_HEADER_FORMAT_TYPE_UDP},
            "mask": {"punt_nw_encap_type": ALL_1, "punt_format": ALL_1},
            "payload": { "ethertype": ETHER_TYPE_IPV4}
        },
        {
            "key":  {"punt_nw_encap_type": CONST_PUNT_NW_IPV6_UDP_ENCAP_TYPE, "punt_format": PUNT_HEADER_FORMAT_TYPE_UDP},
            "mask": {"punt_nw_encap_type": ALL_1, "punt_format": ALL_1},
            "payload": { "ethertype": ETHER_TYPE_IPV6}
        },
        #Default entry
        {
            "key":  {"punt_nw_encap_type": 0, "punt_format": 0},
            "mask": {"punt_nw_encap_type": DONT_CARE, "punt_format": DONT_CARE},
            "payload": { "ethertype": ETHER_TYPE_PUNT_MAC}
        }

    ]
    location = 0
    for line in table_data:
        key = punt_ethertype_static_table_key_t(
            punt_nw_encap_type   = line["key"]["punt_nw_encap_type"],
            punt_format          = line["key"]["punt_format"])
        mask = punt_ethertype_static_table_key_t(
            punt_nw_encap_type   = line["mask"]["punt_nw_encap_type"],
            punt_format          = line["mask"]["punt_format"])
        value = punt_ethertype_static_table_value_t(
            pd_ene_encap_data_punt_ethertype = line["payload"]["ethertype"])
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


def config_pfc_offset_from_vector_static_table():
    table = pfc_offset_from_vector_static_table
    table_data = [
        {
            "key": {"vector": 0x80},
            "mask":{"vector": 0x80},
            "payload": {"offset": 7, "trap": 0},
        },
        {
            "key": {"vector": 0x40},
            "mask":{"vector": 0x40},
            "payload": {"offset": 6, "trap": 0},
        },
        {
            "key": {"vector": 0x20},
            "mask":{"vector": 0x20},
            "payload": {"offset": 5, "trap": 0},
        },
        {
            "key": {"vector": 0x10},
            "mask":{"vector": 0x10},
            "payload": {"offset": 4, "trap": 0},
        },
        {
            "key": {"vector": 0x08},
            "mask":{"vector": 0x08},
            "payload": {"offset": 3, "trap": 0},
        },
        {
            "key": {"vector": 0x04},
            "mask":{"vector": 0x04},
            "payload": {"offset": 2, "trap": 0},
        },
        {
            "key": {"vector": 0x02},
            "mask":{"vector": 0x02},
            "payload": {"offset": 1, "trap": 0},
        },
        {
            "key": {"vector": 0x01},
            "mask":{"vector": 0x01},
            "payload": {"offset": 0, "trap": 0},
        },
        {
            "key": {"vector": 0x0},
            "mask":{"vector": 0x0},
            "payload": {"offset": 0, "trap": 1},
        }
    ]
    location = 0
    for line in table_data:
        key = pfc_offset_from_vector_static_table_key_t(vector  = line["key"]["vector"])
        mask = pfc_offset_from_vector_static_table_key_t(vector  = line["mask"]["vector"])
        value = pfc_offset_from_vector_static_table_value_t(offset = line["payload"]["offset"], trap = line["payload"]["trap"])
        table.insert(HOST_CONTEXT, location, key, mask, value)
        location += 1


def config_map_inject_ccm_macro_static_table():
    table = map_inject_ccm_macro_static_table
    table_data = [
        {
            "key": {"outer_tpid_ptr": 0xf, "inner_tpid_ptr": 0},
            "mask": {"outer_tpid_ptr": 0xf, "inner_tpid_ptr": DONT_CARE},
            "payload": {"next_macro": PUSH_INJECT_HEADER_ENE_MACRO, "second_ene_macro": ENE_END_MACRO}
        },
        {
            "key": {"outer_tpid_ptr": 0, "inner_tpid_ptr": 0xf},
            "mask": {"outer_tpid_ptr": DONT_CARE, "inner_tpid_ptr": 0xf},
            "payload": {"next_macro": ADD_ONE_VLAN_ENE_MACRO, "second_ene_macro": PUSH_INJECT_HEADER_ENE_MACRO}
        },
        {
            "key": {"outer_tpid_ptr": 0, "inner_tpid_ptr": 0},
            "mask": {"outer_tpid_ptr": DONT_CARE, "inner_tpid_ptr": DONT_CARE},
            "payload": {"next_macro": ADD_TWO_VLANS_ENE_MACRO, "second_ene_macro": PUSH_INJECT_HEADER_ENE_MACRO}
        }
    ]

    location = 0
    for line in table_data:
        key = map_inject_ccm_macro_static_table_key_t(
            outer_tpid_ptr=line["key"]["outer_tpid_ptr"],
            inner_tpid_ptr=line["key"]["inner_tpid_ptr"]
        )
        mask = map_inject_ccm_macro_static_table_key_t(
            outer_tpid_ptr=line["mask"]["outer_tpid_ptr"],
            inner_tpid_ptr=line["mask"]["inner_tpid_ptr"]
        )
        value = map_inject_ccm_macro_static_table_value_t(
            next_macro=line["payload"]["next_macro"],
            second_ene_macro=line["payload"]["second_ene_macro"]
        )
        table.insert(HOST_CONTEXT, location, key, mask, value)
        location += 1


# A static table which maps fi header type (5 bits) to protocol type of next layer
def config_acl_map_fi_header_type_to_protocol_number_table():
    table = acl_map_fi_header_type_to_protocol_number_table
    table_config = DirectTableConfig("acl_map_fi_header_type_to_protocol_number_table")
    table_data = [{"key": [ "fi_hdr_type" ]    , "value": [ "is_valid", "acl_l4_protocol",  "protocol_type"]},
                  {"key": [PROTOCOL_TYPE_UDP]  , "value": [1, ACL_UDP,   IPV6_NEXT_HEADER_UDP << 8 | IPV6_NEXT_HEADER_UDP]},
                  {"key": [PROTOCOL_TYPE_TCP]  , "value": [1, ACL_TCP,   IPV6_NEXT_HEADER_TCP << 8 | IPV6_NEXT_HEADER_TCP]},
                  {"key": [PROTOCOL_TYPE_GRE]  , "value": [1, ACL_OTHER, IPV6_NEXT_HEADER_GRE << 8 | IPV6_NEXT_HEADER_GRE]},
                  {"key": [PROTOCOL_TYPE_ICMP] , "value": [1, ACL_ICMP,  IPV6_NEXT_HEADER_ICMP << 8| IPV6_NEXT_HEADER_ICMP]},
                  ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


# A static table which maps ipv4 protocol type (8 bits) to protocol type and acl_l4_protocol
def config_ipv4_acl_map_protocol_type_to_protocol_number_table():
    table = ipv4_acl_map_protocol_type_to_protocol_number_table
    table_config = TcamTableConfig("ipv4_acl_map_protocol_type_to_protocol_number_table")
    table_data = [{"key": [ "protocol"          ], "value": ["dummy_bits", "is_valid" , "acl_l4_protocol",  "protocol_type"]},
                  {"key": [IPV4_PROTOCOL_UDP           ], "value": [     0   ,      1      , ACL_UDP          , IPV4_PROTOCOL_UDP           ]},
                  {"key": [IPV4_PROTOCOL_TCP           ], "value": [     0   ,      1      , ACL_TCP          , IPV4_PROTOCOL_TCP           ]},
                  {"key": [IPV4_PROTOCOL_ICMP          ], "value": [     0   ,      1      , ACL_ICMP         , IPV4_PROTOCOL_ICMP          ]},
                  {"key": [IPV4_PROTOCOL_IGMP          ], "value": [     0   ,      1      , ACL_OTHER        , IPV4_PROTOCOL_IGMP          ]},
                  {"key": [IPV4_PROTOCOL_GRE           ], "value": [     0   ,      1      , ACL_OTHER        , IPV4_PROTOCOL_GRE           ]},
                  {"key": [IPV4_MULTICAST_PREFIX       ], "value": [     0   ,      1      , ACL_OTHER        , IPV4_MULTICAST_PREFIX       ]},
                  {"key": [IPV4_MULTICAST_NON_ROUTABLE ], "value": [     0   ,      1      , ACL_OTHER        , IPV4_MULTICAST_NON_ROUTABLE ]},
                  {"key": [IPV4_PROTOCOL_NVGRE         ], "value": [     0   ,      1      , ACL_OTHER        , IPV4_PROTOCOL_NVGRE         ]},
                  {"key": [DONT_CARE                   ], "value": [     0   ,      0      , ACL_OTHER        , 0]},
                  ]

    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


# next_prto_type|	pd_ipv4_init_rtf_stage|	pd_ipv6_init_rtf_stage|	pd_eth_rtf_stage|	PL_inc|	macro_id
#---------------|-------------------------|-----------------------|-----------------|---------|---------------
# v4	        |    OG	                  |  dont_care	          |  dont_care	    |    once |	og_macro
# v4	        |    pre_fwd_l2	          |  dont_care	          |  dont_care	    |    once |	eth_rtf
# v4	        |    pre_fwd_l3	          |  dont_care	          |  dont_care	    |    once |	ipv4_rtf
# v4	        |    dont_care	          |  dont_care	          |  dont_care	    |    none |	mac_fwd
# v6	        |    dont_care	          |  OG	                  |  dont_care	    |    once |	og_macro
# v6	        |    dont_care	          |  pre_fwd_l2	          |  dont_care	    |    once |	eth_rtf
# v6	        |    dont_care	          |  pre_fwd_l3	          |  dont_care	    |    once |	ipv6_rtf
# v6	        |    dont_care	          |  dont_care	          |  dont_care	    |    none |	mac_fwd
# dont_care	|    dont_care	          |  dont_care	          |  pre_fwd	    |    none |	eth_rtf
# dont_care	|    dont_care	          |  dont_care	          |  dont_care	    |    none |	mac_fwd
def config_l2_termination_next_macro_static_table():
    table_config = TcamTableConfig("l2_termination_next_macro_static_table")
    table_data = [
        {"key": ["next_hdr_type"          , "ipv4_ipv6_eth_init_rtf_stage"                                         ], "value": ["pl_inc",    "macro_id"                       ]},
        #IPV4
        {"key": [PROTOCOL_TYPE_IPV4_SUFFIX, Key(INIT_RTF_OG         <<5 | DONT_CARE<<3 | DONT_CARE, mask=0b1100000)], "value": [PL_INC_ONCE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [PROTOCOL_TYPE_IPV4_SUFFIX, Key(INIT_RTF_PRE_FWD_L2 <<5 | DONT_CARE<<3 | DONT_CARE, mask=0b1100000)], "value": [PL_INC_ONCE, NETWORK_RX_ETH_RTF_MACRO         ]},
        {"key": [PROTOCOL_TYPE_IPV4_SUFFIX, Key(INIT_RTF_PRE_FWD_L3 <<5 | DONT_CARE<<3 | DONT_CARE, mask=0b1100000)], "value": [PL_INC_ONCE, NETWORK_RX_IPV4_RTF_MACRO        ]},
        {"key": [PROTOCOL_TYPE_IPV4_SUFFIX, Key(DONT_CARE           <<5 | DONT_CARE<<3 | DONT_CARE, mask=0b0000000)], "value": [PL_INC_NONE, NETWORK_RX_MAC_FORWARDING_MACRO  ]},
        #IPV6
        {"key": [PROTOCOL_TYPE_IPV6_SUFFIX, Key(DONT_CARE <<5 | INIT_RTF_OG<<3 | DONT_CARE, mask=0b0011000)        ], "value": [PL_INC_ONCE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [PROTOCOL_TYPE_IPV6_SUFFIX, Key(DONT_CARE <<5 | INIT_RTF_PRE_FWD_L2<<3 | DONT_CARE, mask=0b0011000)], "value": [PL_INC_ONCE, NETWORK_RX_ETH_RTF_MACRO         ]},
        {"key": [PROTOCOL_TYPE_IPV6_SUFFIX, Key(DONT_CARE <<5 | INIT_RTF_PRE_FWD_L3<<3 | DONT_CARE, mask=0b0011000)], "value": [PL_INC_ONCE, NETWORK_RX_IPV6_RTF_MACRO        ]},
        {"key": [PROTOCOL_TYPE_IPV6_SUFFIX, Key(DONT_CARE <<5 | DONT_CARE<<3           | DONT_CARE, mask=0b0011000)], "value": [PL_INC_NONE, NETWORK_RX_MAC_FORWARDING_MACRO        ]},
        # Default
        {"key": [_DONT_CARE               , Key(DONT_CARE <<5 | DONT_CARE<<3 | RTF_PRE_FWD_L2, mask=0b0000111)     ], "value": [PL_INC_NONE, NETWORK_RX_ETH_RTF_MACRO         ]},
        {"key": [_DONT_CARE               , _DONT_CARE                                                             ], "value": [PL_INC_NONE, NETWORK_RX_MAC_FORWARDING_MACRO  ]},
    ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


# +---------------------------------+----+----------+------------+
# | ipv4_ipv6_init_rtf_stage        |    |   pl_inc |   macro_id |
# |---------------------------------+----+----------+------------|
# | (RTF_OG, 'mask=0b1100')         | >  |        3 | NETWORK_RX_IP_OBJECT_GROUPS_MACRO|
# | (RTF_PRE_FWD_L2, 'mask=0b1100') | >  |        3 | NETWORK_RX_ETH_RTF_MACRO|
# | (RTF_PRE_FWD_L3, 'mask=0b1100') | >  |        3 | NETWORK_RX_IPV4_RTF_MACRO|
# +----------------------------+----+----------+------------+
def config_l2_tunnel_term_next_macro_static_table():
    table_config = DirectTableConfig("l2_tunnel_term_next_macro_static_table")
    table_size = table_config.get_table_size()

    table_data = [{"key": ["overlay_or_pwe_lp_type", "ipv4_ipv6_init_rtf_stage"] , "value": ["pl_inc", "macro_id"]}]
    for id in range(0, table_size):
        ipv4_ipv6_rtf_stages = id & 0b1111
        ipv4_rtf_stage = (id >>2) & 0b11
        is_pwe = (id >> 4) & 0b1
        if (is_pwe == 1):
            macro_id = NETWORK_RX_MAC_FORWARDING_MACRO
            pl_inc   = PL_INC_NONE
        elif ipv4_rtf_stage == INIT_RTF_OG:
            macro_id = NETWORK_RX_IP_OBJECT_GROUPS_MACRO
            pl_inc   = PL_DEC_ONCE
        elif ipv4_rtf_stage == INIT_RTF_PRE_FWD_L2:
            macro_id = NETWORK_RX_ETH_RTF_MACRO
            pl_inc   = PL_DEC_ONCE
        elif ipv4_rtf_stage == INIT_RTF_PRE_FWD_L3:
            macro_id = NETWORK_RX_IPV4_RTF_MACRO
            pl_inc   = PL_DEC_ONCE
        else:
            macro_id = NETWORK_RX_MAC_FORWARDING_MACRO
            pl_inc   = PL_INC_NONE
        table_data.append({"key": [is_pwe, ipv4_ipv6_rtf_stages], "value": [pl_inc, macro_id]})

    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)

#  this table is used to replace the following logic due to lack of FS at level 9
#  pd.npu_header.is_slp_dm  = mac_af_npp_attributes.enable_sr_dm_accounting;
#  pd.npu_header.ingress_ptp_info = mac_af_npp_attributes.enable_transparent_ptp ? 3'b001: 3'b000;


def config_get_ingress_ptp_info_and_is_slp_dm_static_table():
    table_config = DirectTableConfig("get_ingress_ptp_info_and_is_slp_dm_static_table")
    table_data = [{"key": [ "enable_sr_dm_accounting", "enable_transparent_ptp" ]   , "value": [  "ingress_ptp_info_and_is_slp_dm_cmpressed_fields"]},
                  {"key": [       1                  ,          1               ]   , "value": [       0b1001            ]},
                  {"key": [       1                  ,          0               ]   , "value": [       0b1000            ]},
                  {"key": [       0                  ,          0               ]   , "value": [       0b0000            ]},
                  {"key": [       0                  ,          1               ]   , "value": [       0b0001            ]},
                  ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


# hdr_type	|init_ipv4_stage|	init_ipv6_stage| dont_inc_pl| PL_inc|	macro_id
# ----------|---------------|------------------|-------|-------|-----------
# v4	    |     OG	    |     dont_care	   | 1	   |  none|	OG_macro
# v4	    |     OG	    |     dont_care	   | 0	   |  once|	OG_macro
# v4	    |     pre_fwd_l2|	  dont_care	   | 1	   |  none|	ETH_RTF
# v4	    |     pre_fwd_l2|	  dont_care	   | 0	   |  once|	ETH_RTF
# v4	    |     pre_fwd_l3|	  dont_care	   | 1	   |  none|	IPV4_RTF
# v4	    |     pre_fwd_l3|	  dont_care	   | 0	   |  once|	IPV4_RTF
# v6	    |     dont_care	|   OG       	   | 1	   |  none|	OG_macro
# v6	    |     dont_care	|   OG       	   | 0	   |  once|	OG_macro
# v6	    |     dont_care	|   pre_fwd_l2	   | 1	   |  none|	ETH_RTF
# v6	    |     dont_care	|   pre_fwd_l2	   | 0	   |  once|	ETH_RTF
# v6	    |     dont_care	|   pre_fwd_l3	   | 1	   |  none|	IPV6_RTF
# v6	    |     dont_care	|   pre_fwd_l3	   | 0	   |  once|	IPV6_RTF
# dont_care|	dont_care	|   dont_care	   | 1	   |  none|	ip_FWd
# dont_care|	dont_care	|   dont_care	   | 0	   |  once|	ip_FWd
def config_l3_termination_next_macro_static_table():
    table_config = TcamTableConfig("l3_termination_next_macro_static_table")
    table_data = [
        {"key": ["hdr_type"        , "ipv4_ipv6_init_rtf_stage"                                   , "dont_inc_pl"], "value": ["pl_inc",    "macro_id"                                  ]},
        # IPV4
        {"key": [PROTOCOL_TYPE_IPV4_SUFFIX, Key(INIT_RTF_OG         <<2 | DONT_CARE, mask=0b1100) ,    1    ], "value": [PL_INC_NONE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [PROTOCOL_TYPE_IPV4_SUFFIX, Key(INIT_RTF_OG         <<2 | DONT_CARE, mask=0b1100) ,    0    ], "value": [PL_INC_ONCE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [PROTOCOL_TYPE_IPV4_SUFFIX, Key(INIT_RTF_PRE_FWD_L2 <<2 | DONT_CARE, mask=0b1100) ,    1    ], "value": [PL_INC_NONE, NETWORK_RX_ETH_RTF_MACRO         ]},
        {"key": [PROTOCOL_TYPE_IPV4_SUFFIX, Key(INIT_RTF_PRE_FWD_L2 <<2 | DONT_CARE, mask=0b1100) ,    0    ], "value": [PL_INC_ONCE, NETWORK_RX_ETH_RTF_MACRO         ]},
        {"key": [PROTOCOL_TYPE_IPV4_SUFFIX, Key(INIT_RTF_PRE_FWD_L3 <<2 | DONT_CARE, mask=0b1100) ,    1    ], "value": [PL_INC_NONE, NETWORK_RX_IPV4_RTF_MACRO        ]},
        {"key": [PROTOCOL_TYPE_IPV4_SUFFIX, Key(INIT_RTF_PRE_FWD_L3 <<2 | DONT_CARE, mask=0b1100) ,    0    ], "value": [PL_INC_ONCE, NETWORK_RX_IPV4_RTF_MACRO        ]},
        # IPV6
        {"key": [PROTOCOL_TYPE_IPV6_SUFFIX, Key(DONT_CARE <<2 | INIT_RTF_OG        , mask=0b0011) ,    1    ], "value": [PL_INC_NONE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [PROTOCOL_TYPE_IPV6_SUFFIX, Key(DONT_CARE <<2 | INIT_RTF_OG        , mask=0b0011) ,    0    ], "value": [PL_INC_ONCE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [PROTOCOL_TYPE_IPV6_SUFFIX, Key(DONT_CARE <<2 | INIT_RTF_PRE_FWD_L2, mask=0b0011) ,    1    ], "value": [PL_INC_NONE, NETWORK_RX_ETH_RTF_MACRO         ]},
        {"key": [PROTOCOL_TYPE_IPV6_SUFFIX, Key(DONT_CARE <<2 | INIT_RTF_PRE_FWD_L2, mask=0b0011) ,    0    ], "value": [PL_INC_ONCE, NETWORK_RX_ETH_RTF_MACRO         ]},
        {"key": [PROTOCOL_TYPE_IPV6_SUFFIX, Key(DONT_CARE <<2 | INIT_RTF_PRE_FWD_L3, mask=0b0011) ,    1    ], "value": [PL_INC_NONE, NETWORK_RX_IPV6_RTF_MACRO        ]},
        {"key": [PROTOCOL_TYPE_IPV6_SUFFIX, Key(DONT_CARE <<2 | INIT_RTF_PRE_FWD_L3, mask=0b0011) ,    0    ], "value": [PL_INC_ONCE, NETWORK_RX_IPV6_RTF_MACRO        ]},
        # Default
        {"key": [_DONT_CARE               , _DONT_CARE                                            ,    1    ], "value": [PL_INC_NONE, NETWORK_RX_IP_AF_AND_FORWARDING_MACRO]},
        {"key": [_DONT_CARE               , _DONT_CARE                                            ,    0    ], "value": [PL_INC_ONCE, NETWORK_RX_IP_AF_AND_FORWARDING_MACRO]},
    ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


#  next_hdr_type|term_ipv4_stage |	term_ipv6_stage|  pd_ipv4_stage|	lp_set |  PL_inc|	macro_id
#  -------------|----------------|-----------------|---------------|-----------|--------|-------
#  mpls	        |    dont_care	 |    dont_care   | dont_care	   | dont_care|  once	|   mpls
#  dont_care	|    dont_care	 |    dont_care   |   OG	       | 0	       |  none	|   OG_macro
#  dont_care	|    dont_care	 |    dont_care   |   pre_fwd_l2  | 0	       |  none	|   ETH_RTF
#  dont_care	|    dont_care	 |    dont_care   |   pre_fwd_l3  | 0	       |  none	|   ipv4_rtf
#  v4	        |    OG	         |    dont_care   |   dont_care  | dont_care|  once	|   OG_macro
#  v4	        |    pre_fwd_l2	 |    dont_care   |   dont_care  | dont_care|  once	|   ETH_RTF
#  v4	        |    pre_fwd_l3	 |    dont_care   |   dont_care  | dont_care|  once	|   IPV4_RTF
#  v6	        |    dont_care	 |    OG	       |   dont_care  | dont_care|  once	|   OG_macro
#  v6	        |    dont_care	 |    pre_fwd_l2   |   dont_care  | dont_care|  once	|   ETH_RTF
#  v6	        |    dont_care	 |    pre_fwd_l3   |   dont_care  | dont_care|  once	|   IPV6_RTF
#  dont_care	|    dont_care	 |    dont_care   |	dont_care | dont_care|  once	|   ip_FWd
def config_l3_tunnel_termination_next_macro_static_table():
    table_config = TcamTableConfig("l3_tunnel_termination_next_macro_static_table")
    table_data = [{"key": ["next_hdr_type"          ,  "term_attr_ipv4_ipv6_init_rtf_stage"               , "pd_ipv4_init_rtf_stage", "lp_set"  ], "value": ["pl_inc"   ,    "macro_id"                        ]},
                  # MPLS
                  #   If inner is MPLS, execute MPLS Termination macro
                  {"key": [PROTOCOL_TYPE_MPLS       , _DONT_CARE                                          ,
                           _DONT_CARE              , _DONT_CARE], "value": [PL_INC_ONCE, NETWORK_RX_MPLS_AF_AND_TERMINATION_MACRO]},
                  # ACL_outer cases
                  {"key": [_DONT_CARE               , _DONT_CARE                                          ,
                           INIT_RTF_OG             , 0         ], "value": [PL_INC_NONE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO       ]},
                  {"key": [_DONT_CARE               , _DONT_CARE                                          ,
                           INIT_RTF_PRE_FWD_L2     , 0         ], "value": [PL_INC_NONE, NETWORK_RX_ETH_RTF_MACRO                ]},
                  {"key": [_DONT_CARE               , _DONT_CARE                                          ,
                           INIT_RTF_PRE_FWD_L3     , 0         ], "value": [PL_INC_NONE, NETWORK_RX_IPV4_RTF_MACRO               ]},
                  # if ACL outer, always jump to RTF_ipv4, that will enforce term2FWD to be based on outer, as a result load balancing will be based on the outer header as well
                  {"key": [_DONT_CARE               , _DONT_CARE                                          ,
                           _DONT_CARE              , 0         ], "value": [PL_INC_NONE, NETWORK_RX_NULL_RTF_MACRO               ]},
                  # IPV4
                  {"key": [PROTOCOL_TYPE_IPV4_SUFFIX, Key(INIT_RTF_OG<<2         | DONT_CARE, mask=0b1100), _DONT_CARE              , _DONT_CARE],
                   "value": [PL_INC_ONCE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO       ]},
                  {"key": [PROTOCOL_TYPE_IPV4_SUFFIX, Key(INIT_RTF_PRE_FWD_L2<<2 | DONT_CARE, mask=0b1100), _DONT_CARE              , _DONT_CARE],
                   "value": [PL_INC_ONCE, NETWORK_RX_ETH_RTF_MACRO                ]},
                  {"key": [PROTOCOL_TYPE_IPV4_SUFFIX, Key(INIT_RTF_PRE_FWD_L3<<2 | DONT_CARE, mask=0b1100), _DONT_CARE              , _DONT_CARE],
                   "value": [PL_INC_ONCE, NETWORK_RX_IPV4_RTF_MACRO               ]},
                  #IPV6
                  {"key": [PROTOCOL_TYPE_IPV6_SUFFIX, Key(DONT_CARE<<2 | INIT_RTF_OG, mask=0b0011)        , _DONT_CARE              , _DONT_CARE],
                   "value": [PL_INC_ONCE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO       ]},
                  {"key": [PROTOCOL_TYPE_IPV6_SUFFIX, Key(DONT_CARE<<2 | INIT_RTF_PRE_FWD_L2, mask=0b0011), _DONT_CARE              , _DONT_CARE],
                   "value": [PL_INC_ONCE, NETWORK_RX_ETH_RTF_MACRO                ]},
                  {"key": [PROTOCOL_TYPE_IPV6_SUFFIX, Key(DONT_CARE<<2 | INIT_RTF_PRE_FWD_L3, mask=0b0011), _DONT_CARE              , _DONT_CARE],
                   "value": [PL_INC_ONCE, NETWORK_RX_IPV6_RTF_MACRO               ]},
                  # Default
                  {"key": [_DONT_CARE               , _DONT_CARE                                          ,
                           _DONT_CARE              , _DONT_CARE], "value": [PL_INC_ONCE, NETWORK_RX_IP_AF_AND_FORWARDING_MACRO   ]},
                  ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


def config_null_rtf_next_macro_static_table():
    table_config = TcamTableConfig("null_rtf_next_macro_static_table")
    # pd_tunnel_ipv4_ipv6_init_rtf_stage: ipv4_next_init_stage, ipv6_next_init_stage
    og__dont_care         = Key(INIT_RTF_OG<<2         | DONT_CARE, mask=0b1100)
    pre_fwd_l2__dont_care = Key(INIT_RTF_PRE_FWD_L2<<2 | DONT_CARE, mask=0b1100)
    pre_fwd_l3__dont_care = Key(INIT_RTF_PRE_FWD_L3<<2 | DONT_CARE, mask=0b1100)
    dont_care__og         = Key(DONT_CARE<<2           | INIT_RTF_OG, mask=0b0011)
    dont_care__pre_fwd_l2 = Key(DONT_CARE<<2           | INIT_RTF_PRE_FWD_L2, mask=0b0011)
    dont_care__pre_fwd_l3 = Key(DONT_CARE<<2           | INIT_RTF_PRE_FWD_L3, mask=0b0011)
    dont_care__dont_care  = Key(DONT_CARE<<2           | DONT_CARE, mask=0b0000)

    table_data = [
        {"key": ["next_prot_type"                      , "pd_tunnel_ipv4_ipv6_init_rtf_stage", "acl_outer"] , "value": ["pl_inc"   ,    "macro_id"                        ]},
        {"key": [Key(PROTOCOL_TYPE_IPV4, mask=0b01111) ,           og__dont_care             , _DONT_CARE ] , "value": [PL_INC_ONCE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [Key(PROTOCOL_TYPE_IPV4, mask=0b01111) ,           pre_fwd_l2__dont_care     , _DONT_CARE ] , "value": [PL_INC_ONCE, NETWORK_RX_ETH_RTF_MACRO]},
        {"key": [Key(PROTOCOL_TYPE_IPV4, mask=0b01111) ,           pre_fwd_l3__dont_care     , _DONT_CARE ] , "value": [PL_INC_ONCE, NETWORK_RX_IPV4_RTF_MACRO]},
        {"key": [Key(PROTOCOL_TYPE_IPV6, mask=0b01111) ,           dont_care__og             , _DONT_CARE ] , "value": [PL_INC_ONCE, NETWORK_RX_IP_OBJECT_GROUPS_MACRO]},
        {"key": [Key(PROTOCOL_TYPE_IPV6, mask=0b01111) ,           dont_care__pre_fwd_l2     , _DONT_CARE ] , "value": [PL_INC_ONCE, NETWORK_RX_ETH_RTF_MACRO]},
        {"key": [Key(PROTOCOL_TYPE_IPV6, mask=0b01111) ,           dont_care__pre_fwd_l3     , _DONT_CARE ] , "value": [PL_INC_ONCE, NETWORK_RX_IPV6_RTF_MACRO]},
        {"key": [PROTOCOL_TYPE_MPLS                    ,           dont_care__dont_care      ,    1       ] , "value": [PL_INC_ONCE, NETWORK_RX_MPLS_FORWARDING_MACRO]},
        {"key": [PROTOCOL_TYPE_MPLS                    ,           dont_care__dont_care      ,    0       ] , "value": [PL_INC_TWICE, NETWORK_RX_IP_AF_AND_FORWARDING_MACRO]},
        {"key": [       _DONT_CARE                     ,           dont_care__dont_care      , _DONT_CARE ] , "value": [PL_INC_ONCE, NETWORK_RX_IP_AF_AND_FORWARDING_MACRO]},
    ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


# config_og_next_macro_static_table
# +------------+--------+---------------------------------------+-------------+
# | ip_version | repeat | macro_id                              | pl_inc      |
# +------------+--------+---------------------------------------+-------------+
# | 4          | 0      | NETWORK_RX_IPV4_RTF_MACRO         | PL_INC_NONE |
# | 6          | 0      | NETWORK_RX_IPV6_RTF_MACRO         | PL_INC_NONE |
# +------------+--------+---------------------------------------+-------------+
def config_og_next_macro_static_table():
    table_config = TcamTableConfig("og_next_macro_static_table")
    table_data = [{"key": ["ip_version" ], "value": ["pl_inc",    "macro_id"                 ]},
                  # IPV4
                  {"key": [IP_VERSION_IPV4], "value": [PL_INC_NONE, NETWORK_RX_IPV4_RTF_MACRO]},
                  {"key": [IP_VERSION_IPV6], "value": [PL_INC_NONE, NETWORK_RX_IPV6_RTF_MACRO]},
                  ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


def config_ip_ver_mc_static_table():
    table = ip_ver_mc_static_table
    table_data = [
        {
            "key" : {"is_v6": 1, "v6_sip_127_120": IPV6_MULTICAST_PREFIX, "v4_sip_31_28": 0,                     "v4_frag_offset": 0         },
            "mask": {"is_v6": 1, "v6_sip_127_120": ALL_1,                 "v4_sip_31_28": DONT_CARE,             "v4_frag_offset": DONT_CARE },
            "payload": {"ip_ver_mc": 0b11, "v4_offset_zero": 0}
        },
        {
            "key" : {"is_v6": 1, "v6_sip_127_120": 0,                     "v4_sip_31_28": 0,                     "v4_frag_offset": 0         },
            "mask": {"is_v6": 1, "v6_sip_127_120": DONT_CARE,             "v4_sip_31_28": DONT_CARE,             "v4_frag_offset": DONT_CARE },
            "payload": {"ip_ver_mc": 0b10, "v4_offset_zero": 0}
        },
        {
            "key" : {"is_v6": 0, "v6_sip_127_120": 0,                     "v4_sip_31_28": IPV4_MULTICAST_PREFIX, "v4_frag_offset": 0         },
            "mask": {"is_v6": 1, "v6_sip_127_120": DONT_CARE,             "v4_sip_31_28": ALL_1,                 "v4_frag_offset": ALL_1     },
            "payload": {"ip_ver_mc": 0b01, "v4_offset_zero": 1}
        },
        {
            "key" : {"is_v6": 0, "v6_sip_127_120": 0,                     "v4_sip_31_28": IPV4_MULTICAST_PREFIX, "v4_frag_offset": 0         },
            "mask": {"is_v6": 1, "v6_sip_127_120": DONT_CARE,             "v4_sip_31_28": ALL_1,                 "v4_frag_offset": DONT_CARE },
            "payload": {"ip_ver_mc": 0b01, "v4_offset_zero": 0}
        },

        {
            "key" : {"is_v6": 0, "v6_sip_127_120": 0,                     "v4_sip_31_28": 0,                     "v4_frag_offset": 0        },
            "mask": {"is_v6": 1, "v6_sip_127_120": DONT_CARE,             "v4_sip_31_28": DONT_CARE,             "v4_frag_offset": ALL_1    },
            "payload": {"ip_ver_mc": 0b00, "v4_offset_zero": 1}
        },
        {
            "key" : {"is_v6": 0, "v6_sip_127_120": 0,                     "v4_sip_31_28": 0,                     "v4_frag_offset": 0},
            "mask": {"is_v6": 1, "v6_sip_127_120": DONT_CARE,             "v4_sip_31_28": DONT_CARE,             "v4_frag_offset": DONT_CARE },
            "payload": {"ip_ver_mc": 0b00, "v4_offset_zero": 0}
        }
    ]

    location = 0
    for line in table_data:
        key = ip_ver_mc_static_table_key_t(
            is_v6=line["key"]["is_v6"],
            v6_sip_127_120=line["key"]["v6_sip_127_120"],
            v4_sip_31_28=line["key"]["v4_sip_31_28"],
            v4_frag_offset=line["key"]["v4_frag_offset"] )
        mask = ip_ver_mc_static_table_key_t(
            is_v6=line["mask"]["is_v6"],
            v6_sip_127_120=line["mask"]["v6_sip_127_120"],
            v4_sip_31_28=line["mask"]["v4_sip_31_28"],
            v4_frag_offset=line["mask"]["v4_frag_offset"] )
        value = ip_ver_mc_static_table_value_t(
            ip_ver_mc=line["payload"]["ip_ver_mc"],
            v4_offset_zero=line["payload"]["v4_offset_zero"] )
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


def config_rx_ip_p_counter_offset_static_table():
    table = rx_ip_p_counter_offset_static_table
    table_data = [
        {"ip_ver_mc": 0b00, "per_protocol_count": 1,  "counter_offset": P_COUNT_OFFSET_IPV4_UC},
        {"ip_ver_mc": 0b01, "per_protocol_count": 1,  "counter_offset": P_COUNT_OFFSET_IPV4_MC},
        {"ip_ver_mc": 0b10, "per_protocol_count": 1,  "counter_offset": P_COUNT_OFFSET_IPV6_UC},
        {"ip_ver_mc": 0b11, "per_protocol_count": 1,  "counter_offset": P_COUNT_OFFSET_IPV6_MC},
    ]
    #init all indices
    for key in range (0,8):
        value = rx_ip_p_counter_offset_static_table_value_t(0)
        table.insert(NETWORK_CONTEXT, key, value)

    #program per above
    for line in table_data:
        key     = rx_ip_p_counter_offset_static_table_key_t(ip_ver_mc=line["ip_ver_mc"], per_protocol_count=line["per_protocol_count"])
        value   = rx_ip_p_counter_offset_static_table_value_t(line["counter_offset"])
        table.insert(NETWORK_CONTEXT, key, value)


def config_ip_ingress_cmp_mcid_static_table():
    table_config = TcamTableConfig("ip_ingress_cmp_mcid_static_table")
    table_data = [
        {"key": ["global_mcid_17_downto_16"], "value": ["global_mcid_17_downto_16_is_zero"]},
        {"key": [    0       ], "value": [1]},
        {"key": [ _DONT_CARE ], "value": [0]}]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)

# +--------------------+-----------------------+----+--------------------+
# |   packet_type_bit0 |   not_comp_single_src |    |   non_comp_mc_trap |
# |--------------------+-----------------------+----+--------------------|
# |                  1 |                     1 | >  |                  1 |
# |                  1 |                     0 | >  |                  0 |
# |                  0 |                     0 | >  |                  0 |
# |                  0 |                     1 | >  |                  0 |
# +--------------------+-----------------------+----+--------------------+


def config_get_non_comp_mc_value_static_table():
    table_config = DirectTableConfig("get_non_comp_mc_value_static_table")
    table_data = [{"key": [ "packet_type_bit0", "not_comp_single_src" ]   , "value": [  "non_comp_mc_trap"]},
                  {"key": [       1           ,          1            ]   , "value": [     1              ]},
                  {"key": [       1           ,          0            ]   , "value": [     0              ]},
                  {"key": [       0           ,          0            ]   , "value": [     0              ]},
                  {"key": [       0           ,          1            ]   , "value": [     0              ]},
                  ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


def config_fabric_scaled_mc_map_to_netork_slice_static_table():
    table_config = DirectTableConfig("fabric_scaled_mc_map_to_netork_slice_static_table")
    table_data = [{"key": [ "smcid_lsb" ]   , "value": [  "network_slice_mcid"]}]
    mcid_to_nw_slice = [TM_DESTINATION_MASK_MCID + MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_0_IFG_0,
                        TM_DESTINATION_MASK_MCID + MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_0_IFG_1,
                        TM_DESTINATION_MASK_MCID + MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_1_IFG_0,
                        TM_DESTINATION_MASK_MCID + MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_1_IFG_1,
                        TM_DESTINATION_MASK_MCID + MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_2_IFG_0,
                        TM_DESTINATION_MASK_MCID + MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_2_IFG_1]
    num_mcids = len(mcid_to_nw_slice)
    for i in range(16):
        table_data.append({"key": [i] , "value": [ mcid_to_nw_slice[ i % num_mcids ] ] })
    table_config.create_table(table_data, FABRIC_CONTEXT, init_table=True)

# Not a static table but temporarily configure default value for backword competability


def config_nw_smcid_threshold_table():
    table_config = DirectTableConfig("nw_smcid_threshold_table")
    table_data = [{"key": [ "dummy" ]   , "value": [  "smcid_threshold"]},
                  {"key": [ 0 ]   , "value": [  (1<<16) -1 ]},
                  {"key": [ 1 ]   , "value": [  (1<<16) -1 ]}]

    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


def config_ene_macro_code_tpid_profile_static_table():
    table = ene_macro_code_tpid_profile_static_table
    table_data = [
        {"macro_code": NH_ENE_MACRO_ETH,           "ene_encap_macro_id": NH_ETHERNET_NO_VLAN_ENE_MACRO},
        {"macro_code": NH_ENE_MACRO_ETH_VLAN,      "ene_encap_macro_id": NH_ETHERNET_WITH_ONE_VLAN_ENE_MACRO},
        {"macro_code": NH_ENE_MACRO_ETH_VLAN_VLAN, "ene_encap_macro_id": NH_ETHERNET_WITH_TWO_VLAN_ENE_MACRO},
        {"macro_code": NH_ENE_MACRO_ETH,           "ene_encap_macro_id": NH_ETHERNET_NO_VLAN_ENE_MACRO},
    ]

    #program per above
    for line in table_data:
        key     = ene_macro_code_tpid_profile_static_table_key_t(tpid_profile=0b00, macro_code=line["macro_code"])
        value   = ene_macro_code_tpid_profile_static_table_value_t(ene_encap_tpid=0x8100, ene_encap_macro_id=line["ene_encap_macro_id"])
        table.insert(NETWORK_CONTEXT, key, value)
    for line in table_data:
        key     = ene_macro_code_tpid_profile_static_table_key_t(tpid_profile=0b01, macro_code=line["macro_code"])
        value   = ene_macro_code_tpid_profile_static_table_value_t(ene_encap_tpid=0x88a8, ene_encap_macro_id=line["ene_encap_macro_id"])
        table.insert(NETWORK_CONTEXT, key, value)
    for line in table_data:
        key     = ene_macro_code_tpid_profile_static_table_key_t(tpid_profile=0b10, macro_code=line["macro_code"])
        value   = ene_macro_code_tpid_profile_static_table_value_t(ene_encap_tpid=0x9100, ene_encap_macro_id=line["ene_encap_macro_id"])
        table.insert(NETWORK_CONTEXT, key, value)
    for line in table_data:
        key     = ene_macro_code_tpid_profile_static_table_key_t(tpid_profile=0b11, macro_code=line["macro_code"])
        value   = ene_macro_code_tpid_profile_static_table_value_t(ene_encap_tpid=0x8100, ene_encap_macro_id=line["ene_encap_macro_id"])
        table.insert(NETWORK_CONTEXT, key, value)


def config_eve_to_ethernet_ene_static_table():
    TPID_PRF0 = 0b00
    TPID_PRF1 = 0b01
    TPID_PRF2 = 0b10
    TPID_PRF3 = 0b11
    VLAN_EDIT_COMMAND_SUB_PUSH_1_PRF0  = (VLAN_EDIT_COMMAND_SECONDARY_PUSH_1 << 2) | TPID_PRF0
    VLAN_EDIT_COMMAND_SUB_NOP_PRF0     = (VLAN_EDIT_COMMAND_SECONDARY_NOP << 2) | TPID_PRF0
    VLAN_EDIT_COMMAND_SUB_PUSH_1_PRF1  = (VLAN_EDIT_COMMAND_SECONDARY_PUSH_1 << 2) | TPID_PRF1
    VLAN_EDIT_COMMAND_SUB_NOP_PRF1     = (VLAN_EDIT_COMMAND_SECONDARY_NOP << 2) | TPID_PRF1
    VLAN_EDIT_COMMAND_SUB_PUSH_1_PRF2  = (VLAN_EDIT_COMMAND_SECONDARY_PUSH_1 << 2) | TPID_PRF2
    VLAN_EDIT_COMMAND_SUB_NOP_PRF2     = (VLAN_EDIT_COMMAND_SECONDARY_NOP << 2) | TPID_PRF2
    VLAN_EDIT_COMMAND_SUB_PUSH_1_PRF3  = (VLAN_EDIT_COMMAND_SECONDARY_PUSH_1 << 2) | TPID_PRF3
    VLAN_EDIT_COMMAND_SUB_NOP_PRF3     = (VLAN_EDIT_COMMAND_SECONDARY_NOP << 2) | TPID_PRF3

    table = eve_to_ethernet_ene_static_table
    table_data_push1 = [
        {"main_type": VLAN_EDIT_COMMAND_MAIN_OTHER, "secondary_type": VLAN_EDIT_COMMAND_SUB_PUSH_1_PRF0, "ene_tpid" : 0x8100, "ene_macro": NH_ETHERNET_WITH_ONE_VLAN_ENE_MACRO},
        {"main_type": VLAN_EDIT_COMMAND_MAIN_OTHER, "secondary_type": VLAN_EDIT_COMMAND_SUB_PUSH_1_PRF1, "ene_tpid" : 0x88a8, "ene_macro": NH_ETHERNET_WITH_ONE_VLAN_ENE_MACRO},
        {"main_type": VLAN_EDIT_COMMAND_MAIN_OTHER, "secondary_type": VLAN_EDIT_COMMAND_SUB_PUSH_1_PRF2, "ene_tpid" : 0x9100, "ene_macro": NH_ETHERNET_WITH_ONE_VLAN_ENE_MACRO},
        {"main_type": VLAN_EDIT_COMMAND_MAIN_OTHER, "secondary_type": VLAN_EDIT_COMMAND_SUB_PUSH_1_PRF3, "ene_tpid" : 0x8100, "ene_macro": NH_ETHERNET_WITH_ONE_VLAN_ENE_MACRO},
    ]
    #init all indices
    for key in range (0,128):
        value = eve_to_ethernet_ene_static_table_value_t(ene_encap_tpid=0x8100, ene_encap_macro_id=NH_ETHERNET_NO_VLAN_ENE_MACRO)
        table.insert(NETWORK_CONTEXT, key, value)

    #program per above data - push 1
    for line in table_data_push1:
        key     = eve_to_ethernet_ene_static_table_key_t(main_type=line["main_type"], sub_type=line["secondary_type"])
        value   = eve_to_ethernet_ene_static_table_value_t(ene_encap_tpid=line["ene_tpid"], ene_encap_macro_id=line["ene_macro"])
        table.insert(NETWORK_CONTEXT, key, value)

    #program data - push 2
    for sub_index in range (0,8):
        key     = eve_to_ethernet_ene_static_table_key_t(main_type=VLAN_EDIT_COMMAND_MAIN_PUSH_2,
                                                         sub_type=((sub_index << 2) | TPID_PRF0))
        value   = eve_to_ethernet_ene_static_table_value_t(ene_encap_tpid=0x8100,
                                                           ene_encap_macro_id=NH_ETHERNET_WITH_TWO_VLAN_ENE_MACRO)
        table.insert(NETWORK_CONTEXT, key, value)
        key     = eve_to_ethernet_ene_static_table_key_t(main_type=VLAN_EDIT_COMMAND_MAIN_PUSH_2,
                                                         sub_type=((sub_index << 2) | TPID_PRF1))
        value   = eve_to_ethernet_ene_static_table_value_t(ene_encap_tpid=0x88a8,
                                                           ene_encap_macro_id=NH_ETHERNET_WITH_TWO_VLAN_ENE_MACRO)
        table.insert(NETWORK_CONTEXT, key, value)
        key     = eve_to_ethernet_ene_static_table_key_t(main_type=VLAN_EDIT_COMMAND_MAIN_PUSH_2,
                                                         sub_type=((sub_index << 2) | TPID_PRF2))
        value   = eve_to_ethernet_ene_static_table_value_t(ene_encap_tpid=0x9100,
                                                           ene_encap_macro_id=NH_ETHERNET_WITH_TWO_VLAN_ENE_MACRO)
        table.insert(NETWORK_CONTEXT, key, value)
        key     = eve_to_ethernet_ene_static_table_key_t(main_type=VLAN_EDIT_COMMAND_MAIN_PUSH_2,
                                                         sub_type=((sub_index << 2) | TPID_PRF3))
        value   = eve_to_ethernet_ene_static_table_value_t(ene_encap_tpid=0x8100,
                                                           ene_encap_macro_id=NH_ETHERNET_WITH_TWO_VLAN_ENE_MACRO)
        table.insert(NETWORK_CONTEXT, key, value)


#  |  lp_set  |  l3_dlp_is_group_qos |                  ACTION                    |
#  |    0     |          0           |  UPDATE_DSCP_FROM_L3_DLP_WITH_FWD_QOS_TAG  |
#  |    0     |          1           |  UPDATE_DSCP_FROM_L3_DLP_WITH_QOS_GROUP    |
#  |    1     |          0           |  UPDATE_DSCP_FROM_TUNNEL                   |
#  |    1     |          1           |  UPDATE_DSCP_FROM_TUNNEL                   |


def config_tunnel_qos_static_table():
    table = tunnel_qos_static_table
    table_data = [
        {"lp_set": 0, "l3_dlp_is_group_qos": 0, "action": TUNNEL_QOS_STATIC_TABLE_ACTION_UPDATE_DSCP_FROM_L3_DLP_WITH_FWD_QOS_TAG},
        {"lp_set": 0, "l3_dlp_is_group_qos": 1, "action": TUNNEL_QOS_STATIC_TABLE_ACTION_UPDATE_DSCP_FROM_L3_DLP_WITH_QOS_GROUP},
        {"lp_set": 1, "l3_dlp_is_group_qos": 0, "action": TUNNEL_QOS_STATIC_TABLE_ACTION_UPDATE_DSCP_FROM_TUNNEL},
        {"lp_set": 1, "l3_dlp_is_group_qos": 1, "action": TUNNEL_QOS_STATIC_TABLE_ACTION_UPDATE_DSCP_FROM_TUNNEL}
    ]

    for line in table_data:
        key = tunnel_qos_static_table_key_t(lp_set=line["lp_set"],
                                            l3_dlp_is_group_qos=line["l3_dlp_is_group_qos"])
        value = tunnel_qos_static_table_value_t(action=line["action"])
        table.insert(NETWORK_CONTEXT, key, value)


#  |  acl_is_valid | acl_l4_protocol |        ACTION                       |
#  |    1          |   ACL_OTHER     | UPDATE_SPORT_FROM_MAPPED_PROTO_TYPE |
#  |    1          |   ACL_TCP       | UPDATE_SPORT_FROM_PACKET            |
#  |    1          |   ACL_UDP       | UPDATE_SPORT_FROM_PACKET            |
#  |    1          |   ACL_ICMP      | UPDATE_SPORT_FROM_PACKET            |
#  |    0          |   ACL_OTHER     | UPDATE_SPORT_FROM_PACKET_PROTO_TYPE |
#  |    0          |   ACL_TCP       | UPDATE_SPORT_FROM_PACKET_PROTO_TYPE |
#  |    0          |   ACL_UDP       | UPDATE_SPORT_FROM_PACKET_PROTO_TYPE |
#  |    0          |   ACL_ICMP      | UPDATE_SPORT_FROM_PACKET_PROTO_TYPE |
def config_acl_sport_static_tables():
    ipv4_table = ipv4_acl_sport_static_table
    table_data = [
        {"acl_is_valid": 1, "acl_l4_protocol": ACL_OTHER, "action": IPV4_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_MAPPED_PROTO_TYPE},
        {"acl_is_valid": 1, "acl_l4_protocol": ACL_TCP  , "action": IPV4_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET},
        {"acl_is_valid": 1, "acl_l4_protocol": ACL_UDP  , "action": IPV4_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET},
        {"acl_is_valid": 1, "acl_l4_protocol": ACL_ICMP , "action": IPV4_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET},
        {"acl_is_valid": 0, "acl_l4_protocol": ACL_OTHER, "action": IPV4_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET_PROTO_TYPE},
        {"acl_is_valid": 0, "acl_l4_protocol": ACL_TCP  , "action": IPV4_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET_PROTO_TYPE},
        {"acl_is_valid": 0, "acl_l4_protocol": ACL_UDP  , "action": IPV4_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET_PROTO_TYPE},
        {"acl_is_valid": 0, "acl_l4_protocol": ACL_ICMP , "action": IPV4_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET_PROTO_TYPE},
    ]

    for line in table_data:
        ipv4_key = ipv4_acl_sport_static_table_key_t(acl_is_valid=line["acl_is_valid"], acl_l4_protocol=line["acl_l4_protocol"])
        ipv4_value = ipv4_acl_sport_static_table_value_t(action=line["action"])
        ipv4_table.insert(NETWORK_CONTEXT, ipv4_key, ipv4_value)

    ipv6_table = ipv6_acl_sport_static_table
    table_data = [
        {"acl_is_valid": 1, "acl_l4_protocol": ACL_OTHER, "action": IPV6_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_MAPPED_PROTO_TYPE},
        {"acl_is_valid": 1, "acl_l4_protocol": ACL_TCP  , "action": IPV6_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET},
        {"acl_is_valid": 1, "acl_l4_protocol": ACL_UDP  , "action": IPV6_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET},
        {"acl_is_valid": 1, "acl_l4_protocol": ACL_ICMP , "action": IPV6_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET},
        {"acl_is_valid": 0, "acl_l4_protocol": ACL_OTHER, "action": IPV6_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET_PROTO_TYPE},
        {"acl_is_valid": 0, "acl_l4_protocol": ACL_TCP  , "action": IPV6_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET_PROTO_TYPE},
        {"acl_is_valid": 0, "acl_l4_protocol": ACL_UDP  , "action": IPV6_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET_PROTO_TYPE},
        {"acl_is_valid": 0, "acl_l4_protocol": ACL_ICMP , "action": IPV6_ACL_SPORT_STATIC_TABLE_ACTION_UPDATE_SPORT_FROM_PACKET_PROTO_TYPE},
    ]

    for line in table_data:
        ipv6_key = ipv6_acl_sport_static_table_key_t(acl_is_valid=line["acl_is_valid"], acl_l4_protocol=line["acl_l4_protocol"])
        ipv6_value = ipv6_acl_sport_static_table_value_t(action=line["action"])
        ipv6_table.insert(NETWORK_CONTEXT, ipv6_key, ipv6_value)


# //   |is_midpoint     | mpls_labels_lookup |  is_asbr_or_ldpote |      ACTION                    |
# //   |       0        |        0           |                    | UPDATE_LSP_ZERO_PAYLOAD        |
# //   |       1        |        0           |                    | UPDATE_MIDPOINT_PAYLOAD        |
# //   |       0        |        1           |    0               | UPDATE_LSP_PAYLOAD             |
# //   |       1        |        1           |                    | UPDATE_BACKUP_PAYLOAD          |
# //   |       0        |        1           |    1               | UPDATE_LSP_ASBR_PAYLOAD        |
def config_mpls_l3_lsp_static_table():
    table = mpls_l3_lsp_static_table
    table_data = [
        {"is_midpoint": 0,"mpls_labels_lookup": 0, "is_asbr_or_ldpote": 0, "action": MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_LSP_ZERO_PAYLOAD},
        {"is_midpoint": 0,"mpls_labels_lookup": 0, "is_asbr_or_ldpote": 1, "action": MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_LSP_ZERO_PAYLOAD},
        #
        {"is_midpoint": 1,"mpls_labels_lookup": 0, "is_asbr_or_ldpote": 0, "action": MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_MIDPOINT_PAYLOAD},
        {"is_midpoint": 1,"mpls_labels_lookup": 0, "is_asbr_or_ldpote": 1, "action": MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_MIDPOINT_PAYLOAD},
        #
        {"is_midpoint": 0,"mpls_labels_lookup": 1, "is_asbr_or_ldpote": 0, "action": MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_LSP_PAYLOAD},
        #
        {"is_midpoint": 1,"mpls_labels_lookup": 1, "is_asbr_or_ldpote": 0, "action": MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_BACKUP_PAYLOAD},
        {"is_midpoint": 1,"mpls_labels_lookup": 1, "is_asbr_or_ldpote": 1, "action": MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_BACKUP_PAYLOAD},
        #
        {"is_midpoint": 0,"mpls_labels_lookup": 1, "is_asbr_or_ldpote": 1, "action": MPLS_L3_LSP_STATIC_TABLE_ACTION_UPDATE_LSP_ASBR_PAYLOAD},
    ]

    for line in table_data:
        mpls_encap_control_bits = line["is_midpoint"] <<2 | line["mpls_labels_lookup"] <<1 | line["is_asbr_or_ldpote"]
        key = mpls_l3_lsp_static_table_key_t(mpls_encap_control_bits=mpls_encap_control_bits)
        value = mpls_l3_lsp_static_table_value_t(action=line["action"])
        table.insert(NETWORK_CONTEXT, key, value)


#  |  mpls_is_null_labels |        ACTION               |
#  |    0     		  |  is_null_label_false        |
#  |    1     		  |  is_null_label_true         |
def config_mpls_header_offset_in_bytes_static_table():
    table_config = DirectTableConfig("mpls_header_offset_in_bytes_static_table")
    table_data = [{"key": ["mpls_is_null_labels"] , "value": [ "action"]},
                  {"key": [         0           ] , "value": [MPLS_HEADER_OFFSET_IN_BYTES_STATIC_TABLE_ACTION_IS_NULL_LABEL_FALSE]},
                  {"key": [         1           ] , "value": [MPLS_HEADER_OFFSET_IN_BYTES_STATIC_TABLE_ACTION_IS_NULL_LABEL_TRUE ]}
                  ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


# # | slp_based_forwarding | mc_s_g_miss |              macro                 |   pl_inc    |
# # |        1             |      1      | network_rx_ip_prefix_slp_fwd_macro | PL_INC_NONE |
# # |        1             |      0      | network_rx_ip_prefix_slp_fwd_macro | PL_INC_NONE |
# # |        0             |      1      | network_rx_ip_second_macro         | PL_INC_NONE |
# # |        0             |      0      | resolution_macro                   | PL_INC_NONE |


def config_ipv6_first_fragment_static_table():
    table_config = TcamTableConfig("ipv6_first_fragment_static_table")

    table_data = [
        {"key": ["acl_on_outer" , "acl_changed_destination", "saved_not_first_fragment", "packet_not_first_fragment"], "value": ["ip_first_fragment"]},
        {"key": [    1          ,       _DONT_CARE         ,    _DONT_CARE             ,      0      ]         ,        "value": [1 ]},
        {"key": [    1          ,       _DONT_CARE         ,    _DONT_CARE             ,      1      ]         ,        "value": [0 ]},
        {"key": [   _DONT_CARE  , Key(1<<2 | 0, mask=0b100),    _DONT_CARE             ,      0      ]         ,        "value": [1 ]},
        {"key": [   _DONT_CARE  , Key(1<<2 | 0, mask=0b100),    _DONT_CARE             ,      1      ]         ,        "value": [0 ]},
        {"key": [   _DONT_CARE  ,       _DONT_CARE         ,          0                , _DONT_CARE  ]         ,        "value": [1 ]},
        {"key": [   _DONT_CARE  ,       _DONT_CARE         ,          1                , _DONT_CARE  ]         ,        "value": [0 ]}]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


# controls next macro after outbound_mirror_rx_macro
# MC_LPTS case and svi flood have special TX2RX_RCY_DATA_OBM_TO_INJECT_UP_SUFFIX rcy_data suffix
# only MC_LPTS will have punt header
# catch all is the regular obm flow.
def config_obm_next_macro_static_table():
    table_config = TcamTableConfig("obm_next_macro_static_table")

    table_data = [
        {"key": ["rcy_data_suffix"                       , "has_punt_header"  ],   "value": ["pl_inc"    , "macro_id"]},
        {"key": [ TX2RX_RCY_DATA_OBM_TO_INJECT_UP_SUFFIX ,  PROTOCOL_TYPE_PUNT],   "value": [PL_INC_TWICE, RX_HANDLE_BFD_AND_LPTS_OG_MACRO]},           #MC LPTS
        {"key": [ TX2RX_RCY_DATA_OBM_TO_INJECT_UP_SUFFIX , _DONT_CARE         ],   "value": [PL_INC_NONE , NETWORK_RX_MAC_AF_AND_TERMINATION_MACRO]},   #SVI recirc/flood
        {"key": [ _DONT_CARE                             , _DONT_CARE         ],   "value": [PL_INC_NONE , RX_REDIRECT_MACRO ]}]                        #regular OBM/tx redirect flow.
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


# The mldp_protection field in the npu_l3_encap is only initialized in the CUD. The RX code
# does not initialize it for unicast mpls packets. This table indicates if the field is
# valid or not.


def config_mldp_protection_enabled_static_table():
    table_config = TcamTableConfig("mldp_protection_enabled_static_table")

    table_data = [
        {"key": ["is_mc"        , "l3_encap"]                            , "value": ["enabled"]},
        {"key": [ 1             , NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE]   ,    "value": [1 ]},
        {"key": [ _DONT_CARE    , _DONT_CARE]                            , "value": [0 ]}]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


def config_map_tx_punt_rcy_next_macro_static_table():

    table_config = TcamTableConfig("map_tx_punt_rcy_next_macro_static_table")
    table_data = [
        {"key": ["inject_only"  , "eth_stage" , "redirect_code"],               "value": ["pl_inc"   ,         "macro_id"           ]},
        {"key": [1              , _DONT_CARE  , _DONT_CARE],                    "value": [PL_INC_NONE, TX_INJECT_HEADER_WITH_NPUH_ENE_MACRO]},
        {"key": [0              , 0           , REDIRECT_CODE_DROP_NO_RECYCLE], "value": [PL_INC_NONE, NETWORK_TRANSMIT_ERROR_MACRO]},
        {"key": [0              , 0           , _DONT_CARE],                    "value": [PL_INC_NONE, TX_PUNT_RCY_MACRO]}]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


def config_ip_rx_global_counter_table():
    table = ip_rx_global_counter_table
    key   = 0
    value = ip_rx_global_counter_table_value_t(global_counter=NULL_COUNTER_PTR)
    table.insert(NETWORK_CONTEXT, key, value)

# +---------------------+---------------------+----------------------------------------+--------------+
# |       proto         |     l2_lp type      |                 macro                  |   plc_inc    |
# | PROTOCOL_TYPE_IPV4  |   L2_LP_TYPE_NPP    | network_rx_ip_af_and_termination_macro | PL_INC_ONCE  |
# | PROTOCOL_TYPE_IPV4  |        *            | network_rx_ip_af_and_forwarding_macro  | PL_INC_ONCE  |
# |         *           |        *            | network_rx_ip_af_and_forwarding_macro  | PL_INC_ONCE  |
# +---------------------+---------------------+----------------------------------------+--------------+


def config_mac_termination_security_next_macro_static_table():
    table = mac_termination_security_next_macro_static_table
    table_data = [
        {
            "key":  {"type": PROTOCOL_TYPE_IPV4, "l2_lp_type": L2_LP_TYPE_NPP},
            "mask": {"type": 0b01111,            "l2_lp_type": ALL_1},
            "payload": {"pl_inc": PL_INC_ONCE, "macro_id": NETWORK_RX_IP_AF_AND_TERMINATION_MACRO},
        },
        {
            "key":  {"type": PROTOCOL_TYPE_IPV4, "l2_lp_type": DONT_CARE},
            "mask": {"type": 0b01111,            "l2_lp_type": 0},
            "payload": {"pl_inc": PL_INC_ONCE, "macro_id": NETWORK_RX_IP_AF_AND_FORWARDING_MACRO},
        },
        {
            "key": {"type": DONT_CARE, "l2_lp_type": DONT_CARE},
            "mask":{"type": DONT_CARE, "l2_lp_type": DONT_CARE},
            "payload": {"pl_inc": PL_INC_ONCE, "macro_id": NETWORK_RX_IP_AF_AND_FORWARDING_MACRO},
        },
    ]
    location = 0
    for line in table_data:
        key = mac_termination_security_next_macro_static_table_key_t(type=line["key"]["type"],
                                                                     l2_lp_type=line["key"]["l2_lp_type"])
        mask = mac_termination_security_next_macro_static_table_key_t(type=line["mask"]["type"],
                                                                      l2_lp_type=line["mask"]["l2_lp_type"])
        value = mac_termination_security_next_macro_static_table_value_t(pl_inc=line["payload"]["pl_inc"],
                                                                         macro_id=line["payload"]["macro_id"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


def config_next_header_1_is_l4_over_ipv4_static_table():
    table_config = DirectTableConfig("next_header_1_is_l4_over_ipv4_static_table")
    table_data = [{"key": [ "is_l4" , "fragmented"  ] , "value": [ "next_header_1_is_l4_over_ipv4"]},
                  {"key": [ 1       , 0             ] , "value": [ 1                              ]},
                  ]
    table_config.create_table(table_data, NETWORK_CONTEXT, init_table=True)


# +---------------------+----------+--------------+-------+-------+------------------------------------------------+--------------+
# |       proto         | mac_term | l2_en_l3_qos | v4_mc | v6_mc |        macro                                   |   plc_inc    |
# | PROTOCOL_TYPE_IPV4  |    1     |      *       |   *   |   *   | network_rx_ip_af_and_termination_macro         | PL_INC_ONCE  |
# | PROTOCOL_TYPE_IPV6  |    1     |      *       |   *   |   *   | network_rx_ip_af_and_termination_macro         | PL_INC_ONCE  |
# | PROTOCOL_TYPE_MPLS  |    1     |      *       |   *   |   *   | network_rx_mpls_af_and_termination_macro       | PL_INC_ONCE  |
# |         *           |    *     |      *       |   1   |   *   | network_rx_mac_relay_ipv4_mc_termination_macro | PL_INC_NONE  |
# |         *           |    *     |      *       |   *   |   1   | network_rx_mac_relay_ipv6_mc_termination_macro | PL_INC_NONE  |
# | PROTOCOL_TYPE_IPV4  |    *     |      1       |   *   |   *   | network_rx_mac_qos_macro                       | PL_INC_NONE  |
# | PROTOCOL_TYPE_IPV6  |    *     |      1       |   *   |   *   | network_rx_mac_qos_macro                       | PL_INC_NONE  |
# | PROTOCOL_TYPE_MPLS  |    *     |      1       |   *   |   *   | network_rx_mac_qos_macro                       | PL_INC_NONE  |
# |         *           |    *     |      *       |   *   |   *   | network_rx_mac_forwarding_macro                | PL_INC_NONE  |
# +---------------------+----------+--------------+-------+-------+------------------------------------------------+--------------+
# l2_lpts structure contains below fields  -
#  mac_term        = ctrl_fields[1]
#  l2_en_l3_qos    = ctrl_fields[0]
def config_l2_lpts_next_macro_static_table():
    table = l2_lpts_next_macro_static_table
    table_data = [
        {
            "key"     : {"type"   : PROTOCOL_TYPE_IPV4,  "ctrl_fields": 0b10,  "v4_mc": 0b0,  "v6_mc": 0b0},
            "mask"    : {"type"   : 0b01111,             "ctrl_fields": 0b10,  "v4_mc": 0b0,  "v6_mc": 0b0},
            "payload" : {"pl_inc" : PL_INC_ONCE, "macro_id": NETWORK_RX_IP_AF_AND_TERMINATION_MACRO},
        },
        {
            "key"     : {"type"   : PROTOCOL_TYPE_IPV6,  "ctrl_fields": 0b10,  "v4_mc": 0b0,  "v6_mc": 0b0},
            "mask"    : {"type"   : 0b01111,             "ctrl_fields": 0b10,  "v4_mc": 0b0,  "v6_mc": 0b0},
            "payload" : {"pl_inc" : PL_INC_ONCE, "macro_id": NETWORK_RX_IP_AF_AND_TERMINATION_MACRO},
        },
        {
            "key"     : {"type"   : PROTOCOL_TYPE_MPLS,  "ctrl_fields": 0b10,  "v4_mc": 0b0,  "v6_mc": 0b0},
            "mask"    : {"type"   : 0b11111,             "ctrl_fields": 0b10,  "v4_mc": 0b0,  "v6_mc": 0b0},
            "payload" : {"pl_inc" : PL_INC_ONCE, "macro_id": NETWORK_RX_MPLS_AF_AND_TERMINATION_MACRO},
        },
        {
            "key"     : {"type"   : DONT_CARE,           "ctrl_fields": 0b00,  "v4_mc": 0b1,  "v6_mc": 0b0},
            "mask"    : {"type"   : DONT_CARE,           "ctrl_fields": 0b00,  "v4_mc": 0b1,  "v6_mc": 0b0},
            "payload" : {"pl_inc" : PL_INC_NONE, "macro_id": NETWORK_RX_MAC_RELAY_IPV4_MC_TERMINATION_MACRO},
        },
        {
            "key"     : {"type"   : DONT_CARE,           "ctrl_fields": 0b00,  "v4_mc": 0b0,  "v6_mc": 0b1},
            "mask"    : {"type"   : DONT_CARE,           "ctrl_fields": 0b00,  "v4_mc": 0b0,  "v6_mc": 0b1},
            "payload" : {"pl_inc" : PL_INC_NONE, "macro_id": NETWORK_RX_MAC_RELAY_IPV6_MC_TERMINATION_MACRO},
        },
        {
            "key"     : {"type"   : PROTOCOL_TYPE_IPV4,  "ctrl_fields": 0b01,  "v4_mc": 0b0,  "v6_mc": 0b0},
            "mask"    : {"type"   : 0b01111,             "ctrl_fields": 0b01,  "v4_mc": 0b0,  "v6_mc": 0b0},
            "payload" : {"pl_inc" : PL_INC_NONE, "macro_id": NETWORK_RX_MAC_QOS_MACRO},
        },
        {
            "key"     : {"type"   : PROTOCOL_TYPE_IPV6,  "ctrl_fields": 0b01,  "v4_mc": 0b0,  "v6_mc": 0b0},
            "mask"    : {"type"   : 0b01111,             "ctrl_fields": 0b01,  "v4_mc": 0b0,  "v6_mc": 0b0},
            "payload" : {"pl_inc" : PL_INC_NONE, "macro_id": NETWORK_RX_MAC_QOS_MACRO},
        },
        {
            "key"     : {"type"   : PROTOCOL_TYPE_MPLS,  "ctrl_fields": 0b01,  "v4_mc": 0b0,  "v6_mc": 0b0},
            "mask"    : {"type"   : 0b11111,             "ctrl_fields": 0b01,  "v4_mc": 0b0,  "v6_mc": 0b0},
            "payload" : {"pl_inc" : PL_INC_NONE, "macro_id": NETWORK_RX_MAC_QOS_MACRO},
        },
        {
            "key"     : {"type"   : DONT_CARE,           "ctrl_fields": 0b00,  "v4_mc": 0b0,  "v6_mc": 0b0},
            "mask"    : {"type"   : DONT_CARE,           "ctrl_fields": 0b00,  "v4_mc": 0b0,  "v6_mc": 0b0},
            "payload" : {"pl_inc" : PL_INC_NONE, "macro_id": NETWORK_RX_MAC_FORWARDING_MACRO},
        },
    ]
    location = 0
    for line in table_data:
        key = l2_lpts_next_macro_static_table_key_t(type=line["key"]["type"],
                                                    ctrl_fields=line["key"]["ctrl_fields"],
                                                    v4_mc=line["key"]["v4_mc"],
                                                    v6_mc=line["key"]["v6_mc"])
        mask = l2_lpts_next_macro_static_table_key_t(type=line["mask"]["type"],
                                                     ctrl_fields=line["mask"]["ctrl_fields"],
                                                     v4_mc=line["mask"]["v4_mc"],
                                                     v6_mc=line["mask"]["v6_mc"])
        value = l2_lpts_next_macro_static_table_value_t(pl_inc=line["payload"]["pl_inc"],
                                                        macro_id=line["payload"]["macro_id"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


# +---------+----------------+--------+--------+-----------+
# | lp_type | mac_terminated | is_p2p | traps.app.skip_p2p |
# |    0    |       0        |    0   |         1          |
# |    0    |       0        |    1   |         0          |  // P2P flow
# |    0    |       1        |    0   |         1          |
# |    0    |       1        |    1   |         1          |
# |    1    |       0        |    0   |         1          |
# |    1    |       0        |    1   |         1          |
# |    1    |       1        |    0   |         1          |
# |    1    |       1        |    1   |         1          |
# +---------+----------------+--------+--------+-----------+


def config_l2_lpts_skip_p2p_static_table():
    table = l2_lpts_skip_p2p_static_table
    table_data = [
        {"mac_lp_type_and_term": 0b00, "is_p2p": 0, "skip_p2p_trap" : 1},
        {"mac_lp_type_and_term": 0b00, "is_p2p": 1, "skip_p2p_trap" : 0},
        {"mac_lp_type_and_term": 0b01, "is_p2p": 0, "skip_p2p_trap" : 1},
        {"mac_lp_type_and_term": 0b01, "is_p2p": 1, "skip_p2p_trap" : 1},
        {"mac_lp_type_and_term": 0b10, "is_p2p": 0, "skip_p2p_trap" : 1},
        {"mac_lp_type_and_term": 0b10, "is_p2p": 1, "skip_p2p_trap" : 1},
        {"mac_lp_type_and_term": 0b11, "is_p2p": 0, "skip_p2p_trap" : 1},
        {"mac_lp_type_and_term": 0b11, "is_p2p": 1, "skip_p2p_trap" : 1},
    ]
    for line in table_data:
        key = l2_lpts_skip_p2p_static_table_key_t(mac_lp_type_and_term=line["mac_lp_type_and_term"],
                                                  is_p2p=line["is_p2p"])
        value = l2_lpts_skip_p2p_static_table_value_t(skip_p2p_trap=line["skip_p2p_trap"])
        table.insert(NETWORK_CONTEXT, key, value)


# +--------------+-----------------+------------+--------+----------+
# |  mac_lp_type |  mac_terminated |  is_tagged | is_svi |  action  |
# |      0       |        0        |       0    |    1   | 4'b0001  |
# |      0       |        0        |       1    |    0   | 4'b0010  |
# |      0       |        0        |       1    |    1   | 4'b0011  |
# |      0       |        1        |       0    |    0   | 4'b0101  |
# |      0       |        1        |       0    |    1   | 4'b0101  |
# |      0       |        1        |       1    |    0   | 4'b0111  |
# |      0       |        1        |       1    |    1   | 4'b0111  |
# |      1       |        0        |       0    |    0   | 4'b1000  |
# |      1       |        0        |       0    |    1   | 4'b1000  |
# |      1       |        0        |       1    |    0   | 4'b1010  |
# |      1       |        0        |       1    |    1   | 4'b1010  |
# |      1       |        1        |       0    |    0   | 4'b1100  |
# |      1       |        1        |       0    |    1   | 4'b1100  |
# |      1       |        1        |       1    |    0   | 4'b1110  |
# |      1       |        1        |       1    |    1   | 4'b1110  |
# |      0       |        0        |       0    |    0   | 4'b0000  |
# +--------------+-----------------+------------+--------+----------+


def config_l2_lpts_ctrl_fields_static_table():
    table = l2_lpts_ctrl_fields_static_table
    table_data = [
        {
            "key"     : {"mac_lp_type": 0b0,  "mac_terminated": 0b0, "is_tagged": 0b0, "is_svi": 0b1},
            "mask"    : {"mac_lp_type": 0b1,  "mac_terminated": 0b1, "is_tagged": 0b1, "is_svi": 0b1},
            "payload" : {"ctrl_fields": 0b0001},
        },
        {
            "key"     : {"mac_lp_type": 0b0,  "mac_terminated": 0b0, "is_tagged": 0b1, "is_svi": 0b0},
            "mask"    : {"mac_lp_type": 0b1,  "mac_terminated": 0b1, "is_tagged": 0b1, "is_svi": 0b1},
            "payload" : {"ctrl_fields": 0b0010},
        },
        {
            "key"     : {"mac_lp_type": 0b0,  "mac_terminated": 0b0, "is_tagged": 0b1, "is_svi": 0b1},
            "mask"    : {"mac_lp_type": 0b1,  "mac_terminated": 0b1, "is_tagged": 0b1, "is_svi": 0b1},
            "payload" : {"ctrl_fields": 0b0011},
        },
        {
            "key"     : {"mac_lp_type": 0b0,  "mac_terminated": 0b1, "is_tagged": 0b0, "is_svi": 0b0},
            "mask"    : {"mac_lp_type": 0b1,  "mac_terminated": 0b1, "is_tagged": 0b1, "is_svi": 0b1},
            "payload" : {"ctrl_fields": 0b0101},
        },
        {
            "key"     : {"mac_lp_type": 0b0,  "mac_terminated": 0b1, "is_tagged": 0b0, "is_svi": 0b1},
            "mask"    : {"mac_lp_type": 0b1,  "mac_terminated": 0b1, "is_tagged": 0b1, "is_svi": 0b1},
            "payload" : {"ctrl_fields": 0b0101},
        },
        {
            "key"     : {"mac_lp_type": 0b0,  "mac_terminated": 0b1, "is_tagged": 0b1, "is_svi": 0b0},
            "mask"    : {"mac_lp_type": 0b1,  "mac_terminated": 0b1, "is_tagged": 0b1, "is_svi": 0b1},
            "payload" : {"ctrl_fields": 0b0111},
        },
        {
            "key"     : {"mac_lp_type": 0b0,  "mac_terminated": 0b1, "is_tagged": 0b1, "is_svi": 0b1},
            "mask"    : {"mac_lp_type": 0b1,  "mac_terminated": 0b1, "is_tagged": 0b1, "is_svi": 0b1},
            "payload" : {"ctrl_fields": 0b0111},
        },
        {
            "key"     : {"mac_lp_type": 0b1,  "mac_terminated": 0b0, "is_tagged": 0b0, "is_svi": 0b0},
            "mask"    : {"mac_lp_type": 0b1,  "mac_terminated": 0b1, "is_tagged": 0b1, "is_svi": 0b1},
            "payload" : {"ctrl_fields": 0b1000},
        },
        {
            "key"     : {"mac_lp_type": 0b1,  "mac_terminated": 0b0, "is_tagged": 0b0, "is_svi": 0b1},
            "mask"    : {"mac_lp_type": 0b1,  "mac_terminated": 0b1, "is_tagged": 0b1, "is_svi": 0b1},
            "payload" : {"ctrl_fields": 0b1000},
        },
        {
            "key"     : {"mac_lp_type": 0b1,  "mac_terminated": 0b0, "is_tagged": 0b1, "is_svi": 0b0},
            "mask"    : {"mac_lp_type": 0b1,  "mac_terminated": 0b1, "is_tagged": 0b1, "is_svi": 0b1},
            "payload" : {"ctrl_fields": 0b1010},
        },
        {
            "key"     : {"mac_lp_type": 0b1,  "mac_terminated": 0b0, "is_tagged": 0b1, "is_svi": 0b1},
            "mask"    : {"mac_lp_type": 0b1,  "mac_terminated": 0b1, "is_tagged": 0b1, "is_svi": 0b1},
            "payload" : {"ctrl_fields": 0b1010},
        },
        {
            "key"     : {"mac_lp_type": 0b1,  "mac_terminated": 0b1, "is_tagged": 0b0, "is_svi": 0b0},
            "mask"    : {"mac_lp_type": 0b1,  "mac_terminated": 0b1, "is_tagged": 0b1, "is_svi": 0b1},
            "payload" : {"ctrl_fields": 0b1100},
        },
        {
            "key"     : {"mac_lp_type": 0b1,  "mac_terminated": 0b1, "is_tagged": 0b0, "is_svi": 0b1},
            "mask"    : {"mac_lp_type": 0b1,  "mac_terminated": 0b1, "is_tagged": 0b1, "is_svi": 0b1},
            "payload" : {"ctrl_fields": 0b1100},
        },
        {
            "key"     : {"mac_lp_type": 0b1,  "mac_terminated": 0b1, "is_tagged": 0b1, "is_svi": 0b0},
            "mask"    : {"mac_lp_type": 0b1,  "mac_terminated": 0b1, "is_tagged": 0b1, "is_svi": 0b1},
            "payload" : {"ctrl_fields": 0b1110},
        },
        {
            "key"     : {"mac_lp_type": 0b1,  "mac_terminated": 0b1, "is_tagged": 0b1, "is_svi": 0b1},
            "mask"    : {"mac_lp_type": 0b1,  "mac_terminated": 0b1, "is_tagged": 0b1, "is_svi": 0b1},
            "payload" : {"ctrl_fields": 0b1110},
        },
    ]
    location = 0
    for line in table_data:
        key = l2_lpts_ctrl_fields_static_table_key_t(mac_lp_type = line["key"]["mac_lp_type"],
                                                     mac_terminated = line["key"]["mac_terminated"],
                                                     is_tagged=line["key"]["is_tagged"],
                                                     is_svi=line["key"]["is_svi"])

        mask = l2_lpts_ctrl_fields_static_table_key_t(mac_lp_type = line["mask"]["mac_lp_type"],
                                                      mac_terminated = line["mask"]["mac_terminated"],
                                                      is_tagged=line["mask"]["is_tagged"],
                                                      is_svi=line["mask"]["is_svi"])
        value = l2_lpts_ctrl_fields_static_table_value_t(ctrl_fields=line["payload"]["ctrl_fields"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


def config_urpf_ipsa_dest_is_lpts_static_table():
    table_config = TcamTableConfig("urpf_ipsa_dest_is_lpts_static_table")
    table_data = [
        {"key": ["ipsa_dest_prefix"], "value": ["is_lpts_prefix"]},
        {"key": [DESTINATION_LPTS_PREFIX], "value": [1]},
        {"key": [_DONT_CARE], "value": [0]}
    ]
    table_config.create_table(table_data, NETWORK_CONTEXT)


def config_oamp_drop_destination_static_table():
    table = oamp_drop_destination_static_table

    key = oamp_drop_destination_static_table_key_t()
    value = oamp_drop_destination_static_table_value_t(DESTINATION_MASK_DSP | RX_NOT_CNT_DROP_SYSTEM_PORT_GID)
    table.insert(HOST_CONTEXT, key, value)
