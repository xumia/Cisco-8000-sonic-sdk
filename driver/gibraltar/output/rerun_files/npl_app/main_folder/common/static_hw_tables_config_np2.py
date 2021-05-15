# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

# Static initialization for hardware tables defined in hardware.npl

# Since we manually indented tables in this file, we don't want pep8 to mess with spaces
# This directive is read by leaba_format.py script
# pep8_extra_args = "--ignore=E2"

import os
from config_tables_utils import *
from enum import IntEnum

DONT_CARE = Key(value=0, mask=0)
ALL_1 = (1 << 128) - 1
FWD_HEADER_TYPE_NUM_BITS = 4
ENCAP_HEADER_OFFSET_IN_BITS_TO_IP_ENCAP_ENC_TYPE_2_NH = 40 # Type(4)+l3-dlp(16)+nh-or-host-ptr(20)
ENCAP_HEADER_OFFSET_IN_BITS_TO_IP_ENCAP_ENC_TYPE_2_HOST = 68 # Type(4)+l3-dlp(16)+host(48)
NPU_BASE_LEABA_DONT_OVERWRITE_WIDTH = 64
NPU_BASE_HEADER_LEABA_WIDTH = 28
NPU_HEADER_OFFSET_IN_BITS_TO_ENCAP_DATA = NPU_BASE_LEABA_DONT_OVERWRITE_WIDTH + NPU_BASE_HEADER_LEABA_WIDTH


def config_tables():
    config_txpp_initial_npe_macro_table()
    config_term_to_fwd_hdr_shift_table()
    config_txpp_cud_to_ibm_disable_table()
    config_txpp_cud_mapping_encap_data_source_select()
    config_txpp_dlp_profile_key_construct_parameters_table()
    config_txpp_dest_port_type_to_dlp_profile_en_table()
    config_ip_mc_mpls_next_macro_static_table()
    config_lb_vector_table()

# Enable opeartion on all types except CUD


def config_txpp_cud_to_ibm_disable_table():
    table = txpp_cud_to_ibm_disable_table
    for i in range(0, 16):
        results_vector = 7
        if (i == TX_CUD_IBM_CMD_PREFIX):
            results_vector = 0
        value = txpp_cud_to_ibm_disable_table_value_t(txpp_cud_to_ibm_disable_table_result=results_vector)
        key = txpp_cud_to_ibm_disable_table_key_t(i)
        table.insert(NETWORK_CONTEXT, key, value)

# key_func for txpp_initial_npe_macro_table


def txpp_initial_npe_macro_table_key_func(key_args, mask_args):
    table_key  = txpp_first_macro_table_key_t(**key_args)
    table_mask = txpp_first_macro_table_key_t(**mask_args)
    key = txpp_initial_npe_macro_table_key_t(txpp_first_macro_table_key=table_key)
    mask = txpp_initial_npe_macro_table_key_t(txpp_first_macro_table_key=table_mask)
    return key, mask


def config_txpp_initial_npe_macro_table():
    table = txpp_initial_npe_macro_table
    table_config = TcamTableConfig("txpp_initial_npe_macro_table")
    table_data = [
        {"key": ["is_mc",
                 "src_port_type",
                 "dst_port_type",
                 "is_ibm",
                 "ibm_cmd",
                 "fwd_type",
                 "encap_type"],
         "value": ["first_macro"]},
        # =============  FWD_HEADER_TYPE_SVL  ===============
        {"key": [DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE,
                 FWD_HEADER_TYPE_SVL, DONT_CARE], "value": [NETWORK_TX_SVL_MACRO]},
        # =============  Collapsed MC ===============
        {"key": [DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, Key(HEADER_TYPE_IPV4_HEADERS_PREFIX << 1, mask=0b1110),
                 NPU_ENCAP_L3_HEADER_TYPE_COLLAPSED_MC], "value": [NETWORK_TX_IP_TO_NH_MC_MACRO]},
        {"key": [DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, Key(HEADER_TYPE_IPV6_HEADERS_PREFIX << 1, mask=0b1110),
                 NPU_ENCAP_L3_HEADER_TYPE_COLLAPSED_MC], "value": [NETWORK_TX_IP_TO_NH_MC_MACRO]},
        # ================= Inject up/down ===============
        {"key": [DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, FWD_HEADER_TYPE_INJECT_DOWN                           ,
                 DONT_CARE                            ], "value": [TX_INJECT_MACRO]},
        # =====================  FWD_HEADER_TYPE_ETHERNET  =================
        {"key": [DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE                              ,
                 NPU_ENCAP_L2_HEADER_TYPE_AC          ], "value": [NETWORK_TX_MAC_AC_AND_ACL_MACRO]},
        # {"key": [DONT_CARE, FWD_HEADER_TYPE_ETHERNET                              , NPU_ENCAP_L2_HEADER_TYPE_PWE       ], "value": [NETWORK_TX_MAC_TO_PWE_MACRO]},
        # {"key": [DONT_CARE, FWD_HEADER_TYPE_ETHERNET                        , NPU_ENCAP_L2_HEADER_TYPE_PWE_WITH_TUNNEL_ID], "value": [NETWORK_TX_MAC_TO_PWE_MACRO]},
        {"key": [DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE                              ,
                 NPU_ENCAP_L2_HEADER_TYPE_VXLAN       ], "value": [NETWORK_TX_GRE_VXLAN_MACRO]},
        # =====================  FWD_HEADER_TYPE_IPV4/6  =================
        {"key": [1        , DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, Key(HEADER_TYPE_IPV4_HEADERS_PREFIX << 1, mask=0b1110),
                 NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH ], "value": [NETWORK_TX_IP_TO_NH_MC_MACRO]},
        {"key": [1        , DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, Key(HEADER_TYPE_IPV6_HEADERS_PREFIX << 1, mask=0b1110),
                 NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH ], "value": [NETWORK_TX_IP_TO_NH_MC_MACRO]},
        {"key": [0        , DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, FWD_HEADER_TYPE_IPV4                                  ,
                 NPU_ENCAP_L3_HEADER_TYPE_HOST_MAC    ], "value": [NETWORK_TX_IP_UC_FIRST_MACRO]},
        {"key": [0        , DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, FWD_HEADER_TYPE_IPV6                                  ,
                 NPU_ENCAP_L3_HEADER_TYPE_HOST_MAC    ], "value": [NETWORK_TX_IP_UC_FIRST_MACRO]},
        {"key": [DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, FWD_HEADER_TYPE_IPV4                                  ,
                 NPU_ENCAP_L2_HEADER_TYPE_VXLAN       ], "value": [NETWORK_TX_GRE_VXLAN_MACRO]},
        {"key": [DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, FWD_HEADER_TYPE_IPV6                                  ,
                 NPU_ENCAP_L2_HEADER_TYPE_VXLAN       ], "value": [NETWORK_TX_GRE_VXLAN_MACRO]},
        {"key": [0        , DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, FWD_HEADER_TYPE_IPV4                                  ,
                 NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH ], "value": [NETWORK_TX_IP_UC_FIRST_MACRO]},
        {"key": [DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, FWD_HEADER_TYPE_IPV4                                  ,
                 NPU_ENCAP_L3_HEADER_TYPE_GRE         ], "value": [NETWORK_TX_GRE_VXLAN_MACRO]},
        {"key": [DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, FWD_HEADER_TYPE_IPV6                                  ,
                 NPU_ENCAP_L3_HEADER_TYPE_GRE         ], "value": [NETWORK_TX_GRE_VXLAN_MACRO]},
        {"key": [0        , DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, FWD_HEADER_TYPE_MPLS_BOS_IPV4                         ,
                 NPU_ENCAP_L3_HEADER_TYPE_GRE         ], "value": [NETWORK_TX_GRE_VXLAN_MACRO]},
        {"key": [0        , DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, FWD_HEADER_TYPE_MPLS_BOS_IPV6                         ,
                 NPU_ENCAP_L3_HEADER_TYPE_GRE         ], "value": [NETWORK_TX_GRE_VXLAN_MACRO]},
        # entry for dummy Bud Node member handling
        {"key": [1        , DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, FWD_HEADER_TYPE_MPLS_BOS_IPV4                         ,
                 NPU_ENCAP_L3_HEADER_TYPE_HOST_MAC    ], "value": [NETWORK_TX_IP_TO_NH_MC_MACRO]},
        {"key": [1        , DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, FWD_HEADER_TYPE_MPLS_BOS_IPV6                         ,
                 NPU_ENCAP_L3_HEADER_TYPE_HOST_MAC    ], "value": [NETWORK_TX_IP_TO_NH_MC_MACRO]},
        {"key": [0        , DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, FWD_HEADER_TYPE_IPV6                                  ,
                 NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH ], "value": [NETWORK_TX_IP_UC_FIRST_MACRO]},
        # ================== MPLS_ ================
        {"key": [DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, Key(HEADER_TYPE_MPLS_HEADERS_PREFIX << 2, mask=0b1100), Key(
            0b0000, mask=0b1000)             ], "value": [NETWORK_TX_MPLS_L3_MACRO]},
        # ====================== MPLS + IPv6 + IPv4 path sharing encap types. Don'
        {"key": [DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE                                             ,
                 NPU_ENCAP_L3_HEADER_TYPE_LDP_OVER_TE ], "value": [NETWORK_TX_MPLS_L3_MACRO]},
        {"key": [DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE                                             ,
                 NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE     ], "value": [NETWORK_TX_MPLS_L3_MACRO]},
        {"key": [DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE                                             ,
                 NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE_SR  ], "value": [NETWORK_TX_MPLS_L3_MACRO]},
        {"key": [DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE                                             ,
                 NPU_ENCAP_L3_HEADER_TYPE_TE_HE_WITH_TUNNEL_ID],
         "value": [NETWORK_TX_MPLS_L3_MACRO]},
        # ================== In bound mirror/redirect, and default entry ======================
        {"key": [DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE                                             ,
                 NPU_ENCAP_MIRROR_OR_REDIRECT         ], "value": [TX_PUNT_MACRO]},
        # =====================  MC HOST   =================
        {"key": [1        , DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, Key(HEADER_TYPE_IPV4_HEADERS_PREFIX << 1, mask=0b1110),
                 NPU_ENCAP_L3_HEADER_TYPE_PWE_OR_MC_ACCOUNTING ], "value": [NETWORK_TX_IP_TO_NH_MC_ACCOUNTING_MACRO]},
        {"key": [1        , DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, Key(HEADER_TYPE_IPV6_HEADERS_PREFIX << 1, mask=0b1110),
                 NPU_ENCAP_L3_HEADER_TYPE_PWE_OR_MC_ACCOUNTING], "value": [NETWORK_TX_IP_TO_NH_MC_ACCOUNTING_MACRO]},
        # =============  ENCAP_TYPE_SVL  ===============
        {"key": [DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE                                             ,
                 NPU_ENCAP_L2_HEADER_TYPE_SVL], "value": [NETWORK_TX_SVL_MACRO]},
        # Default entry
        {"key": [DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE, DONT_CARE                                             ,
                 DONT_CARE                            ], "value": [NETWORK_TRANSMIT_ERROR_MACRO]},
    ]

    table_config.create_table(
        table_data,
        NETWORK_CONTEXT,
        key_func=txpp_initial_npe_macro_table_key_func,
        args_map={
            "first_macro": "np_macro_id"})


def config_term_to_fwd_hdr_shift_table():
    table = term_to_fwd_hdr_shift_table
    table_config = DirectTableConfig("term_to_fwd_hdr_shift_table")
    # header_shift_disable_offset_recalc: matches pd.npu_header.fwd_qos_tag[4] -> (bit 264 - offset 64) / 8 = 25
    # highest_header_to_update: the number of headers to update the offset to, regardless of the NPL 'recalculate' indication
    table_data = [ {"key": "" , "value": [ "highest_header_to_update", "header_shift_disable_offset_recalc",
                                           "enable_header_shift"]}, {"key": 0 , "value": [ 0 , 0, 0 ]} ]
    table_config.create_table(table_data, [NETWORK_CONTEXT, UDC_CONTEXT])


def config_txpp_cud_mapping_encap_data_source_select():
    table = encap_data_source_select_table
    table_config = DirectTableConfig("encap_data_source_select_table")
    # TODO: Currently assuming here not using encap data of 120 bits! for this feature will need additional changes (NPL, regs
    # write..)
    encap_data_is_120b = 0
    table_size = table_config.get_table_size()
    table_data = [{"key": ["use_narrow_cud", "use_mapped_cud"] , "value": ["encap_data_shift",
                                                                           "encap_data_size", "mapped_cud_shift", "mapped_cud_size", "expanded_cud_shift", "expanded_cud_size"]}]

    for line in range(0, table_size):
        use_mapped_cud = line & 0b1
        use_narrow_cud = (line >> 1) & 0b1
        # NOTE: All values are in nibble resolution
        # Orig encap data
        encap_data_shift = int(((120 if encap_data_is_120b else 108) - 28) / 4) # size of orig encap data is 28 bits
        encap_data_size = int(0 if (use_mapped_cud and not use_narrow_cud) else (28 / 4))
        # Expanded cud
        expanded_cud_shift = 0
        expanded_cud_size = int(0 if use_mapped_cud else 24 / 4)
        # Mapped cud
        mapped_cud_shift = 0
        mapped_cud_size = int(
            (60 /
             4 if encap_data_is_120b else 40 /
             4) if (
                use_mapped_cud & use_narrow_cud) else (
                120 /
                4 if encap_data_is_120b else 80 /
                4) if use_mapped_cud else 0)

        table_data.append({"key": [use_narrow_cud, use_mapped_cud], "value": [encap_data_shift,
                                                                              encap_data_size, mapped_cud_shift, mapped_cud_size, expanded_cud_shift, expanded_cud_size]})

    args_map = {"use_mapped_cud": "cud_mapping_local_vars_map_cud", "use_narrow_cud": "cud_mapping_local_vars_mapped_cud_is_narrow",
                "encap_data_shift":"orig_encap_data_shift_in_nibble", "encap_data_size":"orig_encap_data_size_in_nibble",
                "mapped_cud_shift":"mapped_cud_shift_in_nibble", "mapped_cud_size":"mapped_cud_size_in_nibble",
                "expanded_cud_shift":"expanded_cud_shift_in_nibble", "expanded_cud_size":"expanded_cud_size_in_nibble"}
    table_config.create_table(table_data, [NETWORK_CONTEXT, UDC_CONTEXT], args_map=args_map)


def config_txpp_dlp_profile_key_construct_parameters_table():
    # NOTE: Iteration ranges and conditions in this function are copied from
    # config_txpp_fwd_header_type_is_l2_table() in static_hw_tables_config_pacific.py
    table = txpp_dlp_profile_key_construct_parameters_table
    MAX_ENCAP_DATA = 15
    # Value is {DLP type(2), Offset into encap_or_term in nibbles(5), mask(4)}
    # 18 bits are taken from encap_or_term, from those top 4 MSBs are masked
    # For L3 only 16 bits are used so we mask off the top 2 MSBs. For L2 all
    # are used so the mask is all 1s. Location of 18 bits in encap_or_term for
    # L2 is 84 bits (21 nibbles) and for L3 88 bits (22 nibbles)

    # Ethernet is true for DLP type L2, all others are false
    # 2 exceptions: NPL_FWD_HEADER_TYPE_IPV{4/6}_COLLAPSED_MC with encap data of a bridge_nh is also L2
    for encap_data in range(0, MAX_ENCAP_DATA):
        for fwd_header_type in range(0, (1 << FWD_HEADER_TYPE_NUM_BITS)):
            if fwd_header_type == FWD_HEADER_TYPE_ETHERNET or ((encap_data == NPU_ENCAP_L3_HEADER_TYPE_COLLAPSED_MC) and (
                    fwd_header_type in [FWD_HEADER_TYPE_IPV4_COLLAPSED_MC, FWD_HEADER_TYPE_IPV6_COLLAPSED_MC])):
                value = txpp_dlp_profile_key_construct_parameters_table_value_t(
                    dlp_profile_local_vars_t(dlp_type=DLP_TYPE_L2, dlp_offset=DLP_OFFSET_L2, dlp_mask=DLP_MASK_L2))
            else:
                value = txpp_dlp_profile_key_construct_parameters_table_value_t(
                    dlp_profile_local_vars_t(dlp_type=DLP_TYPE_L3, dlp_offset=DLP_OFFSET_L3, dlp_mask=DLP_MASK_L3))
            key = txpp_dlp_profile_key_construct_parameters_table_key_t(tx_npu_header_encap_or_term_107_104_=encap_data,
                                                                        tx_npu_header_fwd_header_type=fwd_header_type)
            table.insert(NETWORK_CONTEXT, key, value)


def config_txpp_dest_port_type_to_dlp_profile_en_table():
    table = txpp_dest_port_type_to_dlp_profile_en_table
    table_config = DirectTableConfig("txpp_dest_port_type_to_dlp_profile_en_table")
    table_data = [{"key": ["txpp_dest_port_type"], "value": ["txpp_dest_port_type_to_dlp_profile_en_result"]},
                  {"key": TXPP_DEST_PORT_TYPE_NETWORK, "value": True},
                  {"key": TXPP_DEST_PORT_TYPE_FABRIC, "value": False},
                  {"key": TXPP_DEST_PORT_TYPE_STACKING, "value": False},
                  {"key": TXPP_DEST_PORT_TYPE_RESEREVD, "value": False},
                  ]
    table_config.create_table(table_data, NETWORK_CONTEXT)


def config_ip_mc_mpls_next_macro_static_table():
    table = ip_mc_mpls_next_macro_static_table
    table_data = [
        # IPv4 multicast
        {
            "key"     : {"type": PROTOCOL_TYPE_IPV4_SUFFIX,  "ipv4_msb": IPV4_MULTICAST_PREFIX, "ipv6_msb": 0},
            "mask"    : {"type": 0b01111,                    "ipv4_msb": ALL_1,                 "ipv6_msb": 0},
            "payload" : {"next_macro": NETWORK_RX_MAC_RELAY_IPV4_MC_TERMINATION_MACRO,          "inc": PL_INC_NONE}
        },
        {
            "key"     : {"type": PROTOCOL_TYPE_IPV6_SUFFIX, "ipv4_msb": 0,                      "ipv6_msb": IPV6_MULTICAST_PREFIX},
            "mask"    : {"type": 0b01111,                   "ipv4_msb": 0,                      "ipv6_msb": ALL_1},
            "payload" : {"next_macro": NETWORK_RX_MAC_RELAY_IPV6_MC_TERMINATION_MACRO,          "inc": PL_INC_NONE}
        },
        {
            "key":  {"type": PROTOCOL_TYPE_MPLS, "ipv4_msb": 0,                                 "ipv6_msb": 0},
            "mask": {"type": ALL_1,                         "ipv4_msb": 0,                      "ipv6_msb": 0},
            "payload" : {"next_macro": NETWORK_RX_MPLS_AF_AND_TERMINATION_MACRO,                "inc": PL_INC_ONCE}
        },
    ]

    location = 0
    for line in table_data:
        key = ip_mc_mpls_next_macro_static_table_key_t(
            type=line["key"]["type"],
            ipv4_msb=line["key"]["ipv4_msb"],
            ipv6_msb=line["key"]["ipv6_msb"])
        mask = ip_mc_mpls_next_macro_static_table_key_t(
            type=line["mask"]["type"],
            ipv4_msb=line["mask"]["ipv4_msb"],
            ipv6_msb=line["mask"]["ipv6_msb"])
        value = ip_mc_mpls_next_macro_static_table_value_t(macro_id=line["payload"]["next_macro"], pl_inc=line["payload"]["inc"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


def get_fi_array_type_vector(type0 = 0b00000, type1 = 0b00000, type2 = 0b00000, type3 = 0b00000, type4 = 0b00000, type5 = 0b00000):
    res_types = 0b00000_00000_00000_00000_00000_00000

    res_types |= type5
    res_types |= (type4 << 5)
    res_types |= (type3 << 10)
    res_types |= (type2 << 15)
    res_types |= (type1 << 20)
    res_types |= (type0 << 25)
    return res_types


def config_lb_vector_table():
    table = lb_vector_table
    DONT_CARE_LB_VECTOR_TABLE = 0

    # MPLS
    lb_mpls_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_MPLS)
    lb_mpls_res_mask  = get_fi_array_type_vector(0b11111)
    mpls_lb_result = lb_vector_table_result_t(
        mask_profile = 0,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_MPLS,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=0,
        l2_selected_layer_offset=0)

    # MPLS / ELI
    lb_mpls_el_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_MPLS)
    lb_mpls_el_res_mask  = get_fi_array_type_vector(0b11111)
    mpls_el_lb_result = lb_vector_table_result_t(
        mask_profile = 0,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_MPLS_EL,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=0,
        l2_selected_layer_offset=0)

    # MPLS / IPv4 or Eth / IPv4
    lb_x_ipv4_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_ETHERNET, PROTOCOL_TYPE_IPV4)
    lb_x_ipv4_res_mask  = get_fi_array_type_vector(0b00000, 0b11111)
    x_ipv4_lb_result = lb_vector_table_result_t(
        mask_profile = 1,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV4_L4,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=1,
        l2_selected_layer_offset=0)

    #MPLS / IPv4 / L4 or Eth / IPv4 / L4 or IPv4 / IPv4
    lb_x_ipv4_l4_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_ETHERNET, PROTOCOL_TYPE_IPV4_L4)
    lb_x_ipv4_l4_res_mask  = get_fi_array_type_vector(0b00000, 0b11111)
    x_ipv4_l4_lb_result = lb_vector_table_result_t(
        mask_profile = 2,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV4_L4,
        l4_offset_in_headers=1,
        l3_selected_layer_offset=1,
        l2_selected_layer_offset=0)

    # MPLS / IPv6 or Eth / IPv6
    lb_x_ipv6_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_ETHERNET, PROTOCOL_TYPE_IPV6)
    lb_x_ipv6_res_mask  = get_fi_array_type_vector(0b00000, 0b11111)
    x_ipv6_lb_result = lb_vector_table_result_t(
        mask_profile = 3,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV6_L4,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=1,
        l2_selected_layer_offset=0)

    #MPLS / IPv6 / L4 or Eth / IPv6 / L4
    lb_x_ipv6_l4_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_ETHERNET, PROTOCOL_TYPE_IPV6_L4)
    lb_x_ipv6_l4_res_mask  = get_fi_array_type_vector(0b00000, 0b11111)
    x_ipv6_l4_lb_result = lb_vector_table_result_t(
        mask_profile = 4,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV6_L4,
        l4_offset_in_headers=1,
        l3_selected_layer_offset=1,
        l2_selected_layer_offset=0)

    # MPLS /Eth
    lb_mpls_eth_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_MPLS, PROTOCOL_TYPE_ETHERNET)
    lb_mpls_eth_res_mask  = get_fi_array_type_vector(0b11111, 0b11111)
    mpls_eth_lb_result = lb_vector_table_result_t(
        mask_profile = 5,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=0,
        l2_selected_layer_offset=1)

    # MPLS / Eth / VLAN
    lb_mpls_eth_vlan_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_MPLS, PROTOCOL_TYPE_ETHERNET_VLAN)
    lb_mpls_eth_vlan_res_mask  = get_fi_array_type_vector(0b11111, 0b11111)
    mpls_eth_vlan_lb_result = lb_vector_table_result_t(
        mask_profile = 6,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=0,
        l2_selected_layer_offset=1)

    #Eth / VLAN
    lb_eth_w_vlan_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_ETHERNET_VLAN, PROTOCOL_TYPE_VLAN_0)
    #VLANs share 3 same MSBs prefix, and 2 different bits LSB
    lb_eth_w_vlan_res_mask  = get_fi_array_type_vector(0b11111, 0b11100)
    eth_w_vlan_lb_result = lb_vector_table_result_t(
        mask_profile = 5,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=0,
        l2_selected_layer_offset=0)

    #Eth without VLAN
    lb_eth_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_ETHERNET)
    lb_eth_res_mask  = get_fi_array_type_vector(0b11111)
    eth_lb_result = lb_vector_table_result_t(
        mask_profile = 6,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=0,
        l2_selected_layer_offset=0)

    #Eth / VLAN / IPv4
    lb_eth_vlan_ipv4_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_ETHERNET_VLAN, PROTOCOL_TYPE_VLAN_0, PROTOCOL_TYPE_IPV4)
    lb_eth_vlan_ipv4_res_mask  = get_fi_array_type_vector(0b11111, 0b11100, 0b11111)
    eth_vlan_ipv4_lb_result = lb_vector_table_result_t(
        mask_profile = 1,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV4_L4,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=1,
        l2_selected_layer_offset=0)

    #Eth / VLAN / IPv4 / L4
    lb_eth_vlan_ipv4_l4_res_types = get_fi_array_type_vector(
        PROTOCOL_TYPE_ETHERNET_VLAN, PROTOCOL_TYPE_VLAN_0, PROTOCOL_TYPE_IPV4_L4)
    lb_eth_vlan_ipv4_l4_res_mask  = get_fi_array_type_vector(0b11111, 0b11100, 0b11111)
    eth_vlan_ipv4_l4_lb_result = lb_vector_table_result_t(
        mask_profile = 2,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV4_L4,
        l4_offset_in_headers=1,
        l3_selected_layer_offset=1,
        l2_selected_layer_offset=0)

    #Eth / VLAN / IPv6
    lb_eth_vlan_ipv6_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_ETHERNET_VLAN, PROTOCOL_TYPE_VLAN_0, PROTOCOL_TYPE_IPV6)
    lb_eth_vlan_ipv6_res_mask  = get_fi_array_type_vector(0b11111, 0b11100, 0b11111)
    eth_vlan_ipv6_lb_result = lb_vector_table_result_t(
        mask_profile = 3,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV6_L4,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=1,
        l2_selected_layer_offset=0)

    #Eth / VLAN / IPv6 / L4
    lb_eth_vlan_ipv6_l4_res_types = get_fi_array_type_vector(
        PROTOCOL_TYPE_ETHERNET_VLAN, PROTOCOL_TYPE_VLAN_0, PROTOCOL_TYPE_IPV6_L4)
    lb_eth_vlan_ipv6_l4_res_mask  = get_fi_array_type_vector(0b11111, 0b11100, 0b11111)
    eth_vlan_ipv6_l4_lb_result = lb_vector_table_result_t(
        mask_profile = 4,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV6_L4,
        l4_offset_in_headers=1,
        l3_selected_layer_offset=1,
        l2_selected_layer_offset=0)

    #IPv4 / GRE / IPv4  or IPv4 / UDP /IPv4
    lb_ipv4_gre_ipv4_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_IPV4, PROTOCOL_TYPE_GRE, PROTOCOL_TYPE_IPV4)
    lb_ipv4_gre_ipv4_res_mask  = get_fi_array_type_vector(0b01111, 0b00000, 0b11111)
    ipv4_gre_ipv4_lb_result = lb_vector_table_result_t(
        mask_profile = 1,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV4_L4,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=1,
        l2_selected_layer_offset=0)
    #IPv4 / GRE / IPv4 / L4 or IPv4 / UDP / IPv4 / L4
    lb_ipv4_gre_ipv4l4_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_IPV4, PROTOCOL_TYPE_GRE, PROTOCOL_TYPE_IPV4_L4)
    lb_ipv4_gre_ipv4l4_res_mask  = get_fi_array_type_vector(0b01111, 0b00000, 0b11111)
    ipv4_gre_ipv4l4_lb_result = lb_vector_table_result_t(
        mask_profile = 2,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV4_L4,
        l4_offset_in_headers=1,
        l3_selected_layer_offset=1,
        l2_selected_layer_offset=0)

    #IPv4 / GRE / MPLS / IPv4 or IPv4 / UDP / MPLS / IPv4
    lb_ipv4_gre_mpls_ipv4_res_types = get_fi_array_type_vector(
        PROTOCOL_TYPE_IPV4, PROTOCOL_TYPE_GRE, PROTOCOL_TYPE_MPLS, PROTOCOL_TYPE_IPV4)
    lb_ipv4_gre_mpls_ipv4_res_mask  = get_fi_array_type_vector(0b01111, 0b00000, 0b11111, 0b11111)
    ipv4_gre_mpls_ipv4_lb_result = lb_vector_table_result_t(
        mask_profile = 1,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV4_L4,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=2,
        l2_selected_layer_offset=0)
    #IPv4 / GRE / MPLS / IPv4 / L4 or IPv4 / UDP / MPLS / IPv4 / L4
    lb_ipv4_gre_mpls_ipv4l4_res_types = get_fi_array_type_vector(
        PROTOCOL_TYPE_IPV4, PROTOCOL_TYPE_GRE, PROTOCOL_TYPE_MPLS, PROTOCOL_TYPE_IPV4_L4)
    lb_ipv4_gre_mpls_ipv4l4_res_mask  = get_fi_array_type_vector(0b01111, 0b00000, 0b11111, 0b11111)
    ipv4_gre_mpls_ipv4l4_lb_result = lb_vector_table_result_t(
        mask_profile = 2,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV4_L4,
        l4_offset_in_headers=1,
        l3_selected_layer_offset=2,
        l2_selected_layer_offset=0)

    #IPv4 / GRE / IPv6 or IPv4 / UDP / IPv6
    lb_ipv4_gre_ipv6_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_IPV4, PROTOCOL_TYPE_GRE, PROTOCOL_TYPE_IPV6)
    lb_ipv4_gre_ipv6_res_mask  = get_fi_array_type_vector(0b01111, 0b00000, 0b11111)
    ipv4_gre_ipv6_lb_result = lb_vector_table_result_t(
        mask_profile = 3,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV6_L4,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=1,
        l2_selected_layer_offset=0)
    #IPv4 / GRE / IPv6 / L4 or IPv4 / UDP / IPv4 / L4
    lb_ipv4_gre_ipv6l4_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_IPV4, PROTOCOL_TYPE_GRE, PROTOCOL_TYPE_IPV6_L4)
    lb_ipv4_gre_ipv6l4_res_mask  = get_fi_array_type_vector(0b01111, 0b00000, 0b11111)
    ipv4_gre_ipv6l4_lb_result = lb_vector_table_result_t(
        mask_profile = 4,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV6_L4,
        l4_offset_in_headers=1,
        l3_selected_layer_offset=1,
        l2_selected_layer_offset=0)

    #IPv4 / GRE / MPLS / IPv6
    lb_ipv4_gre_mpls_ipv6_res_types = get_fi_array_type_vector(
        PROTOCOL_TYPE_IPV4, PROTOCOL_TYPE_GRE, PROTOCOL_TYPE_MPLS, PROTOCOL_TYPE_IPV6)
    lb_ipv4_gre_mpls_ipv6_res_mask  = get_fi_array_type_vector(0b11111, 0b11111, 0b11111, 0b11111)
    ipv4_gre_mpls_ipv6_lb_result = lb_vector_table_result_t(
        mask_profile = 3,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV6_L4,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=2,
        l2_selected_layer_offset=0)
    #IPv4 / GRE / MPLS / IPv6 / L4
    lb_ipv4_gre_mpls_ipv6l4_res_types = get_fi_array_type_vector(
        PROTOCOL_TYPE_IPV4, PROTOCOL_TYPE_GRE, PROTOCOL_TYPE_MPLS, PROTOCOL_TYPE_IPV6_L4)
    lb_ipv4_gre_mpls_ipv6l4_res_mask  = get_fi_array_type_vector(0b11111, 0b11111, 0b11111, 0b11111)
    ipv4_gre_mpls_ipv6l4_lb_result = lb_vector_table_result_t(
        mask_profile = 4,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV6_L4,
        l4_offset_in_headers=1,
        l3_selected_layer_offset=2,
        l2_selected_layer_offset=0)
    #IPv4
    lb_ipv4_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_IPV4)
    lb_ipv4_res_mask  = get_fi_array_type_vector(0b11111)
    ipv4_lb_result = lb_vector_table_result_t(
        mask_profile = 1,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_IPV4_L4,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=0,
        l2_selected_layer_offset=0)

    #VXLAN / Eth / IPv4 or GRE / Eth / IPv4
    lb_vxlangre_ipv4_res_types = get_fi_array_type_vector(
        PROTOCOL_TYPE_IPV4_L4,
        PROTOCOL_TYPE_UDP,
        PROTOCOL_TYPE_ETHERNET,
        PROTOCOL_TYPE_IPV4)
    lb_vxlangre_ipv4_res_mask  = get_fi_array_type_vector(0b01111, 0b00000, 0b11111, 0b11111)
    vxlan_ipv4_lb_result = lb_vector_table_result_t(
        mask_profile = 1,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV4_L4,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=2,
        l2_selected_layer_offset=1)
    #VXLAN / Eth / IPv4 / L4 or GRE / Eth / IPv4 / L4
    lb_vxlangre_ipv4l4_res_types = get_fi_array_type_vector(
        PROTOCOL_TYPE_IPV4_L4,
        PROTOCOL_TYPE_UDP,
        PROTOCOL_TYPE_ETHERNET,
        PROTOCOL_TYPE_IPV4_L4)
    lb_vxlangre_ipv4l4_res_mask  = get_fi_array_type_vector(0b01111, 0b00000, 0b11111, 0b11111)
    vxlan_ipv4l4_lb_result = lb_vector_table_result_t(
        mask_profile = 2,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV4_L4,
        l4_offset_in_headers=1,
        l3_selected_layer_offset=2,
        l2_selected_layer_offset=1)
    #VXLAN / Eth / IPv6 or GRE / Eth / IPv6
    lb_vxlangre_ipv6_res_types = get_fi_array_type_vector(
        PROTOCOL_TYPE_IPV4_L4,
        PROTOCOL_TYPE_UDP,
        PROTOCOL_TYPE_ETHERNET,
        PROTOCOL_TYPE_IPV6)
    lb_vxlangre_ipv6_res_mask  = get_fi_array_type_vector(0b01111, 0b00000, 0b11111, 0b11111)
    vxlan_ipv6_lb_result = lb_vector_table_result_t(
        mask_profile = 3,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV6_L4,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=2,
        l2_selected_layer_offset=1)
    #VXLAN / Eth / IPv6 / L4 or GRE / Eth / IPv6 / L4
    lb_vxlangre_ipv6l4_res_types = get_fi_array_type_vector(
        PROTOCOL_TYPE_IPV4_L4,
        PROTOCOL_TYPE_UDP,
        PROTOCOL_TYPE_ETHERNET,
        PROTOCOL_TYPE_IPV6_L4)
    lb_vxlangre_ipv6l4_res_mask  = get_fi_array_type_vector(0b01111, 0b00000, 0b11111, 0b11111)
    vxlan_ipv6l4_lb_result = lb_vector_table_result_t(
        mask_profile = 4,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV6_L4,
        l4_offset_in_headers=1,
        l3_selected_layer_offset=2,
        l2_selected_layer_offset=1)
    #VXLAN / Eth or IPv4 / GRE / Eth
    lb_vxlangre_eth_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_IPV4_L4, PROTOCOL_TYPE_UDP, PROTOCOL_TYPE_ETHERNET)
    lb_vxlangre_eth_res_mask  = get_fi_array_type_vector(0b01111, 0b00000, 0b11111)
    vxlangre_eth_lb_result = lb_vector_table_result_t(
        mask_profile = 5,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=0,
        l2_selected_layer_offset=1)

    #VXLAN / Eth / VLAN / IPv4 or GRE / Eth / VLAN / IPv4
    lb_vxlangre_vlan_ipv4_res_types = get_fi_array_type_vector(
        PROTOCOL_TYPE_IPV4_L4,
        PROTOCOL_TYPE_UDP,
        PROTOCOL_TYPE_ETHERNET_VLAN,
        PROTOCOL_TYPE_VLAN_0,
        PROTOCOL_TYPE_IPV4)
    lb_vxlangre_vlan_ipv4_res_mask  = get_fi_array_type_vector(0b01111, 0b00000, 0b11111, 0b11100, 0b11111)
    vxlan_vlan_ipv4_lb_result = lb_vector_table_result_t(
        mask_profile = 1,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV4_L4,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=2,
        l2_selected_layer_offset=1)
    #VXLAN / Eth / VLAN / IPv4 / L4 or GRE / Eth / VLAN / IPv4 / L4
    lb_vxlangre_vlan_ipv4l4_res_types = get_fi_array_type_vector(
        PROTOCOL_TYPE_IPV4_L4,
        PROTOCOL_TYPE_UDP,
        PROTOCOL_TYPE_ETHERNET_VLAN,
        PROTOCOL_TYPE_VLAN_0,
        PROTOCOL_TYPE_IPV4_L4)
    lb_vxlangre_vlan_ipv4l4_res_mask  = get_fi_array_type_vector(0b01111, 0b00000, 0b11111, 0b11100, 0b11111)
    vxlan_vlan_ipv4l4_lb_result = lb_vector_table_result_t(
        mask_profile = 2,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV4_L4,
        l4_offset_in_headers=1,
        l3_selected_layer_offset=2,
        l2_selected_layer_offset=1)
    #VXLAN / Eth / VLAN / IPv6 or GRE / Eth / VLAN / IPv6
    lb_vxlangre_vlan_ipv6_res_types = get_fi_array_type_vector(
        PROTOCOL_TYPE_IPV4_L4,
        PROTOCOL_TYPE_UDP,
        PROTOCOL_TYPE_ETHERNET_VLAN,
        PROTOCOL_TYPE_VLAN_0,
        PROTOCOL_TYPE_IPV6)
    lb_vxlangre_vlan_ipv6_res_mask  = get_fi_array_type_vector(0b01111, 0b00000, 0b11111, 0b11100, 0b11111)
    vxlan_vlan_ipv6_lb_result = lb_vector_table_result_t(
        mask_profile = 3,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV6_L4,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=2,
        l2_selected_layer_offset=1)
    #VXLAN / Eth / VLAN / IPv6 / L4 or GRE / Eth / VLAN / IPv6 / L4
    lb_vxlangre_vlan_ipv6l4_res_types = get_fi_array_type_vector(
        PROTOCOL_TYPE_IPV4_L4,
        PROTOCOL_TYPE_UDP,
        PROTOCOL_TYPE_ETHERNET_VLAN,
        PROTOCOL_TYPE_VLAN_0,
        PROTOCOL_TYPE_IPV6_L4)
    lb_vxlangre_vlan_ipv6l4_res_mask  = get_fi_array_type_vector(0b01111, 0b00000, 0b11111, 0b11100, 0b11111)
    vxlan_vlan_ipv6l4_lb_result = lb_vector_table_result_t(
        mask_profile = 4,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID_IPV6_L4,
        l4_offset_in_headers=1,
        l3_selected_layer_offset=2,
        l2_selected_layer_offset=1)
    #VXLAN / Eth / VLAN or IPv4 / GRE / Eth / VLAN
    lb_vxlangre_eth_vlan_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_IPV4_L4, PROTOCOL_TYPE_UDP, PROTOCOL_TYPE_ETHERNET_VLAN)
    lb_vxlangre_eth_vlan_res_mask  = get_fi_array_type_vector(0b01111, 0b00000, 0b11111)
    vxlangre_eth_vlan_lb_result = lb_vector_table_result_t(
        mask_profile = 6,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_ETH_VID,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=0,
        l2_selected_layer_offset=1)

    #IPv4 / L4
    lb_ipv4_l4_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_IPV4_L4)
    lb_ipv4_l4_res_mask  = get_fi_array_type_vector(0b11111)
    ipv4_l4_lb_result = lb_vector_table_result_t(
        mask_profile = 2,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_IPV4_L4,
        l4_offset_in_headers=1,
        l3_selected_layer_offset=0,
        l2_selected_layer_offset=0)

    #IPv6
    lb_ipv6_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_IPV6)
    lb_ipv6_res_mask  = get_fi_array_type_vector(0b11111)
    ipv6_lb_result = lb_vector_table_result_t(
        mask_profile = 3,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_IPV6_L4,
        l4_offset_in_headers=0,
        l3_selected_layer_offset=0,
        l2_selected_layer_offset=0)

    #IPv6 / L4
    lb_ipv6_l4_res_types = get_fi_array_type_vector(PROTOCOL_TYPE_IPV6_L4)
    lb_ipv6_l4_res_mask  = get_fi_array_type_vector(0b11111)
    ipv6_l4_lb_result = lb_vector_table_result_t(
        mask_profile = 4,
        soft_fields_configuration=0,
        sort_enable=0,
        vector_select=LB_VECTOR_TYPE_IPV6_L4,
        l4_offset_in_headers=1,
        l3_selected_layer_offset=0,
        l2_selected_layer_offset=0)

    table_data = [
        # =============  LB Vector tables ===============
        # forward header   , payload is: mask_profile[4b],field_configuration[24]
        # sort_enable[1b],vector_select[4b],header select[4b]
        {
            "key":  {"res_header_types": lb_x_ipv4_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_x_ipv4_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": x_ipv4_lb_result },
        },
        {
            "key":  {"res_header_types": lb_x_ipv4_l4_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_x_ipv4_l4_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": x_ipv4_l4_lb_result },
        },
        {
            "key":  {"res_header_types": lb_x_ipv6_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_x_ipv6_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": x_ipv6_lb_result },
        },
        {
            "key":  {"res_header_types": lb_x_ipv6_l4_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_x_ipv6_l4_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": x_ipv6_l4_lb_result },
        },
        {
            "key":  {"res_header_types": lb_mpls_eth_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": 0},
            "mask": {"res_header_types": lb_mpls_eth_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": mpls_eth_lb_result },
        },
        {
            "key":  {"res_header_types": lb_mpls_eth_vlan_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": 0},
            "mask": {"res_header_types": lb_mpls_eth_vlan_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": mpls_eth_vlan_lb_result },
        },
        {
            "key":  {"res_header_types": lb_mpls_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": 0},
            "mask": {"res_header_types": lb_mpls_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": mpls_lb_result },
        },
        #        {
        #            "key":  {"res_header_types": lb_mpls_el_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": 1},
        #            "mask": {"res_header_types": lb_mpls_el_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
        #            "payload": {"lb_vector_table_result": mpls_el_lb_result },
        #        },
        {
            "key":  {"res_header_types": lb_eth_vlan_ipv4_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_eth_vlan_ipv4_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": eth_vlan_ipv4_lb_result },
        },
        {
            "key":  {"res_header_types": lb_eth_vlan_ipv4_l4_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_eth_vlan_ipv4_l4_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": eth_vlan_ipv4_l4_lb_result },
        },
        {
            "key":  {"res_header_types": lb_eth_vlan_ipv6_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_eth_vlan_ipv6_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": eth_vlan_ipv6_lb_result },
        },
        {
            "key":  {"res_header_types": lb_eth_vlan_ipv6_l4_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_eth_vlan_ipv6_l4_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": eth_vlan_ipv6_l4_lb_result },
        },
        {
            "key":  {"res_header_types": lb_eth_w_vlan_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_eth_w_vlan_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": eth_w_vlan_lb_result },
        },

        {
            "key":  {"res_header_types": lb_eth_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_eth_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": eth_lb_result },
        },

        {
            "key":  {"res_header_types": lb_ipv4_gre_ipv4_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_ipv4_gre_ipv4_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": ipv4_gre_ipv4_lb_result },
        },

        {
            "key":  {"res_header_types": lb_ipv4_gre_ipv4l4_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_ipv4_gre_ipv4l4_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": ipv4_gre_ipv4l4_lb_result },
        },

        {
            "key":  {"res_header_types": lb_ipv4_gre_mpls_ipv4_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_ipv4_gre_mpls_ipv4_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": ipv4_gre_mpls_ipv4_lb_result },
        },

        {
            "key":  {"res_header_types": lb_ipv4_gre_mpls_ipv4l4_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_ipv4_gre_mpls_ipv4l4_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": ipv4_gre_mpls_ipv4l4_lb_result },
        },

        {
            "key":  {"res_header_types": lb_ipv4_gre_ipv6_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_ipv4_gre_ipv6_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": ipv4_gre_ipv6_lb_result },
        },

        {
            "key":  {"res_header_types": lb_ipv4_gre_ipv6l4_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_ipv4_gre_ipv6l4_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": ipv4_gre_ipv6l4_lb_result },
        },

        {
            "key":  {"res_header_types": lb_ipv4_gre_mpls_ipv6_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_ipv4_gre_mpls_ipv6_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": ipv4_gre_mpls_ipv6_lb_result },
        },

        {
            "key":  {"res_header_types": lb_ipv4_gre_mpls_ipv6l4_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_ipv4_gre_mpls_ipv6l4_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": ipv4_gre_mpls_ipv6l4_lb_result },
        },
        {
            "key":  {"res_header_types": lb_vxlangre_ipv4_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_vxlangre_ipv4_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": vxlan_ipv4_lb_result },
        },
        {
            "key":  {"res_header_types": lb_vxlangre_ipv4l4_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_vxlangre_ipv4l4_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": vxlan_ipv4l4_lb_result },
        },
        {
            "key":  {"res_header_types": lb_vxlangre_ipv6_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_vxlangre_ipv6_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": vxlan_ipv6_lb_result },
        },
        {
            "key":  {"res_header_types": lb_vxlangre_ipv6l4_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_vxlangre_ipv6l4_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": vxlan_ipv6l4_lb_result },
        },
        {
            "key":  {"res_header_types": lb_vxlangre_vlan_ipv4_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_vxlangre_vlan_ipv4_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": vxlan_vlan_ipv4_lb_result },
        },
        {
            "key":  {"res_header_types": lb_vxlangre_vlan_ipv4l4_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_vxlangre_vlan_ipv4l4_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": vxlan_vlan_ipv4l4_lb_result },
        },
        {
            "key":  {"res_header_types": lb_vxlangre_vlan_ipv6_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_vxlangre_vlan_ipv6_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": vxlan_vlan_ipv6_lb_result },
        },
        {
            "key":  {"res_header_types": lb_vxlangre_vlan_ipv6l4_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_vxlangre_vlan_ipv6l4_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": vxlan_vlan_ipv6l4_lb_result },
        },
        {
            "key":  {"res_header_types": lb_vxlangre_eth_vlan_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_vxlangre_eth_vlan_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": vxlangre_eth_vlan_lb_result },
        },
        {
            "key":  {"res_header_types": lb_vxlangre_eth_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_vxlangre_eth_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": vxlangre_eth_lb_result },
        },
        {
            "key":  {"res_header_types": lb_ipv4_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_ipv4_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": ipv4_lb_result },
        },
        {
            "key":  {"res_header_types": lb_ipv4_l4_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_ipv4_l4_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": ipv4_l4_lb_result },
        },

        {
            "key":  {"res_header_types": lb_ipv6_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_ipv6_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": ipv6_lb_result },
        },
        {
            "key":  {"res_header_types": lb_ipv6_l4_res_types, "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":0, "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "mask": {"res_header_types": lb_ipv6_l4_res_mask , "fi_header_data":DONT_CARE_LB_VECTOR_TABLE , "lb_profile":DONT_CARE_LB_VECTOR_TABLE , "eli_exist": DONT_CARE_LB_VECTOR_TABLE},
            "payload": {"lb_vector_table_result": ipv6_l4_lb_result },
        },
    ]

    location = 0
    for line in table_data:
        table_key = res_lb_vector_table_key_t(res_header_types=line["key"]["res_header_types"],
                                              fi_header_data=line["key"]["fi_header_data"],
                                              lb_profile=line["key"]["lb_profile"],
                                              eli_exist=line["key"]["eli_exist"])
        table_mask = res_lb_vector_table_key_t(res_header_types=line["mask"]["res_header_types"],
                                               fi_header_data=line["mask"]["fi_header_data"],
                                               lb_profile=line["mask"]["lb_profile"],
                                               eli_exist=line["mask"]["eli_exist"])
        key  = lb_vector_table_key_t(res_lb_vector_table_key=table_key)
        mask = lb_vector_table_key_t(res_lb_vector_table_key=table_mask)
        value = lb_vector_table_value_t(lb_vector_table_result=line["payload"]["lb_vector_table_result"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1
