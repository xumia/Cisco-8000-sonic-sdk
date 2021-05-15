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

# Static initialization for hardware tables defined in hardware.npl

# Since we manually indented tables in this file, we don't want pep8 to mess with spaces
# This directive is read by leaba_format.py script
# pep8_extra_args "--ignore=E2,E5,W2"

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
    config_txpp_dlp_profile_key_construct_parameters_table()
    config_ts_cmd_hw_static_table()
    config_txpp_initial_npe_macro_table()
    config_term_to_fwd_hdr_shift_table()
    # TODO: Need to be returned once the hw modeling of field_a and field_b is done
    # config_txpp_macro_id_tcam_key_construction()
    config_txpp_cud_mapping_encap_data_source_select()
    config_txpp_eve_drop_interrupt_drop_mapping()
    # TODO: Need to fix the hw mapping in external json (SDK) for this table
    config_txpp_eve_drop_vlan_eth_type_reg()
    config_ip_mc_mpls_next_macro_static_table()


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
            key = txpp_dlp_profile_key_construct_parameters_table_key_t(packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_=encap_data,
                                                                        packet_protocol_layer_0__tx_npu_header_fwd_header_type=fwd_header_type)
            table.insert(NETWORK_CONTEXT, key, value)


"""
# TODO: should be moved out of this file to somewhere in the SDK
def config_cud_is_multicast_bitmap():
    table = cud_is_multicast_bitmap
    # according to CUD mapping section from ARCH spec
    prefix_table = [
        # 0/1
        {"prefix": TX_CUD_IBM_CMD_MC_COPY_ID_PREFIX, "prefix_len": TX_CUD_MC_COPY_ID_PREFIX_LEN,    "is_mc": True},
        # 100/3
        {"prefix": TX_CUD_IBM_CMD_MC_ID_PREFIX,      "prefix_len": TX_CUD_IBM_CMD_MC_ID_PREFIX_LEN, "is_mc": False},
        # 1010/4
        {"prefix": TX_CUD_MC_COPY_ID_PREFIX,         "prefix_len": TX_CUD_MC_COPY_ID_PREFIX_LEN,    "is_mc": True},
        # 1011/4
        {"prefix": TX_CUD_MC_ID_PREFIX,              "prefix_len": TX_CUD_MC_ID_PREFIX_LEN,         "is_mc": False},
        # 1100/4
        {"prefix": TX_CUD_DSP_PREFIX,                "prefix_len": TX_CUD_DSP_PREFIX_LEN,           "is_mc": False},
        # 1101/4
        {"prefix": TX_CUD_IBM_CMD_PREFIX,            "prefix_len": TX_CUD_IBM_CMD_PREFIX_LEN,       "is_mc": False},
        # 111/3
        {"prefix": TX_CUD_DROP_TRAP_PREFIX,           "prefix_len": TX_CUD_DROP_TRAP_PREFIX_LEN,       "is_mc": False},
    ]

    MAX_PREFIX_LEN = 4
    # prefix represents a left-aligned prefix, of which has prefix_len correct MSBs, and zero in LSBs.
    # suffix iterates over all free LSBs.
    for line in prefix_table:
        num_of_free_bits = MAX_PREFIX_LEN - line["prefix_len"]
        prefix = line["prefix"]
        for suffix in range(0, 1 << num_of_free_bits):
            value = cud_is_multicast_bitmap_value_t(line["is_mc"])
            key = cud_is_multicast_bitmap_key_t(prefix + suffix)
            table.insert(NETWORK_CONTEXT, key, value)
"""


# value_func for ts_cmd_hw_static_table
def ts_cmd_hw_static_table_value_func(value_args):
    update_cs = 1 if value_args["update_cs"] else 0
    reset_cs = 1 if value_args["reset_cs"] else 0
    ts_cmd_trans = ts_cmd_trans_t(
        op=value_args["txpp_op"],
        update_udp_cs=update_cs,
        reset_udp_cs=reset_cs,
        ifg_ts_cmd=value_args["ifg_cmd"])
    value = ts_cmd_hw_static_table_value_t(ts_cmd_trans)
    return value


def config_ts_cmd_hw_static_table():
    table = ts_cmd_hw_static_table
    table_config = DirectTableConfig("ts_cmd_hw_static_table")
    table_data = [
        {"key": ""                             , "value": [     "txpp_op"           , "udp_offset_sel", "update_cs", "reset_cs",      "ifg_cmd"          ]},
        {"key": TS_CMD_OP_NOP                  , "value": [TXPP_TS_CMD_OP_NOP       ,    False        ,    False   ,    False  , IFG_TS_CMD_OP_NOP       ]},
        {"key": TS_CMD_UPDATE_CF               , "value": [TXPP_TS_CMD_OP_UPDATE_CF ,    False        ,    False   ,    False  , IFG_TS_CMD_OP_UPDATE_CF ]},
        {"key": TS_CMD_UPDATE_CF_UPDATE_CS     , "value": [TXPP_TS_CMD_OP_UPDATE_CF ,    False        ,    True    ,    False  , IFG_TS_CMD_OP_UPDATE_CF ]},
        {"key": TS_CMD_UPDATE_CF_RESET_CS      , "value": [TXPP_TS_CMD_OP_UPDATE_CF ,    False        ,    False   ,    True   , IFG_TS_CMD_OP_UPDATE_CF ]},
        {"key": TS_CMD_STAMP_DEV_TIME          , "value": [TXPP_TS_CMD_OP_TOD_STAMP ,    True         ,    False   ,    False  , IFG_TS_CMD_OP_TOD_UPDATE]},
        {"key": TS_CMD_STAMP_DEV_TIME_UPDATE_CS, "value": [TXPP_TS_CMD_OP_TOD_STAMP ,    True         ,    True    ,    False  , IFG_TS_CMD_OP_TOD_UPDATE]},
        {"key": TS_CMD_STAMP_DEV_TIME_RESET_CS , "value": [TXPP_TS_CMD_OP_TOD_STAMP ,    True         ,    False   ,    True   , IFG_TS_CMD_OP_TOD_UPDATE]},
        {"key": TS_CMD_RECORD                  , "value": [TXPP_TS_CMD_OP_TOD_RECORD,    False        ,    False   ,    False  , IFG_TS_CMD_OP_TOD_RECORD]},
        {"key": TS_CMD_RECORD_UPDATE_CS        , "value": [TXPP_TS_CMD_OP_TOD_RECORD,    False        ,    True    ,    False  , IFG_TS_CMD_OP_TOD_RECORD]},
        # {"key": TS_CMD_RECORD_RESET_CS         , "value": [TXPP_TS_CMD_OP_TOD_RECORD,  False   ,    True   , IFG_TS_CMD_OP_TOD_RECORD]},
        # TXPP command should have been TXPP_TS_CMD_OP_IN_TIME_STAMP. Due to HW errata, we stamp TXPP time, and send it to CPU together with RXPP ns time.
        # IFG command must be NOP, since this is used to stamp NPU header, and value is copied to punt header in ENE, so offset is not relevant in IFG anymore
        # in GB, if errata is fixed, can put correct TXPP command, and change NPL logic
        {"key": TS_CMD_STAMP_IN_SYS_TIME       , "value": [TXPP_TS_CMD_OP_TOD_STAMP,     False        ,    False    ,    False  , IFG_TS_CMD_OP_NOP      ]},
    ]

    table_config.create_table(table_data, NETWORK_CONTEXT, value_func=ts_cmd_hw_static_table_value_func, init_table=True)


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
        {"key": ["is_mc"  ,                        "fwd_type"                     ,             "encap_type"             ], "value": ["first_macro"]},
        # =============  FWD_HEADER_TYPE_SVL  ===============
        {"key": [DONT_CARE, FWD_HEADER_TYPE_SVL, DONT_CARE], "value": [NETWORK_TX_SVL_MACRO]},
        # =============  Collapsed MC ===============
        {"key": [DONT_CARE, Key(HEADER_TYPE_IPV4_HEADERS_PREFIX << 1, mask=0b1110), NPU_ENCAP_L3_HEADER_TYPE_COLLAPSED_MC], "value": [NETWORK_TX_IP_TO_NH_MC_MACRO]},
        {"key": [DONT_CARE, Key(HEADER_TYPE_IPV6_HEADERS_PREFIX << 1, mask=0b1110), NPU_ENCAP_L3_HEADER_TYPE_COLLAPSED_MC], "value": [NETWORK_TX_IP_TO_NH_MC_MACRO]},
        # ================= Inject up/down ===============
        {"key": [DONT_CARE, FWD_HEADER_TYPE_INJECT_DOWN                           , DONT_CARE                            ], "value": [TX_INJECT_MACRO]},
        # =====================  FWD_HEADER_TYPE_ETHERNET  =================
        {"key": [DONT_CARE, DONT_CARE                                         , NPU_ENCAP_L2_HEADER_TYPE_AC          ], "value": [NETWORK_TX_MAC_AC_AND_ACL_MACRO]},
        # {"key": [DONT_CARE, FWD_HEADER_TYPE_ETHERNET                              , NPU_ENCAP_L2_HEADER_TYPE_PWE       ], "value": [NETWORK_TX_MAC_TO_PWE_MACRO]},
        # {"key": [DONT_CARE, FWD_HEADER_TYPE_ETHERNET                        , NPU_ENCAP_L2_HEADER_TYPE_PWE_WITH_TUNNEL_ID], "value": [NETWORK_TX_MAC_TO_PWE_MACRO]},
        {"key": [DONT_CARE, DONT_CARE                                         , NPU_ENCAP_L2_HEADER_TYPE_VXLAN       ], "value": [NETWORK_TX_GRE_VXLAN_MACRO]},
        # =====================  FWD_HEADER_TYPE_IPV4/6  =================
        {"key": [1        , Key(HEADER_TYPE_IPV4_HEADERS_PREFIX << 1, mask=0b1110), NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH ], "value": [NETWORK_TX_IP_TO_NH_MC_MACRO]},
        {"key": [1        , Key(HEADER_TYPE_IPV6_HEADERS_PREFIX << 1, mask=0b1110), NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH ], "value": [NETWORK_TX_IP_TO_NH_MC_MACRO]},
        {"key": [0        , FWD_HEADER_TYPE_IPV4                                  , NPU_ENCAP_L3_HEADER_TYPE_HOST_MAC    ], "value": [NETWORK_TX_IP_UC_FIRST_MACRO]},
        {"key": [0        , FWD_HEADER_TYPE_IPV6                                  , NPU_ENCAP_L3_HEADER_TYPE_HOST_MAC    ], "value": [NETWORK_TX_IP_UC_FIRST_MACRO]},
        {"key": [0        , FWD_HEADER_TYPE_IPV4                                  , NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH ], "value": [NETWORK_TX_IP_UC_FIRST_MACRO]},
        {"key": [DONT_CARE, FWD_HEADER_TYPE_IPV4                                  , NPU_ENCAP_L3_HEADER_TYPE_GRE         ], "value": [NETWORK_TX_GRE_VXLAN_MACRO]},
        {"key": [DONT_CARE, FWD_HEADER_TYPE_IPV6                                  , NPU_ENCAP_L3_HEADER_TYPE_GRE         ], "value": [NETWORK_TX_GRE_VXLAN_MACRO]},
        {"key": [0        , FWD_HEADER_TYPE_MPLS_BOS_IPV4                         , NPU_ENCAP_L3_HEADER_TYPE_GRE         ], "value": [NETWORK_TX_GRE_VXLAN_MACRO]},
        {"key": [0        , FWD_HEADER_TYPE_MPLS_BOS_IPV6                         , NPU_ENCAP_L3_HEADER_TYPE_GRE         ], "value": [NETWORK_TX_GRE_VXLAN_MACRO]},
        # entry for dummy Bud Node member handling
        {"key": [1        , FWD_HEADER_TYPE_MPLS_BOS_IPV4                         , NPU_ENCAP_L3_HEADER_TYPE_HOST_MAC    ], "value": [NETWORK_TX_IP_TO_NH_MC_MACRO]},
        {"key": [1        , FWD_HEADER_TYPE_MPLS_BOS_IPV6                         , NPU_ENCAP_L3_HEADER_TYPE_HOST_MAC    ], "value": [NETWORK_TX_IP_TO_NH_MC_MACRO]},
        {"key": [0        , FWD_HEADER_TYPE_IPV6                                  , NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH ], "value": [NETWORK_TX_IP_UC_FIRST_MACRO]},
        # ================== MPLS_ ================
        {"key": [DONT_CARE, Key(HEADER_TYPE_MPLS_HEADERS_PREFIX << 2, mask=0b1100), Key(0b0000, mask=0b1000)             ], "value": [NETWORK_TX_MPLS_L3_MACRO]},
        # ====================== MPLS + IPv6 + IPv4 path sharing encap types. Don'
        {"key": [DONT_CARE, DONT_CARE                                             , NPU_ENCAP_L3_HEADER_TYPE_LDP_OVER_TE ], "value": [NETWORK_TX_MPLS_L3_MACRO]},
        {"key": [DONT_CARE, DONT_CARE                                             , NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE     ], "value": [NETWORK_TX_MPLS_L3_MACRO]},
        {"key": [DONT_CARE, DONT_CARE                                             , NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE_SR  ], "value": [NETWORK_TX_MPLS_L3_MACRO]},
        {"key": [DONT_CARE, DONT_CARE                                     , NPU_ENCAP_L3_HEADER_TYPE_TE_HE_WITH_TUNNEL_ID], "value": [NETWORK_TX_MPLS_L3_MACRO]},
        # ================== In bound mirror/redirect, and default entry ======================
        {"key": [DONT_CARE, DONT_CARE                                             , NPU_ENCAP_MIRROR_OR_REDIRECT         ], "value": [TX_PUNT_MACRO]},
        # =====================  MC HOST   =================
        {"key": [1        , Key(HEADER_TYPE_IPV4_HEADERS_PREFIX << 1, mask=0b1110), NPU_ENCAP_L3_HEADER_TYPE_PWE_OR_MC_ACCOUNTING ], "value": [NETWORK_TX_IP_TO_NH_MC_ACCOUNTING_MACRO]},
        {"key": [1        , Key(HEADER_TYPE_IPV6_HEADERS_PREFIX << 1, mask=0b1110), NPU_ENCAP_L3_HEADER_TYPE_PWE_OR_MC_ACCOUNTING ], "value": [NETWORK_TX_IP_TO_NH_MC_ACCOUNTING_MACRO]},
        # =============  ENCAP_TYPE_SVL  ===============
        {"key": [DONT_CARE, DONT_CARE                                             , NPU_ENCAP_L2_HEADER_TYPE_SVL], "value": [NETWORK_TX_SVL_MACRO]},
        # Default entry
        {"key": [DONT_CARE, DONT_CARE                                             , DONT_CARE                            ], "value": [NETWORK_TRANSMIT_ERROR_MACRO]},
    ]

    table_config.create_table(table_data, NETWORK_CONTEXT, key_func=txpp_initial_npe_macro_table_key_func, args_map={"first_macro": "np_macro_id"})


def config_term_to_fwd_hdr_shift_table():
    table = term_to_fwd_hdr_shift_table
    table_config = DirectTableConfig("term_to_fwd_hdr_shift_table")
    # header_shift_disable_offset_recalc: matches pd.npu_header.fwd_qos_tag[4] -> (bit 264 - offset 64) / 8 = 25
    # highest_header_to_update: the number of headers to update the offset to, regardless of the NPL 'recalculate' indication
    table_data = [ {"key": ""    , "value": [ "highest_header_to_update", "header_shift_disable_offset_recalc", "enable_header_shift"]},
                   {"key":  0    , "value": [              0            ,                  0                  ,       0              ]}
                   ]
    table_config.create_table(table_data, [NETWORK_CONTEXT, UDC_CONTEXT])


def config_txpp_macro_id_tcam_key_construction():
    table_a = fwd_and_encap_types_to_field_a_offset_table
    table_b = fwd_and_encap_types_to_field_b_offset_table
    table_a_config = DirectTableConfig("fwd_and_encap_types_to_field_a_offset_table")
    table_b_config = DirectTableConfig("fwd_and_encap_types_to_field_b_offset_table")
    table_size = table_a_config.get_table_size() # table_a_size == table_b_size
    table_a_data = [{"key": ["fwd_type", "encap_type"]    , "value": ["field_a_offset"]}]
    table_b_data = [{"key": ["fwd_type", "encap_type"]    , "value": ["field_b_offset"]}]
    for line in range(0, table_size):
        encap_type = line & 0b1111
        fwd_type = (line >> 4) & 0b1111
        if encap_type == NPU_ENCAP_L3_HEADER_TYPE_HOST_MAC:
            field_a_offset = int((NPU_HEADER_OFFSET_IN_BITS_TO_ENCAP_DATA + ENCAP_HEADER_OFFSET_IN_BITS_TO_IP_ENCAP_ENC_TYPE_2_HOST) / 4)
        elif encap_type == NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH:
            field_a_offset = int((NPU_HEADER_OFFSET_IN_BITS_TO_ENCAP_DATA + ENCAP_HEADER_OFFSET_IN_BITS_TO_IP_ENCAP_ENC_TYPE_2_NH) / 4)
        else:
            field_a_offset = 0
        # field_b_offset is zeros currently
        field_b_offset = 0

        table_a_data.append({"key": [fwd_type, encap_type], "value": [field_a_offset]})
        table_b_data.append({"key": [fwd_type, encap_type], "value": [field_b_offset]})

    args_map = {"encap_type": "txpp_first_macro_table_key_encap_type", "fwd_type": "txpp_first_macro_table_key_fwd_type",
                "field_a_offset": "txpp_first_macro_local_vars_field_a_offset_in_nibble", "field_b_offset": "txpp_first_macro_local_vars_field_b_offset_in_nibble"}

    table_a_config.create_table(table_a_data, [NETWORK_CONTEXT, UDC_CONTEXT], args_map=args_map)
    table_b_config.create_table(table_b_data, [NETWORK_CONTEXT, UDC_CONTEXT], args_map=args_map)


def config_txpp_cud_mapping_encap_data_source_select():
    table = encap_data_source_select_table
    table_config = DirectTableConfig("encap_data_source_select_table")
    # TODO: Currently assuming here not using encap data of 120 bits! for this feature will need additional changes (NPL, regs
    # write..)
    encap_data_is_120b = 0
    table_size = table_config.get_table_size()
    table_data = [{"key": ["use_narrow_cud", "use_mapped_cud"] , "value": ["encap_data_shift", "encap_data_size", "mapped_cud_shift", "mapped_cud_size", "expanded_cud_shift", "expanded_cud_size"]}]

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
        mapped_cud_size = int((60 / 4 if encap_data_is_120b else 40 / 4) if (use_mapped_cud & use_narrow_cud) else (120 / 4 if encap_data_is_120b else 80 / 4) if use_mapped_cud else 0)

        table_data.append({"key": [use_narrow_cud, use_mapped_cud], "value": [encap_data_shift, encap_data_size, mapped_cud_shift, mapped_cud_size, expanded_cud_shift, expanded_cud_size]})

    args_map = {"use_mapped_cud": "cud_mapping_local_vars_map_cud", "use_narrow_cud": "cud_mapping_local_vars_mapped_cud_is_narrow",
                "encap_data_shift":"orig_encap_data_shift_in_nibble", "encap_data_size":"orig_encap_data_size_in_nibble",
                "mapped_cud_shift":"mapped_cud_shift_in_nibble", "mapped_cud_size":"mapped_cud_size_in_nibble",
                "expanded_cud_shift":"expanded_cud_shift_in_nibble", "expanded_cud_size":"expanded_cud_size_in_nibble"}
    table_config.create_table(table_data, [NETWORK_CONTEXT, UDC_CONTEXT], args_map=args_map)


# Copied from AV
class VeCmd(IntEnum):
    VE_CMD_NOP = 0
    VE_CMD_REMARK = 1 # only pcp-dei update (same for both)
    VE_CMD_POP1 = 2
    VE_CMD_POP2 = 5
    VE_CMD_PUSH1 = 4
    VE_CMD_PUSH2 = 11
    VE_CMD_TRANSLATE_1_1 = 3
    VE_CMD_TRANSLATE_2_1 = 6
    VE_CMD_TRANSLATE_1_2 = 10
    VE_CMD_TRANSLATE_2_2 = 9


def config_txpp_eve_drop_interrupt_drop_mapping():
    table_drop_map = eve_drop_mapping_hw_table
    table_interrupt_map = eve_interrupt_mapping_hw_table
    table_drop_map_config = DirectTableConfig("eve_drop_mapping_hw_table")
    table_interrupt_map_config = DirectTableConfig("eve_interrupt_mapping_hw_table")
    table_size = table_drop_map_config.get_table_size() # table_drop_map size == table_interrupt_map size
    table_drop_map_data      = [{"key": ["ve_cmd", "vlan1_exist", "vlan2_exist"] , "value": ["drop"]}]
    table_interrupt_map_data = [{"key": ["ve_cmd", "vlan1_exist", "vlan2_exist"] , "value": ["interrupt"]}]
    for line in range(0, table_size):
        vlan2_exist = line & 0b1
        vlan1_exist = (line >> 1) & 0b1
        ve_cmd      = (line >> 2) & 0b1111
        drop = 0
        interrupt = 0
        # No drop
        if ve_cmd == VeCmd.VE_CMD_NOP or ve_cmd == VeCmd.VE_CMD_PUSH1 or ve_cmd == VeCmd.VE_CMD_PUSH2:
            drop = 0
            interrupt = 0

        #Drop if vlan1 does not exist
        if ve_cmd == VeCmd.VE_CMD_POP1 or ve_cmd == VeCmd.VE_CMD_REMARK or ve_cmd == VeCmd.VE_CMD_TRANSLATE_1_1 or ve_cmd == VeCmd.VE_CMD_TRANSLATE_1_2:
            drop = not vlan1_exist
            interrupt = not vlan1_exist

        # Drop if not both vlans exist
        if ve_cmd == VeCmd.VE_CMD_POP2 or ve_cmd == VeCmd.VE_CMD_TRANSLATE_2_1 or ve_cmd == VeCmd.VE_CMD_TRANSLATE_2_2:
            drop = not(vlan1_exist and vlan2_exist)
            interrupt = not(vlan1_exist and vlan2_exist)

        table_drop_map_data.append({"key": [ve_cmd, vlan1_exist, vlan2_exist], "value": [drop]})
        table_interrupt_map_data.append({"key": [ve_cmd, vlan1_exist, vlan2_exist], "value": [interrupt]})

    args_map = {"ve_cmd":"eve_drop_opcode", "vlan1_exist":"eve_drop_vlan_id_1_tpid_exists", "vlan2_exist":"eve_drop_vlan_id_2_tpid_exists",
                "drop":"eve_drop_drop", "interrupt":"eve_drop_interrupt"}
    table_drop_map_config.create_table(table_drop_map_data, [NETWORK_CONTEXT, UDC_CONTEXT], args_map=args_map)
    table_interrupt_map_config.create_table(table_interrupt_map_data, [NETWORK_CONTEXT, UDC_CONTEXT], args_map=args_map)


"""
Below code takes care of programming the eve_drop_vlan_id_hw_table only in NSIM.
For HW, EveDropVlanEthTypeRegs are directly programmed from SDK.
"""


def config_txpp_eve_drop_vlan_eth_type_reg():
    table = eve_drop_vlan_id_hw_table
    table_config = DirectTableConfig("eve_drop_vlan_id_hw_table")
    table_data = [{"key": ["eve_drop_vlan_id_hw_table"] , "value": ["eve_drop_vlan_id_tpid_exists"]},
                  {"key":            0x8100             , "value":               1                 },
                  {"key":            0x9100             , "value":               1                 },
                  {"key":            0x88a8             , "value":               1                 },
                  ]
    table_config.create_table(table_data, [NETWORK_CONTEXT, UDC_CONTEXT])


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
        key = ip_mc_mpls_next_macro_static_table_key_t(type=line["key"]["type"], ipv4_msb=line["key"]["ipv4_msb"], ipv6_msb=line["key"]["ipv6_msb"])
        mask = ip_mc_mpls_next_macro_static_table_key_t(type=line["mask"]["type"], ipv4_msb=line["mask"]["ipv4_msb"], ipv6_msb=line["mask"]["ipv6_msb"])
        value = ip_mc_mpls_next_macro_static_table_value_t(macro_id=line["payload"]["next_macro"], pl_inc=line["payload"]["inc"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1
