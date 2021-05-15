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
# pep8_extra_args = "--ignore=E2"

from config_tables_utils import *

DONT_CARE = 0
ALL_1 = (1 << 128) - 1
FWD_HEADER_TYPE_NUM_BITS = 4


def config_tables():
    config_ts_cmd_hw_static_table()
    config_txpp_initial_npe_macro_table()
    config_txpp_fwd_header_type_is_l2_table()
    config_map_tm_dp_ecn_to_wa_ecn_dp_static_table()


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
        {"prefix": TX_CUD_RESERVED_PREFIX,           "prefix_len": TX_CUD_RESERVED_PREFIX_LEN,       "is_mc": False},
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


def config_ts_cmd_hw_static_table():
    table = ts_cmd_hw_static_table
    table_data = [
        #=========================================================================
        #       Key                            |                                                      Payload                                                    |
        #=========================================================================================================================================================
        {"key": TS_CMD_OP_NOP,                   "txpp_op": TXPP_TS_CMD_OP_NOP,        "update_cs": False, "reset_cs": False, "ifg_cmd": IFG_TS_CMD_OP_NOP},
        {"key": TS_CMD_UPDATE_CF,                "txpp_op": TXPP_TS_CMD_OP_UPDATE_CF,  "update_cs": False, "reset_cs": False, "ifg_cmd": IFG_TS_CMD_OP_UPDATE_CF},
        {"key": TS_CMD_UPDATE_CF_UPDATE_CS,      "txpp_op": TXPP_TS_CMD_OP_UPDATE_CF,  "update_cs": True,  "reset_cs": False, "ifg_cmd": IFG_TS_CMD_OP_UPDATE_CF},
        {"key": TS_CMD_UPDATE_CF_RESET_CS,       "txpp_op": TXPP_TS_CMD_OP_UPDATE_CF,  "update_cs": False, "reset_cs": True,  "ifg_cmd": IFG_TS_CMD_OP_UPDATE_CF},
        {"key": TS_CMD_STAMP_DEV_TIME,           "txpp_op": TXPP_TS_CMD_OP_TOD_STAMP,  "update_cs": False, "reset_cs": False, "ifg_cmd": IFG_TS_CMD_OP_TOD_UPDATE},
        {"key": TS_CMD_STAMP_DEV_TIME_UPDATE_CS, "txpp_op": TXPP_TS_CMD_OP_TOD_STAMP,  "update_cs": True,  "reset_cs": False, "ifg_cmd": IFG_TS_CMD_OP_TOD_UPDATE},
        {"key": TS_CMD_STAMP_DEV_TIME_RESET_CS,  "txpp_op": TXPP_TS_CMD_OP_TOD_STAMP,  "update_cs": False, "reset_cs": True,  "ifg_cmd": IFG_TS_CMD_OP_TOD_UPDATE},
        {"key": TS_CMD_RECORD,                   "txpp_op": TXPP_TS_CMD_OP_TOD_RECORD, "update_cs": False, "reset_cs": False, "ifg_cmd": IFG_TS_CMD_OP_TOD_RECORD},
        {"key": TS_CMD_RECORD_UPDATE_CS,         "txpp_op": TXPP_TS_CMD_OP_TOD_RECORD, "update_cs": True,  "reset_cs": False, "ifg_cmd": IFG_TS_CMD_OP_TOD_RECORD},
        {"key": TS_CMD_RECORD_RESET_CS,          "txpp_op": TXPP_TS_CMD_OP_TOD_RECORD, "update_cs": False, "reset_cs": True,  "ifg_cmd": IFG_TS_CMD_OP_TOD_RECORD},
        # TXPP command should have been TXPP_TS_CMD_OP_IN_TIME_STAMP. Due to HW errata, we stamp TXPP time, and send it to CPU together with RXPP ns time.
        # IFG command must be NOP, since this is used to stamp NPU header, and value is copied to punt header in ENE, so offset is not relevant in IFG anymore
        # in GB, if errata is fixed, can put correct TXPP command, and change NPL logic
        {"key": TS_CMD_STAMP_IN_SYS_TIME,  "txpp_op": TXPP_TS_CMD_OP_TOD_STAMP, "update_cs": False, "reset_cs": False, "ifg_cmd": IFG_TS_CMD_OP_NOP},
    ]

    # this is 16 entries direct table. First 0 everything, then configure according to description above.
    for line_num in range (0,16):
        key = ts_cmd_hw_static_table_key_t(line_num)
        ts_cmd_trans = ts_cmd_trans_t(op=TXPP_TS_CMD_OP_NOP, update_udp_cs=0, reset_udp_cs=0, ifg_ts_cmd=TS_CMD_OP_NOP)
        value = ts_cmd_hw_static_table_value_t(ts_cmd_trans)
        table.insert(NETWORK_CONTEXT, key, value)

    for line in table_data:
        key = ts_cmd_hw_static_table_key_t(line["key"])
        update_cs = 1 if line["update_cs"] else 0
        reset_cs = 1 if line["reset_cs"] else 0
        ts_cmd_trans = ts_cmd_trans_t(
            op=line["txpp_op"],
            update_udp_cs=update_cs,
            reset_udp_cs=reset_cs,
            ifg_ts_cmd=line["ifg_cmd"])
        value = ts_cmd_hw_static_table_value_t(ts_cmd_trans)
        table.insert(NETWORK_CONTEXT, key, value)


def config_txpp_initial_npe_macro_table():
    table = txpp_initial_npe_macro_table
    table_data = [
        # =============  Collapsed MC ===============
        # forward header type FWD_HEADER_TYPE_IPV4_COLLAPSED_MC and FWD_HEADER_TYPE_IPV4
        {
            "key":  {"is_mc": DONT_CARE, "fwd_type": HEADER_TYPE_IPV4_HEADERS_PREFIX << 1, "first_encap_type": NPU_ENCAP_L3_HEADER_TYPE_COLLAPSED_MC, "second_encap_type": DONT_CARE},
            "mask": {"is_mc": DONT_CARE, "fwd_type": 0b1110,                          "first_encap_type": ALL_1,                                 "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_IP_TO_NH_MC_MACRO},
        },
        # forward header type FWD_HEADER_TYPE_IPV6_COLLAPSED_MC and FWD_HEADER_TYPE_IPV6
        {
            "key":  {"is_mc": DONT_CARE, "fwd_type": HEADER_TYPE_IPV6_HEADERS_PREFIX << 1, "first_encap_type": NPU_ENCAP_L3_HEADER_TYPE_COLLAPSED_MC, "second_encap_type": DONT_CARE},
            "mask": {"is_mc": DONT_CARE, "fwd_type": 0b1110,                          "first_encap_type": ALL_1,                                 "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_IP_TO_NH_MC_MACRO},
        },

        # ================= Inject up/down ===============
        # Inject down
        {
            "key": {"is_mc": DONT_CARE, "fwd_type": FWD_HEADER_TYPE_INJECT_DOWN, "first_encap_type": DONT_CARE, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": DONT_CARE, "fwd_type": ALL_1,                       "first_encap_type": DONT_CARE, "second_encap_type": DONT_CARE},
            "payload": {"first_macro": TX_INJECT_MACRO},
        },
        ## REMOVED - Not need any longer
        # # Inject up
        # {
        #    "key": {"is_mc": DONT_CARE, "fwd_type": FWD_HEADER_TYPE_INJECT_UP, "first_encap_type": DONT_CARE, "second_encap_type": DONT_CARE},
        #    "mask":{"is_mc": DONT_CARE, "fwd_type": ALL_1,                     "first_encap_type": DONT_CARE, "second_encap_type": DONT_CARE},
        #    "payload": {"first_macro": TX_INJECT_MACRO},
        #},

        # =====================  FWD_HEADER_TYPE_ETHERNET  =================
        # basic AC switching
        {
            "key": {"is_mc": DONT_CARE, "fwd_type": FWD_HEADER_TYPE_ETHERNET, "first_encap_type": NPU_ENCAP_L2_HEADER_TYPE_AC, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": DONT_CARE, "fwd_type": DONT_CARE,                "first_encap_type": ALL_1,                       "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_MAC_AC_AND_ACL_MACRO},
        },
        # l2 DLP is PWE
        # {
        #     "key": {"is_mc": DONT_CARE, "fwd_type": FWD_HEADER_TYPE_ETHERNET, "first_encap_type": NPU_ENCAP_L2_HEADER_TYPE_PWE, "second_encap_type": DONT_CARE},
        #     "mask":{"is_mc": DONT_CARE, "fwd_type": ALL_1,                    "first_encap_type": ALL_1,                        "second_encap_type": DONT_CARE},
        #     "payload": {"first_macro": NETWORK_TX_MAC_TO_PWE_MACRO},
        # },
        # {
        #     "key": {"is_mc": DONT_CARE, "fwd_type": FWD_HEADER_TYPE_ETHERNET, "first_encap_type": NPU_ENCAP_L2_HEADER_TYPE_PWE_WITH_TUNNEL_ID, "second_encap_type": DONT_CARE},
        #     "mask":{"is_mc": DONT_CARE, "fwd_type": ALL_1,                    "first_encap_type": ALL_1,                                       "second_encap_type": DONT_CARE},
        #     "payload": {"first_macro": NETWORK_TX_MAC_TO_PWE_MACRO},
        # },
        # l2 DLP is VXlan. Pacific does not support VXLAN MCAST
        {
            "key": {"is_mc": DONT_CARE, "fwd_type": FWD_HEADER_TYPE_ETHERNET, "first_encap_type": NPU_ENCAP_L2_HEADER_TYPE_VXLAN, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": DONT_CARE, "fwd_type": ALL_1,                    "first_encap_type": ALL_1,                          "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_GRE_VXLAN_MACRO},
        },
        #{
        #    "key": {"is_mc": DONT_CARE, "fwd_type": FWD_HEADER_TYPE_ETHERNET, "first_encap_type": NPU_ENCAP_L2_HEADER_TYPE_VXLAN_LBG_ID, "second_encap_type": DONT_CARE},
        #    "mask":{"is_mc": DONT_CARE, "fwd_type": ALL_1,                    "first_encap_type": ALL_1,                                 "second_encap_type": DONT_CARE},
        #    "payload": {"first_macro": NETWORK_TX_MAC_TO_VXLAN_MACRO},
        #},

        # =====================  FWD_HEADER_TYPE_IPV4/6  =================
        # IP multicast packets (not collapsed)
        {
            "key": {"is_mc": 1,     "fwd_type": HEADER_TYPE_IPV4_HEADERS_PREFIX << 1, "first_encap_type": NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": ALL_1, "fwd_type": 0b1110,                          "first_encap_type": ALL_1,                                "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_IP_TO_NH_MC_MACRO},
        },
        {
            "key": {"is_mc": 1,     "fwd_type": HEADER_TYPE_IPV6_HEADERS_PREFIX << 1, "first_encap_type": NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": ALL_1, "fwd_type": 0b1110,                          "first_encap_type": ALL_1,                                "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_IP_TO_NH_MC_MACRO},
        },
        # IPV4 routing to host, directly to DSP
        {
            "key": {"is_mc": 0,     "fwd_type": FWD_HEADER_TYPE_IPV4, "first_encap_type": NPU_ENCAP_L3_HEADER_TYPE_HOST_MAC, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": ALL_1, "fwd_type": ALL_1,                "first_encap_type": ALL_1,                             "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_IP_UC_FIRST_MACRO},
        },
        # IPV6 routing to host, directly to DSP
        {
            "key": {"is_mc": 0,     "fwd_type": FWD_HEADER_TYPE_IPV6, "first_encap_type": NPU_ENCAP_L3_HEADER_TYPE_HOST_MAC, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": ALL_1, "fwd_type": ALL_1,                "first_encap_type": ALL_1,                             "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_IP_UC_FIRST_MACRO},
        },
        # IPV4 VxLAN router NH
        {
            "key": {"is_mc": 0,     "fwd_type": FWD_HEADER_TYPE_IPV4, "first_encap_type": NPU_ENCAP_L2_HEADER_TYPE_VXLAN,    "second_encap_type": DONT_CARE},
            "mask":{"is_mc": ALL_1, "fwd_type": ALL_1,                "first_encap_type": ALL_1,                             "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_GRE_VXLAN_MACRO},
        },
        {
            "key": {"is_mc": 0,     "fwd_type": FWD_HEADER_TYPE_IPV6, "first_encap_type": NPU_ENCAP_L2_HEADER_TYPE_VXLAN,    "second_encap_type": DONT_CARE},
            "mask":{"is_mc": ALL_1, "fwd_type": ALL_1,                "first_encap_type": ALL_1,                             "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_GRE_VXLAN_MACRO},
        },
        # IPV4 NH router over Ethernet network
        {
            "key": {"is_mc": 0,     "fwd_type": FWD_HEADER_TYPE_IPV4, "first_encap_type": NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": ALL_1, "fwd_type": ALL_1,                "first_encap_type": ALL_1,                                "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_IP_UC_FIRST_MACRO},
        },
        # IPV4 GRE Tunnel for IPv4 Payload
        {
            "key": {"is_mc": 0,     "fwd_type": FWD_HEADER_TYPE_IPV4, "first_encap_type": NPU_ENCAP_L3_HEADER_TYPE_GRE, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": ALL_1, "fwd_type": ALL_1,                "first_encap_type": ALL_1,                        "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_GRE_VXLAN_MACRO},
        },
        # IPV4 GRE Tunnel for IPv6 Payload
        {
            "key": {"is_mc": 0,     "fwd_type": FWD_HEADER_TYPE_IPV6, "first_encap_type": NPU_ENCAP_L3_HEADER_TYPE_GRE, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": ALL_1, "fwd_type": ALL_1,                "first_encap_type": ALL_1,                        "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_GRE_VXLAN_MACRO},
        },
        # IPV4 GRE Tunnel, IPv4 payload for MPLS Decap
        {
            "key": {"is_mc": 0,     "fwd_type": FWD_HEADER_TYPE_MPLS_BOS_IPV4, "first_encap_type": NPU_ENCAP_L3_HEADER_TYPE_GRE, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": ALL_1, "fwd_type": ALL_1,                         "first_encap_type": ALL_1,                        "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_GRE_VXLAN_MACRO},
        },
        # IPV4 GRE Tunnel, IPv6 payload for MPLS Decap
        {
            "key": {"is_mc": 0,     "fwd_type": FWD_HEADER_TYPE_MPLS_BOS_IPV6, "first_encap_type": NPU_ENCAP_L3_HEADER_TYPE_GRE, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": ALL_1, "fwd_type": ALL_1,                         "first_encap_type": ALL_1,                        "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_GRE_VXLAN_MACRO},
        },
        # entry for dummy Bud Node member handling
        {
            "key": {"is_mc": 1,     "fwd_type": FWD_HEADER_TYPE_MPLS_BOS_IPV4, "first_encap_type": NPU_ENCAP_L3_HEADER_TYPE_HOST_MAC, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": ALL_1, "fwd_type": ALL_1,                         "first_encap_type": ALL_1,                        "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_IP_TO_NH_MC_MACRO},
        },
        # entry for dummy Bud Node member handling
        {
            "key": {"is_mc": 1,     "fwd_type": FWD_HEADER_TYPE_MPLS_BOS_IPV6, "first_encap_type": NPU_ENCAP_L3_HEADER_TYPE_HOST_MAC, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": ALL_1, "fwd_type": ALL_1,                         "first_encap_type": ALL_1,                        "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_IP_TO_NH_MC_MACRO},
        },

        # IPV6 NH router over Ethernet network
        {
            "key": {"is_mc": 0,     "fwd_type": FWD_HEADER_TYPE_IPV6, "first_encap_type": NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": ALL_1, "fwd_type": ALL_1,                "first_encap_type": ALL_1,                                "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_IP_UC_FIRST_MACRO},
        },
        # ================== MPLS_ ================
        # MPLS encap types starting with 0, do not share handling with IP
        # covers NPU_ENCAP_MPLS_HEADER_TYPE_ILM_LABEL, NPU_ENCAP_MPLS_HEADER_TYPE_ILM_TUNNEL, NPU_ENCAP_MPLS_HEADER_TYPE_ILM_PHP
        {
            "key": {"is_mc": DONT_CARE, "fwd_type": HEADER_TYPE_MPLS_HEADERS_PREFIX << 2, "first_encap_type": 0b0000, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": DONT_CARE, "fwd_type": 0b1100,                          "first_encap_type": 0b1000, "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_MPLS_L3_MACRO},
        },

        # ====================== MPLS + IPv6 + IPv4 path sharing encap types. Don'
        # TE headend for LDP over TE intra AS routing
        {
            "key": {"is_mc": DONT_CARE, "fwd_type": DONT_CARE, "first_encap_type": NPU_ENCAP_L3_HEADER_TYPE_LDP_OVER_TE, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": DONT_CARE, "fwd_type": DONT_CARE, "first_encap_type": ALL_1,                                "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_MPLS_L3_MACRO},
        },

        # TE headend intra AS routing without a specific tunnel id in the ingress,
        # resolving tunnel labels in the egress . Covers fwd_type IPv4/6 and MPLS
        {
            "key": {"is_mc": DONT_CARE, "fwd_type": DONT_CARE, "first_encap_type": NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": DONT_CARE, "fwd_type": DONT_CARE, "first_encap_type": ALL_1,                            "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_MPLS_L3_MACRO},
        },
        {
            "key": {"is_mc": DONT_CARE, "fwd_type": DONT_CARE, "first_encap_type": NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE_SR, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": DONT_CARE, "fwd_type": DONT_CARE, "first_encap_type": ALL_1,                            "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_MPLS_L3_MACRO},
        },
        # TE headend intra AS routing with a tunnel id resolved in the ingress. Covers fwd_type IPv4/6 and MPLS
        {
            "key": {"is_mc": DONT_CARE, "fwd_type": DONT_CARE, "first_encap_type": NPU_ENCAP_L3_HEADER_TYPE_TE_HE_WITH_TUNNEL_ID, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": DONT_CARE, "fwd_type": DONT_CARE, "first_encap_type": ALL_1,                                         "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_MPLS_L3_MACRO},
        },

        # ================== In bound mirror/redirect, and default entry ======================
        # All IBM/redirect packets treated the same. fwd_type not relevant in this case.
        {
            "key": {"is_mc": DONT_CARE, "fwd_type": DONT_CARE, "first_encap_type": NPU_ENCAP_MIRROR_OR_REDIRECT, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": DONT_CARE, "fwd_type": DONT_CARE, "first_encap_type": ALL_1,                        "second_encap_type": DONT_CARE},
            "payload": {"first_macro": TX_PUNT_MACRO},
        },
        # =============  MCG Counters ===============
        {
            "key":  {"is_mc": DONT_CARE, "fwd_type": HEADER_TYPE_IPV4_HEADERS_PREFIX << 1, "first_encap_type": NPU_ENCAP_L3_HEADER_TYPE_PWE_OR_MC_ACCOUNTING, "second_encap_type": DONT_CARE},
            "mask": {"is_mc": DONT_CARE, "fwd_type": 0b1110,                          "first_encap_type": ALL_1,                                 "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_IP_TO_NH_MC_ACCOUNTING_MACRO},
        },
        # forward header type FWD_HEADER_TYPE_IPV6_COLLAPSED_MC and FWD_HEADER_TYPE_IPV6
        {
            "key":  {"is_mc": DONT_CARE, "fwd_type": HEADER_TYPE_IPV6_HEADERS_PREFIX << 1, "first_encap_type": NPU_ENCAP_L3_HEADER_TYPE_PWE_OR_MC_ACCOUNTING, "second_encap_type": DONT_CARE},
            "mask": {"is_mc": DONT_CARE, "fwd_type": 0b1110,                          "first_encap_type": ALL_1,                                 "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TX_IP_TO_NH_MC_ACCOUNTING_MACRO},
        },

        # Default entry
        {
            "key": {"is_mc": DONT_CARE, "fwd_type": DONT_CARE, "first_encap_type": DONT_CARE, "second_encap_type": DONT_CARE},
            "mask":{"is_mc": DONT_CARE, "fwd_type": DONT_CARE, "first_encap_type": DONT_CARE, "second_encap_type": DONT_CARE},
            "payload": {"first_macro": NETWORK_TRANSMIT_ERROR_MACRO},
        },

    ]

    location = 0
    for line in table_data:
        table_key = txpp_first_macro_table_key_t(is_mc=line["key"]["is_mc"],
                                                 fwd_type=line["key"]["fwd_type"],
                                                 first_encap_type=line["key"]["first_encap_type"],
                                                 second_encap_type=line["key"]["second_encap_type"])
        table_mask = txpp_first_macro_table_key_t(is_mc=line["mask"]["is_mc"],
                                                  fwd_type=line["mask"]["fwd_type"],
                                                  first_encap_type=line["mask"]["first_encap_type"],
                                                  second_encap_type=line["mask"]["second_encap_type"])
        key = txpp_initial_npe_macro_table_key_t(txpp_first_macro_table_key=table_key)
        mask = txpp_initial_npe_macro_table_key_t(txpp_first_macro_table_key=table_mask)
        value = txpp_initial_npe_macro_table_value_t(np_macro_id=line["payload"]["first_macro"])
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        location += 1


def config_txpp_fwd_header_type_is_l2_table():
    table = txpp_fwd_header_type_is_l2_table
    MAX_ENCAP_DATA = 15
    # Ethernet is true for is_l2, all others are false
    # 2 exceptions: NPL_FWD_HEADER_TYPE_IPV{4/6}_COLLAPSED_MC with encap data of a bridge_nh is also l2
    for encap_data in range(0, MAX_ENCAP_DATA):
        for fwd_header_type in range(0, (1 << FWD_HEADER_TYPE_NUM_BITS)):
            if fwd_header_type == FWD_HEADER_TYPE_ETHERNET or ((encap_data == NPU_ENCAP_L3_HEADER_TYPE_COLLAPSED_MC) and (
                    fwd_header_type == FWD_HEADER_TYPE_IPV4_COLLAPSED_MC or fwd_header_type == FWD_HEADER_TYPE_IPV6_COLLAPSED_MC)):
                value = txpp_fwd_header_type_is_l2_table_value_t(1)
            else:
                value = txpp_fwd_header_type_is_l2_table_value_t(0)
            key = txpp_fwd_header_type_is_l2_table_key_t(packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_=encap_data,
                                                         packet_protocol_layer_0__tx_npu_header_fwd_header_type=fwd_header_type)
            table.insert(NETWORK_CONTEXT, key, value)


def config_map_tm_dp_ecn_to_wa_ecn_dp_static_table():
    table = map_tm_dp_ecn_to_wa_ecn_dp_static_table
    table_config = DirectTableConfig("map_tm_dp_ecn_to_wa_ecn_dp_static_table")
    table_data = [{"key": ["tm_h_ecn", "tm_h_dp_0"] , "value": ["dp_ecn_wa_local_var_new_dp"]},
                  {"key": [  0       ,     0      ] , "value": [             0              ]},
                  {"key": [  0       ,     1      ] , "value": [             1              ]},
                  {"key": [  1       ,     0      ] , "value": [             0              ]},
                  {"key": [  1       ,     1      ] , "value": [             1              ]},
                  ]
    table_config.create_table(table_data, FABRIC_CONTEXT)
