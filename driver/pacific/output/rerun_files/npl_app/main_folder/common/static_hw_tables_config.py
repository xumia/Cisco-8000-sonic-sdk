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

DONT_CARE = 0
ALL_1 = (1 << 128) - 1
FWD_HEADER_TYPE_NUM_BITS = 4


def config_tables():
    config_txpp_first_enc_type_to_second_enc_type_offset()
    config_calc_checksum_enable_table()
    config_fwd_type_to_ive_enable_table()
    config_bfd_udp_port_static_table()
    config_bfd_inject_inner_ethernet_header_static_table()
    config_bfd_set_inject_type_static_table()
    config_bfd_punt_encap_static_table()
    config_eth_oam_set_da_mc_static_table()
    config_bfd_inject_ttl_static_table()


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


def config_fwd_type_to_ive_enable_table():
    table = fwd_type_to_ive_enable_table
    for fwd_header_type in range(0, (1 << FWD_HEADER_TYPE_NUM_BITS)):
        if fwd_header_type == FWD_HEADER_TYPE_ETHERNET:
            value = fwd_type_to_ive_enable_table_value_t(1)
        else:
            value = fwd_type_to_ive_enable_table_value_t(0)
        key = fwd_type_to_ive_enable_table_key_t(txpp_npe_to_npe_metadata_fwd_header_type=fwd_header_type)
        table.insert(NETWORK_CONTEXT, key, value)


def config_calc_checksum_enable_table():
    table = calc_checksum_enable_table
    for fwd_header_type in range(0, (1 << FWD_HEADER_TYPE_NUM_BITS)):
        if fwd_header_type == FWD_HEADER_TYPE_IPV4 or fwd_header_type == FWD_HEADER_TYPE_IPV4_COLLAPSED_MC:
            checksum_enable = 1
        else:
            checksum_enable = 0
        key = calc_checksum_enable_table_key_t(txpp_npe_to_npe_metadata_fwd_header_type=fwd_header_type)
        value = calc_checksum_enable_table_value_t(calc_checksum_enable=checksum_enable)
        table.insert(NETWORK_CONTEXT, key, value)

    table = calc_checksum_enable_table
    for fwd_header_type in range(0, (1 << FWD_HEADER_TYPE_NUM_BITS)):
        checksum_enable = 0
        key = calc_checksum_enable_table_key_t(txpp_npe_to_npe_metadata_fwd_header_type=fwd_header_type)
        value = calc_checksum_enable_table_value_t(calc_checksum_enable=checksum_enable)
        table.insert(FABRIC_CONTEXT, key, value)


# Table not used. Configuring all entries to false
def config_txpp_first_enc_type_to_second_enc_type_offset():
    table = txpp_first_enc_type_to_second_enc_type_offset
    for i in range(0, 16):
        value = txpp_first_enc_type_to_second_enc_type_offset_value_t(txpp_first_encap_is_wide=FALSE_VALUE)
        key = txpp_first_enc_type_to_second_enc_type_offset_key_t(i)
        table.insert(NETWORK_CONTEXT, key, value)


def config_bfd_udp_port_static_table():
    table = bfd_udp_port_static_table
    table_data = [
        {
            "key": {"session_type": BFD_TYPE_MICRO},
            "value": {"l4_ports": (UDP_BFD_CONTROL_SRC_PORT << 16) | UDP_BFD_MICRO_HOP_PORT,  "length": 32},
        },
        {
            "key": {"session_type": BFD_TYPE_SINGLE_HOP},
            "value": {"l4_ports": (UDP_BFD_CONTROL_SRC_PORT << 16) | UDP_BFD_SINGLE_HOP_PORT, "length": 32},
        },
        {
            "key": {"session_type": BFD_TYPE_MULTI_HOP},
            "value": {"l4_ports": (UDP_BFD_CONTROL_SRC_PORT << 16) | UDP_BFD_MULTI_HOP_PORT,  "length": 32},
        },
        {
            "key": {"session_type": BFD_TYPE_ECHO},
            "value": {"l4_ports": (UDP_BFD_ECHO_PORT << 16) | UDP_BFD_ECHO_PORT,       "length": 32},
        },
    ]
    for line in table_data:
        key = bfd_udp_port_static_table_key_t(pd_pd_npu_host_inject_fields_aux_data_bfd_session_type=line["key"]["session_type"])
        value = bfd_udp_port_static_table_value_t(
            l4_ports=line["value"]["l4_ports"],
            length=line["value"]["length"])
        table.insert(HOST_CONTEXT, key, value)


def config_bfd_inject_ttl_static_table():
    table = bfd_inject_ttl_static_table
    table_data = [
        { "key": {"requires_inject_up": 0,
                  "requires_label"    : 0},
          "value": {"ttl"             : 255},
          },
        { "key": {"requires_inject_up": 0,
                  "requires_label"    : 1},
          "value": {"ttl"             : 255},
          },
        { "key": {"requires_inject_up": 1,
                  "requires_label"    : 0},
          "value": {"ttl"             : 0},
          },
        { "key": {"requires_inject_up": 1,
                  "requires_label"    : 1},
          "value": {"ttl"             : 255},
          },
    ]
    for line in table_data:
        key = bfd_inject_ttl_static_table_key_t(
            requires_inject_up=line["key"]["requires_inject_up"],
            requires_label=line["key"]["requires_label"])
        value = bfd_inject_ttl_static_table_value_t(
            bfd_inject_ttl=line["value"]["ttl"])
        table.insert(HOST_CONTEXT, key, value)


def config_bfd_inject_inner_ethernet_header_static_table():
    sizeof_initial_hdr = SIZEOF_INJECT_HEADER
    table = bfd_inject_inner_ethernet_header_static_table
    table_data = [
        { "key": {"requires_inject_up": 0,
                  "transport": BFD_TRANSPORT_IPV4 << 1},
          "value": {"type": 0,
                    "pkt_size": sizeof_initial_hdr + SIZEOF_IPV4_HEADER + SIZEOF_UDP_HEADER + SIZEOF_BFD_HEADER,
                    "size1": sizeof_initial_hdr, # inner ethernet = 0
                    "size2": sizeof_initial_hdr + SIZEOF_IPV4_HEADER,
                    "size3": 0,
                    "bitmap": 0b011111},
          },
        { "key": {"requires_inject_up": 0,
                  "transport": (BFD_TRANSPORT_IPV4 << 1) | 1},
          "value": {"type": 0,
                    "pkt_size": sizeof_initial_hdr + SIZEOF_IPV4_HEADER + SIZEOF_UDP_HEADER + SIZEOF_BFD_HEADER,
                    "size1": sizeof_initial_hdr, # inner ethernet = 0
                    "size2": sizeof_initial_hdr + SIZEOF_IPV4_HEADER,
                    "size3": 0,
                    "bitmap": 0b011111},
          },
        { "key": {"requires_inject_up": 0,
                  "transport": BFD_TRANSPORT_IPV6 << 1},
          "value": {"type": 0,
                    "pkt_size": sizeof_initial_hdr + SIZEOF_IPV6_HEADER + SIZEOF_UDP_HEADER + SIZEOF_BFD_HEADER,
                    "size1": sizeof_initial_hdr, # inner ethernet = 0
                    "size2": sizeof_initial_hdr + SIZEOF_IPV6_HEADER - SIZEOF_IPV6_ADDR,
                    "size3": sizeof_initial_hdr + SIZEOF_IPV6_HEADER,
                    "bitmap": 0b111111},
          },
        { "key": {"requires_inject_up": 0,
                  "transport": (BFD_TRANSPORT_IPV6 << 1) | 1},
          "value": {"type": 0,
                    "pkt_size": sizeof_initial_hdr + SIZEOF_IPV6_HEADER + SIZEOF_UDP_HEADER + SIZEOF_BFD_HEADER,
                    "size1": sizeof_initial_hdr, # inner ethernet = 0
                    "size2": sizeof_initial_hdr + SIZEOF_IPV6_HEADER - SIZEOF_IPV6_ADDR,
                    "size3": sizeof_initial_hdr + SIZEOF_IPV6_HEADER,
                    "bitmap": 0b111111},
          },
        { "key": {"requires_inject_up": 1,
                  "transport": BFD_TRANSPORT_IPV4 << 1},
          "value": {"type": ETHER_TYPE_IPV4,
                    "pkt_size": sizeof_initial_hdr + SIZEOF_8021Q_HEADER + SIZEOF_IPV4_HEADER + SIZEOF_UDP_HEADER + SIZEOF_BFD_HEADER,
                    "size1": sizeof_initial_hdr + SIZEOF_8021Q_HEADER,
                    "size2": sizeof_initial_hdr + SIZEOF_8021Q_HEADER + SIZEOF_IPV4_HEADER,
                    "size3": 0,
                    "bitmap": 0b011111},
          },
        { "key": {"requires_inject_up": 1,
                  "transport": BFD_TRANSPORT_IPV6 << 1},
          "value": {"type": ETHER_TYPE_IPV6,
                    "pkt_size": sizeof_initial_hdr + SIZEOF_8021Q_HEADER + SIZEOF_IPV6_HEADER + SIZEOF_UDP_HEADER + SIZEOF_BFD_HEADER,
                    "size1": sizeof_initial_hdr + SIZEOF_8021Q_HEADER,
                    "size2": sizeof_initial_hdr + SIZEOF_8021Q_HEADER + SIZEOF_IPV6_HEADER - SIZEOF_IPV6_ADDR,
                    "size3": sizeof_initial_hdr + SIZEOF_8021Q_HEADER + SIZEOF_IPV6_HEADER,
                    "bitmap": 0b111111},
          },
        { "key": {"requires_inject_up": 1,
                  "transport": (BFD_TRANSPORT_IPV4 << 1) | 1},
          "value": {"type": ETHER_TYPE_MPLS_UC,
                    "pkt_size": sizeof_initial_hdr + SIZEOF_8021Q_HEADER + SIZEOF_MPLS_LABEL + SIZEOF_IPV4_HEADER + SIZEOF_UDP_HEADER + SIZEOF_BFD_HEADER,
                    "size1": sizeof_initial_hdr + SIZEOF_8021Q_HEADER + SIZEOF_MPLS_LABEL,
                    "size2": sizeof_initial_hdr + SIZEOF_8021Q_HEADER + SIZEOF_MPLS_LABEL + SIZEOF_IPV4_HEADER,
                    "size3": 0,
                    "bitmap": 0b011111},
          },
        { "key": {"requires_inject_up": 1,
                  "transport": (BFD_TRANSPORT_IPV6 << 1) | 1},
          "value": {"type": ETHER_TYPE_MPLS_UC,
                    "pkt_size": sizeof_initial_hdr + SIZEOF_8021Q_HEADER + SIZEOF_MPLS_LABEL + SIZEOF_IPV6_HEADER + SIZEOF_UDP_HEADER + SIZEOF_BFD_HEADER,
                    "size1": sizeof_initial_hdr + SIZEOF_8021Q_HEADER + SIZEOF_MPLS_LABEL,
                    "size2": sizeof_initial_hdr + SIZEOF_8021Q_HEADER + SIZEOF_MPLS_LABEL + SIZEOF_IPV6_HEADER - SIZEOF_IPV6_ADDR,
                    "size3": sizeof_initial_hdr + SIZEOF_8021Q_HEADER + SIZEOF_MPLS_LABEL + SIZEOF_IPV6_HEADER,
                    "bitmap": 0b111111},
          },
    ]

    for line in table_data:
        key = bfd_inject_inner_ethernet_header_static_table_key_t(
            requires_inject_up=line["key"]["requires_inject_up"],
            transport=line["key"]["transport"])
        value = bfd_inject_inner_ethernet_header_static_table_value_t(
            type=line["value"]["type"],
            pkt_size=line["value"]["pkt_size"],
            size1=line["value"]["size1"],
            size2=line["value"]["size2"],
            size3=line["value"]["size3"],
            bitmap=line["value"]["bitmap"])
        table.insert(HOST_CONTEXT, key, value)


def config_bfd_set_inject_type_static_table():
    table = bfd_set_inject_type_static_table
    table_data = [
        {"requires_inject_up": 0, "inject_header_type": INJECT_HEADER_TYPE_DOWN_RX_COUNT},
        {"requires_inject_up": 1, "inject_header_type": INJECT_HEADER_TYPE_UP_ETH},
    ]
    for line in table_data:
        key = bfd_set_inject_type_static_table_key_t(
            pd_pd_npu_host_inject_fields_aux_data_bfd_requires_inject_up=line["requires_inject_up"])
        value = bfd_set_inject_type_static_table_value_t(packet_inject_header_inject_header_type=line["inject_header_type"])
        table.insert(HOST_CONTEXT, key, value)


def config_bfd_punt_encap_static_table():
    table = bfd_punt_encap_static_table
    table_data = [
        {
            "key": {"encap_result": 1},
            "value": {"fwd_offset": INGRESS_NPU_HEADER_SIZE,
                      "nmret": NPU_ENCAP_MIRROR_OR_REDIRECT,
                      "lpts_punt_encap": (PUNT_SRC_INGRESS_BFD << 4)},
        },
    ]
    for line in table_data:
        key = bfd_punt_encap_static_table_key_t(encap_result=line["key"]["encap_result"])
        value = bfd_punt_encap_static_table_value_t(fwd_offset=line["value"]["fwd_offset"],
                                                    nmret=line["value"]["nmret"],
                                                    lpts_punt_encap=line["value"]["lpts_punt_encap"])
        table.insert(NETWORK_CONTEXT, key, value)


def config_eth_oam_set_da_mc_static_table():
    table = eth_oam_set_da_mc_static_table
    table_data = [
        {
            "key": 1,
            "value": {"da": MAC_OAM_DA_MC_MSB},
        },
    ]
    for line in table_data:
        key = eth_oam_set_da_mc_static_table_key_t()
        value = eth_oam_set_da_mc_static_table_value_t(
            da=line["value"]["da"])
        table.insert(HOST_CONTEXT, key, value)

    table = eth_oam_set_da_mc2_static_table
    table_data = [
        {
            "key": 1,
            "value": {"da": MAC_OAM_DA_MC_LSB},
        },
    ]

    for line in table_data:
        key = eth_oam_set_da_mc2_static_table_key_t()
        value = eth_oam_set_da_mc2_static_table_value_t(
            da=line["value"]["da"])
        table.insert(HOST_CONTEXT, key, value)
