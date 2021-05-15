#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

from leaba import sdk
import ip_test_base
from packet_test_utils import *
import sim_utils
import topology as T
from scapy.all import *
import decor

from sdk_test_case_base import *

SYS_PORT_GID_BASE = 23

RX_IFG = 0
RX_SERDES_FIRST = T.get_device_out_first_serdes(4)
RX_SERDES_LAST = RX_SERDES_FIRST + 1

TX_IFG_DEF = T.get_device_ifg(1)
TX_SERDES_FIRST_DEF = T.get_device_out_next_first_serdes(8)
TX_SERDES_LAST_DEF = TX_SERDES_FIRST_DEF + 1

TX_IFG_EXT = T.get_device_ifg(1)
TX_SERDES_FIRST_EXT = T.get_device_next2_first_serdes(8)
TX_SERDES_LAST_EXT = TX_SERDES_FIRST_EXT + 1

AC_PORT_GID_BASE = 10

SWITCH_GID = 100

DST_MAC = "ca:fe:ca:fe:ca:fe"
SRC_MAC = "de:ad:de:ad:de:ad"
VLAN = 0xAB9

PUNT_INJECT_PORT_MAC_ADDR = "ca:fe:ba:be:ca:fe"
HOST_MAC_ADDR = "ba:be:ca:fe:ba:be"

# IPv4
IPV4_SIP = T.ipv4_addr('192.85.1.1')
IPV4_DIP = T.ipv4_addr('208.209.210.211')

# IPv6
IPV6_SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
IPV6_DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

TTL = 127

MIRROR_CMD_GID1 = 9
MIRROR_CMD_GID2 = 10
LP_MIRROR_CMD_GID = 11

PUNT_VLAN = 0xA13

PUNT_INJECT_IFG = 0
PUNT_INJECT_SERDES_FIRST = T.get_device_first_serdes(8)
PUNT_INJECT_SERDES_LAST = PUNT_INJECT_SERDES_FIRST + 1
PUNT_INJECT_SP_GID = SYS_PORT_GID_BASE + 20

MPLS_LABEL = sdk.la_mpls_label()
MPLS_LABEL.label = 0x63
MPLS_TTL = 0xff

QOS_COUNTER_OFFSET = 2
QOS_MARK_DSCP = 0x18

QOS_GROUP_ID = 1

IN_PCPDEI = sdk.la_vlan_pcpdei()
IN_PCPDEI.fields.pcp = 2
IN_PCPDEI.fields.dei = 1

IN_DSCP = sdk.la_ip_dscp()
IN_DSCP.value = 0

INPUT_IPV4_PACKET_BASE = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=2, id=1, vlan=VLAN) / \
    IP(src=IPV4_SIP.addr_str, dst=IPV4_DIP.addr_str, ttl=TTL) / \
    TCP()

INPUT_IPV6_PACKET_BASE = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=2, id=1, vlan=VLAN) / \
    IPv6(src=IPV6_SIP.addr_str, dst=IPV6_DIP.addr_str, hlim=TTL) / \
    TCP()

INPUT_IPV4_o_MPLS_PACKET_BASE = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=2, id=1, vlan=VLAN) / \
    MPLS(label=MPLS_LABEL.label, ttl=MPLS_TTL) / \
    IP(src=IPV4_SIP.addr_str, dst=IPV4_DIP.addr_str, ttl=TTL)
# TCP() remove this TCP header in order to reduce the packet size, to
# avoid failing on a bug occurs only on PAcific HW (junk into the Punt
# header)

INPUT_IPV6_o_MPLS_PACKET_BASE = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=2, id=1, vlan=VLAN) / \
    MPLS(label=MPLS_LABEL.label, ttl=MPLS_TTL) / \
    IPv6(src=IPV6_SIP.addr_str, dst=IPV6_DIP.addr_str, hlim=TTL)
# TCP() remove this TCP header in order to reduce the packet size, to
# avoid failing on a bug occurs only on PAcific HW (junk into the Punt
# header)

OUTPUT_IPV4_PACKET_BASE = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=2, id=1, vlan=VLAN) / \
    IP(src=IPV4_SIP.addr_str, dst=IPV4_DIP.addr_str, ttl=TTL) / \
    TCP()

OUTPUT_IPV6_PACKET_BASE = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=2, id=1, vlan=VLAN) / \
    IPv6(src=IPV6_SIP.addr_str, dst=IPV6_DIP.addr_str, hlim=TTL) / \
    TCP()

OUTPUT_IPV4_o_MPLS_PACKET_BASE = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=2, id=1, vlan=VLAN) / \
    MPLS(label=MPLS_LABEL.label, ttl=MPLS_TTL) / \
    IP(src=IPV4_SIP.addr_str, dst=IPV4_DIP.addr_str, ttl=TTL)
# TCP() remove this TCP header in order to reduce the packet size, to
# avoid failing on a bug occurs only on PAcific HW (junk into the Punt
# header)

OUTPUT_IPV6_o_MPLS_PACKET_BASE = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=2, id=1, vlan=VLAN) / \
    MPLS(label=MPLS_LABEL.label, ttl=MPLS_TTL) / \
    IPv6(src=IPV6_SIP.addr_str, dst=IPV6_DIP.addr_str, hlim=TTL)
# TCP() remove this TCP header in order to reduce the packet size, to
# avoid failing on a bug occurs only on PAcific HW (junk into the Punt
# header)

MIRROR_PACKET_BASE = \
    Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
         fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET, next_header_offset=0,
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR, code=MIRROR_CMD_GID1,
         source_sp=SYS_PORT_GID_BASE, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         source_lp=AC_PORT_GID_BASE | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING, destination_lp=AC_PORT_GID_BASE + 1,
         relay_id=SWITCH_GID, lpts_flow_type=0) / \
    Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=2, id=1, vlan=VLAN) / \
    MPLS(label=MPLS_LABEL.label, ttl=MPLS_TTL) / \
    IP(src=IPV4_SIP.addr_str, dst=IPV4_DIP.addr_str, ttl=TTL)
# TCP() remove this TCP header in order to reduce the packet size, to
# avoid failing on a bug occurs only on PAcific HW (junk into the Punt
# header)

MIRROR_IPV6_PACKET_BASE = \
    Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
         fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET, next_header_offset=0,
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR, code=MIRROR_CMD_GID1,
         source_sp=SYS_PORT_GID_BASE, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         source_lp=AC_PORT_GID_BASE | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING, destination_lp=AC_PORT_GID_BASE + 2,
         relay_id=SWITCH_GID, lpts_flow_type=0) / \
    Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=2, id=1, vlan=VLAN) / \
    IPv6(src=IPV6_SIP.addr_str, dst=IPV6_DIP.addr_str, hlim=TTL) / \
    TCP()

INPUT_IPV4_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_IPV4_PACKET_BASE)
OUTPUT_IPV4_PACKET = add_payload(OUTPUT_IPV4_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
INPUT_IPV6_PACKET = add_payload(INPUT_IPV6_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
OUTPUT_IPV6_PACKET = add_payload(OUTPUT_IPV6_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
MIRROR_PACKET = add_payload(MIRROR_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
MIRROR_IPV6_PACKET = add_payload(MIRROR_IPV6_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
INPUT_IPV4_o_MPLS_PACKET = add_payload(INPUT_IPV4_o_MPLS_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
OUTPUT_IPV4_o_MPLS_PACKET = add_payload(OUTPUT_IPV4_o_MPLS_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
INPUT_IPV6_o_MPLS_PACKET = add_payload(INPUT_IPV6_o_MPLS_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
OUTPUT_IPV6_o_MPLS_PACKET = add_payload(OUTPUT_IPV6_o_MPLS_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)


class l2_rtf_base(sdk_test_case_base):
    RX_SLICE = T.get_device_slice(2)
    PUNT_INJECT_SLICE = T.get_device_slice(3)
    TX_SLICE_DEF = T.get_device_slice(4)
    TX_SLICE_EXT = T.get_device_slice(5)

    def setUp(self):
        super().setUp()
        self.RX_SLICE = T.choose_active_slices(self.device, self.RX_SLICE, [2, 3])
        self.PUNT_INJECT_SLICE = T.choose_active_slices(self.device, self.PUNT_INJECT_SLICE, [3, 1])
        self.TX_SLICE_DEF = T.choose_active_slices(self.device, self.TX_SLICE_DEF, [4, 2])
        self.TX_SLICE_EXT = T.choose_active_slices(self.device, self.TX_SLICE_EXT, [5, 0])

        self.create_system_setup()
        self.eth_acl_key_profile = self.device.create_acl_key_profile(
            sdk.la_acl_key_type_e_ETHERNET, sdk.la_acl_direction_e_INGRESS, sdk.LA_ACL_KEY_ETHERNET, 0)

    def create_drop_command(self):
        command = []
        drop_action = sdk.la_acl_command_action()
        drop_action.type = sdk.la_acl_action_type_e_DROP
        drop_action.data.drop = True
        command.append(drop_action)

        return command

    def create_force_l2_destination_command(self, l2_destination):
        command = []
        force_action = sdk.la_acl_command_action()
        force_action.type = sdk.la_acl_action_type_e_L2_DESTINATION
        force_action.data.l2_dest = l2_destination
        command.append(force_action)

        return command

    def create_mirror_cmd_acl_command(self, mirror_gid):
        command = []
        mirror_cmd_action = sdk.la_acl_command_action()
        mirror_cmd_action.type = sdk.la_acl_action_type_e_MIRROR_CMD
        mirror_cmd_action.data.mirror_cmd = mirror_gid
        command.append(mirror_cmd_action)
        do_mirror_action = sdk.la_acl_command_action()
        do_mirror_action.type = sdk.la_acl_action_type_e_DO_MIRROR
        do_mirror_action.data.do_mirror = sdk.la_acl_mirror_src_e_DO_MIRROR_FROM_CMD
        command.append(do_mirror_action)

        return command

    def create_counter_command(self, counter):
        command = []
        counter_cmd_action = sdk.la_acl_command_action()
        counter_cmd_action.type = sdk.la_acl_action_type_e_COUNTER
        counter_cmd_action.data.counter = counter
        command.append(counter_cmd_action)

        return command

    def create_tc_and_color_command(self, tc, color):
        command = []
        qos_action = sdk.la_acl_command_action()
        qos_action.type = sdk.la_acl_action_type_e_TRAFFIC_CLASS
        qos_action.data.traffic_class = tc
        command.append(qos_action)

        color_action = sdk.la_acl_command_action()
        color_action.type = sdk.la_acl_action_type_e_COLOR
        color_action.data.color = color
        command.append(color_action)

        return command

    def create_mirror_from_lp_command(self):
        command = []
        do_mirror_action = sdk.la_acl_command_action()
        do_mirror_action.type = sdk.la_acl_action_type_e_DO_MIRROR
        do_mirror_action.data.do_mirror = sdk.la_acl_mirror_src_e_DO_MIRROR_FROM_LP
        command.append(do_mirror_action)

        return command

    def create_qos_commands(self, qos_offset, qos_mark_dscp):
        command = []
        do_qos_action = sdk.la_acl_command_action()
        do_qos_action.type = sdk.la_acl_action_type_e_COUNTER_TYPE
        do_qos_action.data.counter_type = sdk.la_acl_counter_type_e_DO_QOS_COUNTING
        command.append(do_qos_action)

        qos_action = sdk.la_acl_command_action()
        qos_action.type = sdk.la_acl_action_type_e_QOS_OR_METER_COUNTER_OFFSET
        qos_action.data.qos_offset = qos_offset
        command.append(qos_action)

        remark_fwd_action = sdk.la_acl_command_action()
        remark_fwd_action.type = sdk.la_acl_action_type_e_REMARK_FWD
        remark_fwd_action.data.remark_fwd = qos_mark_dscp
        command.append(remark_fwd_action)

        encap_exp_action = sdk.la_acl_command_action()
        encap_exp_action.type = sdk.la_acl_action_type_e_ENCAP_EXP
        encap_exp_action.data.encap_exp = 0
        command.append(encap_exp_action)

        remark_group_action = sdk.la_acl_command_action()
        remark_group_action.type = sdk.la_acl_action_type_e_REMARK_GROUP
        remark_group_action.data.remark_group = 0
        command.append(remark_group_action)

        return command

    def create_system_setup(self):
        self.switch = T.switch(self, self.device, SWITCH_GID)
        self.dest_mac = T.mac_addr(DST_MAC)

        self.rx_eth_port = T.ethernet_port(
            self,
            self.device,
            self.RX_SLICE,
            RX_IFG,
            SYS_PORT_GID_BASE,
            RX_SERDES_FIRST,
            RX_SERDES_LAST)
        self.rx_ac_port = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            self.switch,
            self.rx_eth_port,
            None,
            VLAN,
            0x0)

        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            self.PUNT_INJECT_SLICE,
            PUNT_INJECT_IFG,
            PUNT_INJECT_SP_GID,
            PUNT_INJECT_SERDES_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        self.lp_mirror_cmd = T.create_l2_mirror_command(self.device, LP_MIRROR_CMD_GID, self.pi_port, HOST_MAC_ADDR, PUNT_VLAN)

        self.tx_eth_port_def = T.ethernet_port(
            self,
            self.device,
            self.TX_SLICE_DEF,
            TX_IFG_DEF,
            SYS_PORT_GID_BASE + 1,
            TX_SERDES_FIRST_DEF,
            TX_SERDES_LAST_DEF)
        self.tx_ac_port_def = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 1,
            self.topology.filter_group_def,
            self.switch,
            self.tx_eth_port_def,
            self.dest_mac,
            VLAN,
            0x0)

        self.tx_eth_port_ext = T.ethernet_port(self,
                                               self.device,
                                               self.TX_SLICE_EXT,
                                               TX_IFG_EXT,
                                               SYS_PORT_GID_BASE + 2,
                                               TX_SERDES_FIRST_EXT,
                                               TX_SERDES_LAST_EXT)
        self.tx_ac_port_ext = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 2,
            self.topology.filter_group_def,
            self.switch,
            self.tx_eth_port_ext,
            None,
            VLAN,
            0x0)

        self.mirror_command1 = T.create_l2_mirror_command(self.device, MIRROR_CMD_GID1, self.pi_port, HOST_MAC_ADDR, PUNT_VLAN)
        self.mirror_command2 = T.create_l2_mirror_command(self.device, MIRROR_CMD_GID2, self.pi_port, HOST_MAC_ADDR, PUNT_VLAN)
