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

PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
SA = T.mac_addr('be:ef:5d:35:7a:35')

PUNT_INJECT_IFG = 0
PUNT_INJECT_SERDES_FIRST = T.get_device_first_serdes(8)
PUNT_INJECT_SERDES_LAST = PUNT_INJECT_SERDES_FIRST + 1
PUNT_INJECT_SP_GID = 0x100

PUNT_INJECT_PORT_MAC_ADDR = "ca:fe:ba:be:ca:fe"
HOST_MAC_ADDR = "ba:be:ca:fe:ba:be"
PUNT_VLAN = 0xA13

MIRROR_CMD_GID1 = 9
MIRROR_CMD_GID2 = 10

# IPv4
IPV4_SIP = T.ipv4_addr('192.85.1.1')
IPV4_DIP = T.ipv4_addr('208.209.210.211')

# IPv6
IPV6_SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
IPV6_DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

# Tunnel
REMOTE_ANY_IP = T.ipv4_addr('250.12.255.10')
LOCAL_IP = T.ipv4_addr('192.168.95.250')
ANY_IP = T.ipv4_addr('255.255.255.255')
TUNNEL_PORT_GID = 0x521

TTL = 127

QOS_COUNTER_OFFSET = 2
QOS_MARK_DSCP = 0x18

QOS_GROUP_ID = 1
IN_DSCP_VAL = 0

IN_DSCP = sdk.la_ip_dscp()
IN_DSCP.value = IN_DSCP_VAL

INPUT_IPV4_PACKET_BASE = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=IPV4_SIP.addr_str, dst=IPV4_DIP.addr_str, ttl=TTL) / \
    TCP()

INPUT_IPV4_PACKET_SVI_BASE = \
    Ether(dst=T.RX_SVI_MAC.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
    IP(src=IPV4_SIP.addr_str, dst=IPV4_DIP.addr_str, ttl=TTL) / \
    TCP()

EXPECTED_DEFAULT_OUTPUT_IPV4_PACKET_BASE = \
    Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) / \
    IP(src=IPV4_SIP.addr_str, dst=IPV4_DIP.addr_str, ttl=TTL - 1) / \
    TCP()

EXPECTED_EXTRA_OUTPUT_IPV4_PACKET_BASE = \
    Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str) / \
    IP(src=IPV4_SIP.addr_str, dst=IPV4_DIP.addr_str, ttl=TTL - 1) / \
    TCP()

INPUT_IPV6_PACKET_BASE = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IPv6(src=IPV6_SIP.addr_str, dst=IPV6_DIP.addr_str, hlim=TTL) / \
    TCP()

EXPECTED_DEFAULT_OUTPUT_IPV6_PACKET_BASE = \
    Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) / \
    IPv6(src=IPV6_SIP.addr_str, dst=IPV6_DIP.addr_str, hlim=TTL - 1) / \
    TCP()

EXPECTED_EXTRA_OUTPUT_IPV6_PACKET_BASE = \
    Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str) / \
    IPv6(src=IPV6_SIP.addr_str, dst=IPV6_DIP.addr_str, hlim=TTL - 1) / \
    TCP()

INPUT_IPV4_O_IPV4_TUNNEL_PACKET_BASE = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=REMOTE_ANY_IP.addr_str, dst=LOCAL_IP.addr_str, ttl=TTL) / \
    IP(src=IPV4_SIP.addr_str, dst=IPV4_DIP.addr_str, ttl=TTL) / \
    TCP()

EXPECTED_OUTPUT_IPV4_O_IPV4_TUNNEL_PACKET_BASE = \
    Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) / \
    IP(src=IPV4_SIP.addr_str, dst=IPV4_DIP.addr_str, ttl=TTL - 1) / \
    TCP()

INPUT_IPV6_O_IPV4_TUNNEL_PACKET_BASE = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=REMOTE_ANY_IP.addr_str, dst=LOCAL_IP.addr_str, ttl=TTL) / \
    IPv6(src=IPV6_SIP.addr_str, dst=IPV6_DIP.addr_str, hlim=TTL) / \
    TCP()

EXPECTED_OUTPUT_IPV6_O_IPV4_TUNNEL_PACKET_BASE = \
    Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) / \
    IPv6(src=IPV6_SIP.addr_str, dst=IPV6_DIP.addr_str, hlim=TTL - 1) / \
    TCP()

MIRROR_IPV4_PACKET_BASE = \
    Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4,
         fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4, next_header_offset=0,
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR, code=MIRROR_CMD_GID1,
         source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         source_lp=T.RX_L3_AC_GID, destination_lp=T.TX_L3_AC_DEF_GID,
         relay_id=T.VRF_GID, lpts_flow_type=0) / \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=IPV4_SIP.addr_str, dst=IPV4_DIP.addr_str, ttl=TTL) / \
    TCP()

MIRROR_IPV6_PACKET_BASE = \
    Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV6,
         fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6, next_header_offset=0,
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR, code=MIRROR_CMD_GID1,
         source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         source_lp=T.RX_L3_AC_GID, destination_lp=T.TX_L3_AC_DEF_GID,
         relay_id=T.VRF_GID, lpts_flow_type=0) / \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IPv6(src=IPV6_SIP.addr_str, dst=IPV6_DIP.addr_str, hlim=TTL) / \
    TCP()

INPUT_IPV4_PACKET, INPUT_IPV4_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_IPV4_PACKET_BASE)
INPUT_IPV4_PACKET_SVI, INPUT_IPV4_PACKET_SVI_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_IPV4_PACKET_SVI_BASE)
EXPECTED_DEFAULT_OUTPUT_IPV4_PACKET = add_payload(EXPECTED_DEFAULT_OUTPUT_IPV4_PACKET_BASE, INPUT_IPV4_PACKET_PAYLOAD_SIZE)
EXPECTED_EXTRA_OUTPUT_IPV4_PACKET = add_payload(EXPECTED_EXTRA_OUTPUT_IPV4_PACKET_BASE, INPUT_IPV4_PACKET_PAYLOAD_SIZE)
MIRROR_IPV4_PACKET = add_payload(MIRROR_IPV4_PACKET_BASE, INPUT_IPV4_PACKET_PAYLOAD_SIZE)
INPUT_IPV6_PACKET, INPUT_IPV6_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_IPV6_PACKET_BASE)
EXPECTED_DEFAULT_OUTPUT_IPV6_PACKET = add_payload(EXPECTED_DEFAULT_OUTPUT_IPV6_PACKET_BASE, INPUT_IPV6_PACKET_PAYLOAD_SIZE)
EXPECTED_EXTRA_OUTPUT_IPV6_PACKET = add_payload(EXPECTED_EXTRA_OUTPUT_IPV6_PACKET_BASE, INPUT_IPV6_PACKET_PAYLOAD_SIZE)
INPUT_IPV4_O_IPV4_TUNNEL_PACKET, INPUT_IPV4_O_IPV4_TUNNEL_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(
    INPUT_IPV4_O_IPV4_TUNNEL_PACKET_BASE)
EXPECTED_OUTPUT_IPV4_O_IPV4_TUNNEL_PACKET = add_payload(
    EXPECTED_OUTPUT_IPV4_O_IPV4_TUNNEL_PACKET_BASE,
    INPUT_IPV4_O_IPV4_TUNNEL_PACKET_PAYLOAD_SIZE)
INPUT_IPV6_O_IPV4_TUNNEL_PACKET, INPUT_IPV6_O_IPV4_TUNNEL_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(
    INPUT_IPV6_O_IPV4_TUNNEL_PACKET_BASE)
EXPECTED_OUTPUT_IPV6_O_IPV4_TUNNEL_PACKET = add_payload(
    EXPECTED_OUTPUT_IPV6_O_IPV4_TUNNEL_PACKET_BASE,
    INPUT_IPV6_O_IPV4_TUNNEL_PACKET_PAYLOAD_SIZE)
MIRROR_IPV6_PACKET = add_payload(MIRROR_IPV6_PACKET_BASE, INPUT_IPV6_PACKET_PAYLOAD_SIZE)


class l3_rtf_base(sdk_test_case_base):
    PUNT_INJECT_SLICE = 3

    def setUp(self):
        super().setUp()
        self.PUNT_INJECT_SLICE = T.choose_active_slices(self.device, self.PUNT_INJECT_SLICE, [3, 1])
        self.add_default_routes()
        self.create_pi_port_and_mirror_commands()

    def create_default_drop_acl(self):
        self.default_ipv4_drop_acl = self.device.create_acl(
            self.topology.ingress_acl_key_profile_ipv4_def,
            self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV4_DIP
        field.val.ipv4_dip.s_addr = IPV4_DIP.to_num()
        field.mask.ipv4_dip.s_addr = 0xffffffff
        key.append(field)

        command = self.create_drop_command()
        self.default_ipv4_drop_acl.append(key, command)

        self.default_ipv6_drop_acl = self.device.create_acl(
            self.topology.ingress_acl_key_profile_ipv6_def,
            self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV6_SIP
        sdk.set_ipv6_addr(field.val.ipv6_sip, 0, 0)
        sdk.set_ipv6_addr(field.mask.ipv6_sip, 0, 0)
        key.append(field)

        command = self.create_drop_command()
        self.default_ipv6_drop_acl.append(key, command)

    def add_default_routes(self):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = 0x0
        prefix.length = 0
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.topology.nh_l3_ac_def.hld_obj, PRIVATE_DATA_DEFAULT, False)

        self.ip_impl = ip_test_base.ipv6_test_base
        prefix = self.ip_impl.build_prefix(IPV6_DIP, length=0)
        self.topology.vrf.hld_obj.add_ipv6_route(prefix, self.topology.nh_l3_ac_def.hld_obj, PRIVATE_DATA_DEFAULT, False)

    def create_pi_port_and_mirror_commands(self):
        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            self.PUNT_INJECT_SLICE,
            PUNT_INJECT_IFG,
            PUNT_INJECT_SP_GID,
            PUNT_INJECT_SERDES_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        self.mirror_command1 = T.create_l2_mirror_command(self.device, MIRROR_CMD_GID1, self.pi_port, HOST_MAC_ADDR, PUNT_VLAN)
        self.mirror_command2 = T.create_l2_mirror_command(self.device, MIRROR_CMD_GID2, self.pi_port, HOST_MAC_ADDR, PUNT_VLAN)

    def create_drop_command(self):
        command = []
        drop_action = sdk.la_acl_command_action()
        drop_action.type = sdk.la_acl_action_type_e_DROP
        drop_action.data.drop = True
        command.append(drop_action)

        return command

    def create_force_l3_destination_command(self, l3_destination):
        command = []
        force_action = sdk.la_acl_command_action()
        force_action.type = sdk.la_acl_action_type_e_L3_DESTINATION
        force_action.data.l3_dest = l3_destination
        command.append(force_action)

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

    def create_counter_command(self, counter):
        command = []
        counter_cmd_action = sdk.la_acl_command_action()
        counter_cmd_action.type = sdk.la_acl_action_type_e_COUNTER
        counter_cmd_action.data.counter = counter
        command.append(counter_cmd_action)

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
        encap_exp_action.data.encap_exp = 1
        command.append(encap_exp_action)

        remark_group_action = sdk.la_acl_command_action()
        remark_group_action.type = sdk.la_acl_action_type_e_REMARK_GROUP
        remark_group_action.data.remark_group = 0
        command.append(remark_group_action)

        return command

    def create_ip_over_ip_tunnel_ports(self):
        self.ip_impl = ip_test_base.ipv4_test_base

        # VRF, Underlay Prefix
        tunnel_dest = self.ip_impl.build_prefix(LOCAL_IP, length=16)

        self.ip_over_ip_any_src_tunnel_port = T.ip_over_ip_tunnel_port(self, self.device,
                                                                       TUNNEL_PORT_GID,
                                                                       self.topology.vrf,
                                                                       tunnel_dest,
                                                                       ANY_IP,
                                                                       self.topology.vrf)

        self.ip_over_ip_any_src_tunnel_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        self.ip_over_ip_any_src_tunnel_port.hld_obj.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)
