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

from enum import Enum
import sdk_test_case_base
import unittest
from leaba import sdk
from packet_test_utils import *
import sim_utils
import topology as T
from scapy.all import *
import ip_test_base
import decor

CHAR_BIT = 8
BYTES_NUM_IN_ADDR = 16

TTL = 127
SPORT = 0x1234
DPORT = 0x2345
ECN = 0x3
DSCP = 0x5

# IPv4
SIP_V4 = T.ipv4_addr('192.193.194.195')
DIP_V4 = T.ipv4_addr('208.209.210.211')

# IPv6
SIP_V6 = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
DIP_V6 = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')


class command_type(Enum):
    NOP = 0
    PERMIT = 1
    DROP = 2
    MONITOR = 3


NUM_OF_SHORTS = 8
BITS_IN_SHORT = 16
BITS_IN_QWORD = 64
NUM_OF_BYTES = 16


def apply_v6_prefix_mask(q0, q1, prefix_length):
    dqw_addr = q1 << 64 | q0
    mask = ~((1 << (CHAR_BIT * BYTES_NUM_IN_ADDR - prefix_length)) - 1)
    dqw_addr = dqw_addr & mask
    masked_q0 = dqw_addr & ((1 << 64) - 1)
    masked_q1 = dqw_addr >> 64
    return masked_q0, masked_q1


def build_v6_prefix(dip, length):
    prefix = sdk.la_ipv6_prefix_t()
    q0 = sdk.get_ipv6_addr_q0(dip.hld_obj)
    q1 = sdk.get_ipv6_addr_q1(dip.hld_obj)
    masked_q0, masked_q1 = apply_v6_prefix_mask(q0, q1, length)
    sdk.set_ipv6_addr(prefix.addr, masked_q0, masked_q1)
    prefix.length = length
    return prefix


class security_group_acl_l2_base(sdk_test_case_base.sdk_test_case_base):

    @staticmethod
    def device_config_func(device, state):
        device.set_int_property(sdk.la_device_property_e_SGACL_MAX_CELL_COUNTERS, 1024)

    @classmethod
    def setUpClass(cls):
        super(
            security_group_acl_l2_base,
            cls).setUpClass(
            slice_modes=sim_utils.STANDALONE_DEV,
            device_config_func=security_group_acl_l2_base.device_config_func)

    IN_SLICE = 5
    IN_IFG = 0
    IN_SERDES_FIRST = 4
    IN_SERDES_LAST = IN_SERDES_FIRST + 1
    OUT_SLICE = 4
    OUT_IFG = 1
    OUT_SERDES_FIRST = 8
    OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

    SYS_PORT_GID_BASE = 23
    AC_PORT_GID_BASE = 10

    SWITCH_GID = 100
    VRF_GID = 100

    SRC_MAC = "de:ad:de:ad:de:ad"
    UCAST_MAC = "ca:fe:ca:fe:ca:fe"
    MCAST_MAC = '01:00:5e:00:00:01'
    BCAST_MAC = 'ff:ff:ff:ff:ff:ff'
    VLAN = 0xAB9

    AGE_INTERVAL = 2

    def setUp(self):
        super().setUp(create_default_topology=False)
        self.IN_SLICE = T.choose_active_slices(self.device, self.IN_SLICE, [0, 1, 2])
        self.OUT_SLICE = T.choose_active_slices(self.device, self.OUT_SLICE, [2, 4])
        self.topology.create_inject_ports()
        self._add_objects_to_keep()
        self.create_topology()
        self.device.set_trap_configuration(sdk.LA_EVENT_APP_SGACL_DROP, 0, None, None, False, False, True, 0)

        if self.monitor:
            self.command = command_type(command_type.MONITOR)
        elif self.drop:
            self.command = command_type(command_type.DROP)
        else:
            self.command = command_type(command_type.PERMIT)

        self.sgacl_key_profile = self.device.create_acl_key_profile(
            sdk.la_acl_key_type_e_SGACL, sdk.la_acl_direction_e_INGRESS, sdk.LA_ACL_KEY_SECURITY_GROUP, 0)
        self.sgacl_v4_command_profile = self.device.create_acl_command_profile(sdk.LA_SGACL_COMMAND)
        self.sgacl_v6_command_profile = self.device.create_acl_command_profile(sdk.LA_SGACL_COMMAND)

        self.sgacl_counter = self.device.create_counter(2)

    def verify_cell_counter(self):
        if self.command == command_type.PERMIT:
            packet_count, byte_count = self.sgacl_counter.read(0, True, True)
        else:
            packet_count, byte_count = self.sgacl_counter.read(1, True, True)

        self.assertEqual(packet_count, 1)

    def create_topology(self):
        self.sw1 = T.switch(self, self.device, self.SWITCH_GID)
        self.ac_profile = T.ac_profile(self, self.device)

        self.eth_port1 = T.ethernet_port(
            self,
            self.device,
            self.IN_SLICE,
            self.IN_IFG,
            self.SYS_PORT_GID_BASE,
            self.IN_SERDES_FIRST,
            self.IN_SERDES_LAST)
        self.eth_port1.set_ac_profile(self.ac_profile)
        self.ac_port1 = T.l2_ac_port(
            self,
            self.device,
            self.AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port1,
            None,
            self.VLAN,
            0x0)

        self.eth_port2 = T.ethernet_port(
            self,
            self.device,
            self.OUT_SLICE,
            self.OUT_IFG,
            self.SYS_PORT_GID_BASE + 1,
            self.OUT_SERDES_FIRST,
            self.OUT_SERDES_LAST)
        self.eth_port2.set_ac_profile(self.ac_profile)
        self.ac_port2 = T.l2_ac_port(
            self,
            self.device,
            self.AC_PORT_GID_BASE + 1,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port2,
            None,
            self.VLAN,
            0x0)

    def initialize_test_data(self):
        if self.is_ipv4:
            self.ipvx = 'v4'
            self.SIP = SIP_V4
            self.DIP = DIP_V4
            self.source_host_prefix = sdk.la_ipv4_prefix_t()
            self.source_host_prefix.addr.s_addr = self.SIP.to_num()
            self.source_host_prefix.length = 32
            self.source_subnet_prefix = sdk.la_ipv4_prefix_t()
            self.source_subnet_prefix.length = 24
            self.source_subnet_prefix.addr.s_addr = self.SIP.to_num() & 0xffffff00
            self.destination_host_prefix = sdk.la_ipv4_prefix_t()
            self.destination_host_prefix.addr.s_addr = self.DIP.to_num()
            self.destination_host_prefix.length = 32
            self.destination_subnet_prefix = sdk.la_ipv4_prefix_t()
            self.destination_subnet_prefix.length = 24
            self.destination_subnet_prefix.addr.s_addr = self.DIP.to_num() & 0xffffff00
            self.ip_version = sdk.la_ip_version_e_IPV4
            self.sgacl_command_profile = self.sgacl_v4_command_profile
        else:
            self.ipvx = 'v6'
            self.SIP = SIP_V6
            self.DIP = DIP_V6
            self.source_host_prefix = build_v6_prefix(self.SIP, 128)
            self.source_subnet_prefix = build_v6_prefix(self.SIP, 64)
            self.destination_host_prefix = build_v6_prefix(self.DIP, 128)
            self.destination_subnet_prefix = build_v6_prefix(self.DIP, 64)
            self.ip_version = sdk.la_ip_version_e_IPV6
            self.sgacl_command_profile = self.sgacl_v6_command_profile

        self.g_vrf = self.device.create_vrf(0)

    def install_mac(self, dst_mac):
        self.mac = T.mac_addr(dst_mac)
        self.sw1.hld_obj.set_mac_entry(self.mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

    def create_packets(self, src_mac, dest_mac, vlan):
        INPUT_PACKET_BASE = \
            Ether(dst=dest_mac, src=src_mac, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=vlan) / \
            IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=TTL, dscp=DSCP, ecn=ECN) / \
            TCP(sport=SPORT, dport=DPORT)

        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=dest_mac, src=src_mac, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=vlan) / \
            IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=TTL, dscp=DSCP, ecn=ECN) / \
            TCP(sport=SPORT, dport=DPORT)

        INPUT_PACKET, INPUT_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_BASE)
        EXPECTED_OUTPUT_PACKET = add_payload(EXPECTED_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
        INPUT_PACKET = add_payload(INPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)

        return INPUT_PACKET, EXPECTED_OUTPUT_PACKET

    def test_l2_sgacl_v4(self):
        self.is_ipv4 = True
        self.run_test()

    def test_l2_sgacl_v6(self):
        self.is_ipv4 = False
        self.run_test()

    def tearDown(self):
        super().tearDown()

    def run_test(self):
        self.initialize_test_data()
        self.install_mac(self.UCAST_MAC)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.UCAST_MAC, self.VLAN)
        self.set_common_sgacl_settings()
        self.set_protocol_specific_sgacl_settings(self.command)

    def set_common_sgacl_settings(self):
        ''' Setting SDA mode.'''
        sda_mode = True
        self.device.set_sda_mode(sda_mode)
        read_sda_mode = self.device.get_sda_mode()
        self.assertEqual(sda_mode, read_sda_mode)

        ''' Set enforecement on switch '''
        enforcement = True
        self.sw1.hld_obj.set_security_group_policy_enforcement(enforcement)
        read_enforcement = self.sw1.hld_obj.get_security_group_policy_enforcement()
        self.assertEqual(enforcement, read_enforcement)

        ''' Set Default Port SGT:170(0xAA)'''
        sgt = 170
        self.rx_eth_port = self.eth_port1
        self.rx_eth_port.hld_obj.set_security_group_tag(sgt)
        read_sgt = self.rx_eth_port.hld_obj.get_security_group_tag()
        self.assertEqual(sgt, read_sgt)

    def set_protocol_specific_sgacl_settings(self, cmd_type):
        ''' Configuring src-ip SGT Mapping EM:100(0x64), LPM 187(0xBB)'''
        sgt = 100
        prefix = self.source_host_prefix
        self.g_vrf.add_security_group_tag(prefix, sgt)
        read_sgt = self.g_vrf.get_security_group_tag(prefix)
        self.assertEqual(sgt, read_sgt)

        ''' Configuring dst-ip SGT Mapping EM:204(0xCC), LPM:101(0x65)'''
        sgt = 101
        prefix = self.destination_host_prefix
        self.g_vrf.add_security_group_tag(prefix, sgt)
        read_sgt = self.g_vrf.get_security_group_tag(prefix)
        self.assertEqual(sgt, read_sgt)

        ''' Creating sgt/dgt cell and monitor mode.'''
        sgt = 100
        dgt = 101
        cell = self.device.create_security_group_cell(sgt, dgt, self.ip_version)

        if cmd_type == command_type.MONITOR:
            allow_drop = False
        else:
            allow_drop = True

        cell.set_monitor_mode(allow_drop)
        read_allow_drop = cell.get_monitor_mode()
        self.assertEqual(allow_drop, read_allow_drop)

        ''' Create SGACL. '''
        sgacl = self.device.create_acl(self.sgacl_key_profile, self.sgacl_command_profile)

        self.assertNotEqual(sgacl, None)
        count = sgacl.get_count()
        self.assertEqual(count, 0)

        ''' Add ace to SGACL. '''
        cmds = []
        action = sdk.la_acl_command_action()
        action.type = sdk.la_acl_cmd_type_e_SGACL
        if cmd_type == command_type.PERMIT:
            action.data.drop = False
        else:
            action.data.drop = True
        cmds.append(action)

        k = []
        k_all = []
        f = sdk.la_acl_field()

        f.type = sdk.la_acl_field_type_e_PROTOCOL
        f.val.protocol = sdk.la_l4_protocol_e_TCP
        f.mask.protocol = 0xff
        k.append(f)
        k_all.append(f)

        f.type = sdk.la_acl_field_type_e_SGACL_BINCODE
        f.val.sgacl_bincode = 0x1
        f.mask.sgacl_bincode = 0x1
        k.append(f)
        k_all.append(f)

        count_pre = sgacl.get_count()
        sgacl.insert(0, k, cmds)
        count_post = sgacl.get_count()
        self.assertEqual(count_post, count_pre + 1)

        ''' Set SGACL on the cell. '''
        cell.set_acl(sgacl)
        cell.set_bincode(1)

        ''' Enable Enforecment on the DSP. '''
        enable = True
        self.tx_eth_port = self.eth_port2
        self.tx_eth_port.hld_obj.set_security_group_policy_enforcement(enable)
        read_enable = self.tx_eth_port.hld_obj.get_security_group_policy_enforcement()
        self.assertEqual(enable, read_enable)

        ''' Attach counter to cell '''
        cell.set_counter(self.sgacl_counter)

        # Send Packet
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.UCAST_MAC, self.VLAN)
        if self.command == command_type.DROP:
            self.run_and_drop(in_packet, out_packet)
        else:
            self.run_and_compare(in_packet, out_packet)

        self.verify_cell_counter()

        cell.clear_acl()
        self.device.destroy(sgacl)
        cell.set_counter(None)
        self.device.destroy(cell)

    def run_and_compare(self, in_packet, out_packet):
        run_and_compare(
            self,
            self.device,
            in_packet,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            out_packet,
            self.OUT_SLICE,
            self.OUT_IFG,
            self.OUT_SERDES_FIRST)

    def run_and_drop(self, in_packet, out_packet):
        run_and_drop(
            self,
            self.device,
            in_packet,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST)
