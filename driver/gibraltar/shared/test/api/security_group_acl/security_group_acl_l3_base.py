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

NUM_OF_DEFAULT_ENTRIES = 6
MAX_IPV4_SECURITY_GROUP_ACL_ENTRIES = 1512 - NUM_OF_DEFAULT_ENTRIES
MAX_IPV6_SECURITY_GROUP_ACL_ENTRIES = 1024 - NUM_OF_DEFAULT_ENTRIES

PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
TTL = 127
SPORT = 0x1234
DPORT = 0x2345
EXTRA_VRF_GID = 0x3ff
ECN = 0x3
DSCP = 0x5
MAX_COUNTER_OFFSET = 8

SA = T.mac_addr('be:ef:5d:35:7a:35')
# IPv4
SIP_V4 = T.ipv4_addr('192.193.194.195')
DIP_V4 = T.ipv4_addr('208.209.210.211')
IP_V4_MASK = T.ipv4_addr('255.255.255.255')
IP_V4_SUBNET_MASK = T.ipv4_addr('255.255.255.0')

# IPv6
SIP_V6 = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
DIP_V6 = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')
IP_V6_MASK = T.ipv6_addr('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
IP_V6_SUBNET_MASK = T.ipv6_addr('ffff:ffff:ffff:ffff:0000:0000:0000:0000')


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


class security_group_acl_l3_base(sdk_test_case_base.sdk_test_case_base):
    @staticmethod
    def device_config_func(device, state):
        device.set_int_property(sdk.la_device_property_e_SGACL_MAX_CELL_COUNTERS, 1024)

    @classmethod
    def setUpClass(cls):
        super(
            security_group_acl_l3_base,
            cls).setUpClass(
            slice_modes=sim_utils.STANDALONE_DEV,
            device_config_func=security_group_acl_l3_base.device_config_func)

    sgacl_key_profile = None

    def setUp(self):
        super().setUp()

        self.l3_port_impl = T.ip_l3_ac_base(self.topology)
        self.rx_port = self.l3_port_impl.rx_port
        self.device.set_trap_configuration(sdk.LA_EVENT_APP_SGACL_DROP, 0, None, None, False, False, True, 0)

        if self.monitor:
            self.command = command_type(command_type.MONITOR)
        elif self.drop:
            self.command = command_type(command_type.DROP)
        else:
            self.command = command_type(command_type.PERMIT)

        self.default_sgacl_counter = self.device.create_counter(2)
        self.sgacl_counter = self.device.create_counter(2)

        self.create_sgacl_key_profile()

    def verify_cell_counter(self):
        if self.command == command_type.PERMIT:
            packet_count, byte_count = self.sgacl_counter.read(0, True, True)
        else:
            packet_count, byte_count = self.sgacl_counter.read(1, True, True)

        self.assertEqual(packet_count, 1)

    def initialize_test_data(self):
        if self.is_ipv4:
            self.ip_impl = ip_test_base.ipv4_test_base
            self.scapy_IP = scapy.layers.inet.IP
            self.SECURITY_GROUP_ACL_FIELDS = ['ALL']
            self.ipvx = 'v4'
            self.SIP = SIP_V4
            self.DIP = DIP_V4
            self.IP_MASK = IP_V4_MASK
            self.IP_SUBNET_MASK = IP_V4_SUBNET_MASK
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
            self.prefix_sgt_em = self.source_host_prefix
            self.prefix_sgt_lpm = self.source_subnet_prefix
            self.prefix_dgt_em = self.destination_host_prefix
            self.prefix_dgt_lpm = self.destination_subnet_prefix
            self.default_prefix = sdk.la_ipv4_prefix_t()
            self.default_prefix.length = 0
        else:
            self.ip_impl = ip_test_base.ipv6_test_base
            self.scapy_IP = scapy.layers.inet6.IPv6
            self.SECURITY_GROUP_ACL_FIELDS = ['ALL']
            self.ipvx = 'v6'
            self.SIP = SIP_V6
            self.DIP = DIP_V6
            self.IP_MASK = IP_V6_MASK
            self.IP_SUBNET_MASK = IP_V6_SUBNET_MASK
            self.source_host_prefix = build_v6_prefix(self.SIP, 128)
            self.source_subnet_prefix = build_v6_prefix(self.SIP, 64)
            self.destination_host_prefix = build_v6_prefix(self.DIP, 128)
            self.destination_subnet_prefix = build_v6_prefix(self.DIP, 64)
            self.ip_version = sdk.la_ip_version_e_IPV6
            self.prefix_sgt_em = self.source_host_prefix
            self.prefix_sgt_lpm = self.source_subnet_prefix
            self.prefix_dgt_em = self.destination_host_prefix
            self.prefix_dgt_lpm = self.destination_subnet_prefix
            self.default_prefix = build_v6_prefix(self.SIP, 0)

        self.in_packet, self.out_packet = self.create_packets()
        self.per_field_counters = {}

    def test_run(self):
        self.run_test()

    def tearDown(self):
        super().tearDown()

    def create_sgacl_key_profile(self):
        key_type = sdk.la_acl_key_type_e_SGACL
        direction = sdk.la_acl_direction_e_INGRESS
        tcam_pool_id = 0
        security_group_acl_l3_base.sgacl_key_profile = self.device.create_acl_key_profile(
            key_type, direction, sdk.LA_ACL_KEY_SECURITY_GROUP, tcam_pool_id)

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_nh, PRIVATE_DATA_DEFAULT)

    def create_packets(self):
        rx_port_mac_str = T.mac_addr.mac_num_to_str(self.l3_port_impl.rx_port.hld_obj.get_mac().flat)
        tx_port_mac_str = T.mac_addr.mac_num_to_str(self.l3_port_impl.tx_port.hld_obj.get_mac().flat)
        nh_mac_str = self.l3_port_impl.reg_nh.mac_addr.addr_str
        vid1 = T.RX_L3_AC_PORT_VID1
        vid2 = T.RX_L3_AC_PORT_VID2

        if self.is_ipv4:
            INPUT_PACKET_BASE = \
                Ether(dst=rx_port_mac_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
                Dot1Q(vlan=vid1, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=vid2) / \
                IPvX(ipvx=self.ipvx,
                     src=self.SIP.addr_str,
                     dst=self.DIP.addr_str,
                     ttl=TTL,
                     dscp=DSCP, ecn=ECN,
                     flags=0x1, frag=0) / \
                TCP(sport=SPORT, dport=DPORT, flags="SA")

            EXPECTED_OUTPUT_PACKET_BASE = \
                Ether(dst=nh_mac_str, src=tx_port_mac_str) / \
                IPvX(ipvx=self.ipvx,
                     src=self.SIP.addr_str,
                     dst=self.DIP.addr_str,
                     ttl=TTL - 1,
                     dscp=DSCP, ecn=ECN,
                     flags=0x1, frag=0) / \
                TCP(sport=SPORT, dport=DPORT, flags="SA")
        else:
            INPUT_PACKET_BASE = \
                Ether(dst=rx_port_mac_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
                Dot1Q(vlan=vid1, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=vid2) / \
                IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=TTL, dscp=DSCP, ecn=ECN) / \
                IPv6ExtHdrFragment(offset=100) / \
                TCP(sport=SPORT, dport=DPORT, flags="SA")

            EXPECTED_OUTPUT_PACKET_BASE = \
                Ether(dst=nh_mac_str, src=tx_port_mac_str) / \
                IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=TTL - 1, dscp=DSCP, ecn=ECN) / \
                IPv6ExtHdrFragment(offset=100) / \
                TCP(sport=SPORT, dport=DPORT, flags="SA")

        INPUT_PACKET, INPUT_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_BASE)
        EXPECTED_OUTPUT_PACKET = add_payload(EXPECTED_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
        INPUT_PACKET = add_payload(INPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)

        return INPUT_PACKET, EXPECTED_OUTPUT_PACKET

    def run_test(self):
        self.initialize_test_data()
        self.add_default_route()
        self.create_packets()
        self.set_common_sgacl_settings()
        self.set_protocol_specific_sgacl_settings(self.command)

    def set_common_sgacl_settings(self):
        ''' Setting SDA mode.'''
        sda_mode = True
        self.device.set_sda_mode(sda_mode)
        read_sda_mode = self.device.get_sda_mode()
        self.assertEqual(sda_mode, read_sda_mode)

        ''' Set Default Port SGT:170(0xAA)'''
        sgt = 170
        self.topology.rx_eth_port.hld_obj.set_security_group_tag(sgt)
        read_sgt = self.topology.rx_eth_port.hld_obj.get_security_group_tag()
        self.assertEqual(sgt, read_sgt)

        # Add default entry in LPM
        self.topology.vrf.hld_obj.add_security_group_tag(self.default_prefix, 0)

        self.set_unknown_sgacl_policy()
        self.set_default_sgacl_policy()

    def set_protocol_specific_sgacl_settings(self, cmd_type):
        ''' Creating sgt/dgt cell and monitor mode.'''
        sgt = 100
        dgt = 101

        self.cell = self.device.create_security_group_cell(sgt, dgt, self.ip_version)
        self.device.destroy(self.cell)
        self.cell = self.device.create_security_group_cell(sgt, dgt, self.ip_version)

        if cmd_type == command_type.MONITOR:
            allow_drop = False
        else:
            allow_drop = True

        self.cell.set_monitor_mode(allow_drop)
        read_allow_drop = self.cell.get_monitor_mode()
        self.assertEqual(allow_drop, read_allow_drop)

        sgacl_command_profile_def = self.device.create_acl_command_profile(sdk.LA_SGACL_COMMAND)

        ''' Create SGACL. '''
        self.sgacl = self.device.create_acl(security_group_acl_l3_base.sgacl_key_profile, sgacl_command_profile_def)

        self.assertNotEqual(self.sgacl, None)
        count = self.sgacl.get_count()
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

        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_TTL
        f2.val.ttl = TTL
        f2.mask.ttl = 0xff

        k.append(f2)
        k_all.append(f2)

        f3 = sdk.la_acl_field()
        f3.type = sdk.la_acl_field_type_e_TCP_FLAGS
        f3.val.tcp_flags.fields.syn = 1
        f3.val.tcp_flags.fields.ack = 1
        f3.mask.tcp_flags.flat = 0x3f

        k.append(f3)
        k_all.append(f3)

        if self.is_ipv4:
            f4 = sdk.la_acl_field()
            f4.type = sdk.la_acl_field_type_e_IPV4_FLAGS
            f4.val.ipv4_flags.fragment = 0
            f4.mask.ipv4_flags.fragment = 0
        else:
            f4 = sdk.la_acl_field()
            f4.type = sdk.la_acl_field_type_e_IPV6_FRAGMENT
            f4.val.ipv6_fragment.fragment = 0
            f4.mask.ipv6_fragment.fragment = 0

        k.append(f4)
        k_all.append(f4)

        count_pre = self.sgacl.get_count()
        self.sgacl.insert(0, k, cmds)
        count_post = self.sgacl.get_count()
        self.assertEqual(count_post, count_pre + 1)

        ''' Set SGACL on the cell. '''
        self.cell.set_acl(self.sgacl)
        self.cell.clear_acl()
        self.cell.set_acl(self.sgacl)

        read_sgacl = self.cell.get_acl()
        self.cell.set_bincode(1)

        ''' Enable Enforecment on the DSP. '''
        enable = True
        self.tx_eth_port = self.topology.tx_l3_ac_eth_port_reg.hld_obj
        self.tx_eth_port.set_security_group_policy_enforcement(enable)
        read_enable = self.tx_eth_port.get_security_group_policy_enforcement()
        self.assertEqual(enable, read_enable)

        self.cell.set_counter(self.sgacl_counter)

        # Run (EM, EM) test
        self.run_test_combination(cmd_type, is_sgt_em=True, is_dgt_em=True, is_default_policy_run=True)
        # Run (LPM, LPM) test
        self.run_test_combination(cmd_type, is_sgt_em=False, is_dgt_em=False, is_default_policy_run=True)
        # Run (EM, LPM) test
        self.run_test_combination(cmd_type, is_sgt_em=True, is_dgt_em=False, is_default_policy_run=True)
        # Run (LPM, EM) test
        self.run_test_combination(cmd_type, is_sgt_em=False, is_dgt_em=True, is_default_policy_run=True)

        self.clear_sgacl_settings()

    def run_test_combination(self, cmd_type, is_sgt_em, is_dgt_em, is_default_policy_run=False):
        sgt = 100
        dgt = 101

        if is_sgt_em:
            self.prefix_sgt = self.prefix_sgt_em
        else:
            self.prefix_sgt = self.prefix_sgt_lpm

        self.topology.vrf.hld_obj.add_security_group_tag(self.prefix_sgt, sgt)
        read_sgt = self.topology.vrf.hld_obj.get_security_group_tag(self.prefix_sgt)
        self.assertEqual(sgt, read_sgt)

        if is_dgt_em:
            self.prefix_dgt = self.prefix_dgt_em
        else:
            self.prefix_dgt = self.prefix_dgt_lpm

        self.topology.vrf.hld_obj.add_security_group_tag(self.prefix_dgt, dgt)
        read_dgt = self.topology.vrf.hld_obj.get_security_group_tag(self.prefix_dgt)
        self.assertEqual(dgt, read_dgt)

        # send packet
        self.send_packets(cmd_type)

        self.verify_cell_counter()

        self.topology.vrf.hld_obj.delete_security_group_tag(self.prefix_sgt)
        self.topology.vrf.hld_obj.delete_security_group_tag(self.prefix_dgt)

        if is_default_policy_run:
            port_sgt = self.topology.rx_eth_port.hld_obj.get_security_group_tag()
            self.topology.rx_eth_port.hld_obj.set_security_group_tag(0)

            # (0,0)
            self.send_packets(command_type.DROP)

            # (sgt,*) test
            if is_sgt_em and is_dgt_em and self.is_ipv4:
                # On GB Hardware, for IPv6 and (sgt,*) with SGT in EM, sgt lookup result gets overwritten in NPL
                # And we derive sgt=0. Disabling this test till NPL fixes the issue.
                self.topology.vrf.hld_obj.add_security_group_tag(self.prefix_sgt, sgt)
                read_sgt = self.topology.vrf.hld_obj.get_security_group_tag(self.prefix_sgt)
                self.assertEqual(sgt, read_sgt)
                # send packet
                self.send_packets(command_type.PERMIT)
                self.topology.vrf.hld_obj.delete_security_group_tag(self.prefix_sgt)

            # (*,dgt) test
            self.topology.vrf.hld_obj.add_security_group_tag(self.prefix_dgt, dgt)
            read_sgt = self.topology.vrf.hld_obj.get_security_group_tag(self.prefix_dgt)
            self.assertEqual(dgt, read_sgt)
            # send packet
            self.send_packets(command_type.PERMIT)

            self.topology.vrf.hld_obj.delete_security_group_tag(self.prefix_dgt)

            # (*,*) test
            self.topology.vrf.hld_obj.add_security_group_tag(self.prefix_sgt, 0x777)
            read_sgt = self.topology.vrf.hld_obj.get_security_group_tag(self.prefix_sgt)
            self.assertEqual(0x777, read_sgt)
            self.topology.vrf.hld_obj.add_security_group_tag(self.prefix_dgt, 0x888)
            read_sgt = self.topology.vrf.hld_obj.get_security_group_tag(self.prefix_dgt)
            self.assertEqual(0x888, read_sgt)
            # send packet
            self.send_packets(command_type.PERMIT)

            self.topology.vrf.hld_obj.delete_security_group_tag(self.prefix_dgt)
            self.topology.vrf.hld_obj.delete_security_group_tag(self.prefix_sgt)

            # Add back port tag
            self.topology.rx_eth_port.hld_obj.set_security_group_tag(port_sgt)
            read_sgt = self.topology.rx_eth_port.hld_obj.get_security_group_tag()
            self.assertEqual(port_sgt, read_sgt)

    def set_unknown_sgacl_policy(self):
        sgacl_command_profile_def = self.device.create_acl_command_profile(sdk.LA_SGACL_COMMAND)
        self.unknown_sgacl = self.device.create_acl(security_group_acl_l3_base.sgacl_key_profile, sgacl_command_profile_def)

        # Add Unknown to Unknown Drop SGACL
        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_SGACL_BINCODE
        f1.val.sgacl_bincode = 0x0
        f1.mask.sgacl_bincode = 0x0
        k1.append(f1)

        cmd = []
        action = sdk.la_acl_command_action()
        action.type = sdk.la_acl_cmd_type_e_SGACL
        action.data.drop = True
        cmd.append(action)
        self.unknown_sgacl.append(k1, cmd)

        # Create (0,0) cell and set monitor mode
        unknown_sgt = 0
        unknown_dgt = 0
        self.unknown_cell = self.device.create_security_group_cell(unknown_sgt, unknown_dgt, self.ip_version)
        self.unknown_cell.set_monitor_mode(True)
        self.unknown_cell.set_bincode(0)

        ''' Set SGACL on the cell.'''
        self.unknown_cell.set_acl(self.unknown_sgacl)

    def set_default_sgacl_policy(self):
        sgacl_command_profile_def = self.device.create_acl_command_profile(sdk.LA_SGACL_COMMAND)
        self.default_sgacl = self.device.create_acl(security_group_acl_l3_base.sgacl_key_profile, sgacl_command_profile_def)

        # Add default Permit SGACL
        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_SGACL_BINCODE
        f1.val.sgacl_bincode = 0x0
        f1.mask.sgacl_bincode = 0x0
        k1.append(f1)

        default_cmd = []
        default_action = sdk.la_acl_command_action()
        default_action.type = sdk.la_acl_cmd_type_e_SGACL
        default_action.data.drop = False
        default_cmd.append(default_action)
        self.default_sgacl.append(k1, default_cmd)

        # Create (0xFFFF,0xFFFF) cell and set monitor mode
        default_sgt = 0xFFFF
        default_dgt = 0xFFFF
        self.default_cell = self.device.create_security_group_cell(default_sgt, default_dgt, self.ip_version)
        self.default_cell.set_monitor_mode(True)
        self.default_cell.set_bincode(0)

        ''' Set SGACL on the cell.'''
        self.default_cell.set_acl(self.default_sgacl)
        self.default_cell.set_counter(self.default_sgacl_counter)

    def clear_sgacl_settings(self):
        self.cell.set_counter(None)
        self.cell.clear_acl()
        self.device.destroy(self.sgacl)
        self.device.destroy(self.cell)
        self.unknown_cell.clear_acl()
        self.device.destroy(self.unknown_sgacl)
        self.device.destroy(self.unknown_cell)
        self.default_cell.clear_acl()
        self.device.destroy(self.default_sgacl)
        self.device.destroy(self.default_cell)

    def create_match_packet(self):
        packets = {}

        for f in self.SECURITY_GROUP_ACL_FIELDS:
            out_packet = self.out_packet.copy()
            p = self.in_packet.copy()

            out_packet[self.scapy_IP] = p[self.scapy_IP].copy()
            if self.is_ipv4:
                out_packet[self.scapy_IP].ttl = out_packet[self.scapy_IP].ttl - 1
            else:
                out_packet[self.scapy_IP].hlim = out_packet[self.scapy_IP].hlim - 1
            packets[f] = {'input': p, 'output': out_packet}

        return packets

    ########## Helper Methods ##########

    def send_packets(self, command):
        packets = self.create_match_packet()

        for f in self.SECURITY_GROUP_ACL_FIELDS:
            if command == command_type.DROP:
                run_and_drop(self, self.device, packets[f]['input'], T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
            else:
                run_and_compare(self, self.device,
                                packets[f]['input'], T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                packets[f]['output'], T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
