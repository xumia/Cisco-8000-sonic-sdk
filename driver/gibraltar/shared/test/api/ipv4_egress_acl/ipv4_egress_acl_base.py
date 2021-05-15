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

import unittest
from leaba import sdk
from packet_test_utils import *
import sim_utils
import topology as T
from scapy.all import *
from sdk_test_case_base import *
import nplapicli as nplapi
import smart_slices_choise as ssch

PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
SA = T.mac_addr('be:ef:5d:35:7a:35')

# IPv4
# 0xc0c1c2c3
SIP = T.ipv4_addr('192.193.194.195')
# 0xd0d1d2d3
DIP = T.ipv4_addr('208.209.210.211')

TTL = 127

INPUT_PACKET_BASE = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
    ICMP()

EXPECTED_DEFAULT_OUTPUT_PACKET_BASE = \
    Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1) / \
    ICMP()

INPUT_PACKET_TCP_BASE = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL, len=140) / \
    TCP(sport=0x1234, dport=0x2345)

EXPECTED_SVI_OUTPUT_PACKET_BASE = \
    Ether(dst=T.NH_SVI_DEF_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1) / \
    ICMP()
INPUT_PACKET, PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_BASE)
EXPECTED_DEFAULT_OUTPUT_PACKET = add_payload(EXPECTED_DEFAULT_OUTPUT_PACKET_BASE, PAYLOAD_SIZE)
INPUT_PACKET_TCP = add_payload(INPUT_PACKET_TCP_BASE, PAYLOAD_SIZE)
EXPECTED_DEFAULT_OUTPUT_PACKET_SVI = add_payload(EXPECTED_SVI_OUTPUT_PACKET_BASE, PAYLOAD_SIZE)

SIMPLE_QOS_COUNTER_OFFSET = 2
QOS_MARK_DSCP = 0x19

HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
PUNT_VLAN = 0xB13

PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"

MIRROR_CMD_GID = 0b01010
MIRROR_CMD_GID1 = 21
MIRROR_VLAN = 0xA12


class ipv4_egress_acl_base(sdk_test_case_base):
    INJECT_SLICE = T.get_device_slice(3)
    INJECT_IFG = 0
    INJECT_PIF_FIRST = T.get_device_first_serdes(8)
    INJECT_SP_GID = 20

    def setUp(self):
        super().setUp()
        ssch.rechoose_odd_inject_slice(self, self.device)

        self.add_default_route()
        # create_default_ipv4_egress_acl_key_profile
        self.drop_counter = None
        self.nop_counter = None
        self.punt_counter = None

    def add_default_route(self, is_svi=False):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = 0x0
        prefix.length = 0
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.topology.nh_l3_ac_def.hld_obj if (
            is_svi is False) else self.topology.nh_svi_def.hld_obj, PRIVATE_DATA_DEFAULT, False)

    def delete_default_route(self):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = 0x0
        prefix.length = 0
        self.topology.vrf.hld_obj.delete_ipv4_route(prefix)

    def create_empty_acl(self):
        ''' Create empty ACL. '''

        acl0 = self.device.create_acl(self.topology.egress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl0, None)

        count = acl0.get_count()
        self.assertEqual(count, 0)

        return acl0

    def create_simple_sec_acl(self):
        ''' Create simple security ACL. '''

        acl1 = self.device.create_acl(self.topology.egress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl1, None)

        count = acl1.get_count()
        self.assertEqual(count, 0)

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV4_SIP
        f1.val.ipv4_sip.s_addr = SIP.to_num() + 1  # should not catch
        f1.mask.ipv4_sip.s_addr = 0xffffffff
        k1.append(f1)

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_IPV4_DIP
        f2.val.ipv4_dip.s_addr = DIP.to_num() & 0xffffff00
        f2.mask.ipv4_dip.s_addr = 0xffffff00
        k2.append(f2)

        k3 = []
        f3 = sdk.la_acl_field()
        f3.type = sdk.la_acl_field_type_e_IPV4_DIP
        f3.val.ipv4_dip.s_addr = DIP.to_num()
        f3.mask.ipv4_dip.s_addr = 0xffffffff
        k3.append(f3)

        commands1 = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = False
        commands1.append(action1)

        commands2 = []
        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_DROP
        action2.data.drop = True
        commands2.append(action2)

        acl1.append(k1, commands1)

        count = acl1.get_count()
        self.assertEqual(count, 1)

        acl1.append(k2, commands1)

        count = acl1.get_count()
        self.assertEqual(count, 2)

        acl1.append(k3, commands2)

        count = acl1.get_count()
        self.assertEqual(count, 3)

        acl_entry_desc = acl1.get(0)
        self.assertEqual(acl_entry_desc.key_val[0].type, k1[0].type)
        self.assertEqual(acl_entry_desc.key_val[0].val.ipv4_sip.s_addr, k1[0].val.ipv4_sip.s_addr)
        self.assertEqual(acl_entry_desc.key_val[0].mask.ipv4_sip.s_addr, k1[0].mask.ipv4_sip.s_addr)
        self.assertEqual(acl_entry_desc.cmd_actions[0].type, commands1[0].type)
        self.assertEqual(acl_entry_desc.cmd_actions[0].data.drop, commands1[0].data.drop)

        acl_entry_desc = acl1.get(1)
        self.assertEqual(acl_entry_desc.key_val[0].type, k2[0].type)
        self.assertEqual(acl_entry_desc.key_val[0].val.ipv4_sip.s_addr, k2[0].val.ipv4_sip.s_addr)
        self.assertEqual(acl_entry_desc.key_val[0].mask.ipv4_sip.s_addr, k2[0].mask.ipv4_sip.s_addr)
        self.assertEqual(acl_entry_desc.cmd_actions[0].type, commands1[0].type)
        self.assertEqual(acl_entry_desc.cmd_actions[0].data.drop, commands1[0].data.drop)

        acl_entry_desc = acl1.get(2)
        self.assertEqual(acl_entry_desc.key_val[0].type, k3[0].type)
        self.assertEqual(acl_entry_desc.key_val[0].val.ipv4_sip.s_addr, k3[0].val.ipv4_sip.s_addr)
        self.assertEqual(acl_entry_desc.key_val[0].mask.ipv4_sip.s_addr, k3[0].mask.ipv4_sip.s_addr)
        self.assertEqual(acl_entry_desc.cmd_actions[0].type, commands2[0].type)
        self.assertEqual(acl_entry_desc.cmd_actions[0].data.drop, commands2[0].data.drop)

        return acl1

    def create_simple_sec_acl_group(self):
        acl1 = self.create_simple_sec_acl()

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1])

        return acl_group

    def insert_ace(self, acl, is_drop, is_punt=False, l3_dest=None, position=0):
        ''' Insert ACE that catch all traffic and result in drop if is_drop True. '''

        k1 = []

        commands = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = is_drop
        commands.append(action1)
        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_PUNT
        action2.data.punt = is_punt
        commands.append(action2)

        counter = self.device.create_counter(8)
        action3 = sdk.la_acl_command_action()
        action3.type = sdk.la_acl_action_type_e_COUNTER
        action3.data.counter = counter
        commands.append(action3)

        count_pre = acl.get_count()

        acl.insert(0, k1, commands)

        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

        return counter

    def insert_drop_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in drop.'''
        self.drop_counter = self.insert_ace(acl, True)

    def insert_nop_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in NOP. '''
        self.nop_counter = self.insert_ace(acl, False)

    def insert_punt_ace(self, acl):
        ''' Insert Punt ACE that catch all traffic and result in Punt.'''
        self.punt_counter = self.insert_ace(acl, False, True)

    def trim_acl_invalid(self, acl):
        ''' Invalid removal from an ACL - expect failure.'''

        count = acl.get_count()

        try:
            acl.erase(count)
            self.assertFail()
        except sdk.BaseException:
            pass

        count_tag = acl.get_count()
        self.assertEqual(count, count_tag)

    def remove_acl(self, acl, pos):
        ''' Remove arbitrary ACE from the ACL. '''

        count = acl.get_count()

        acl.erase(pos)
        count_tag = acl.get_count()
        self.assertEqual(count_tag, count - 1)

    def trim_acl(self, acl):
        ''' Remove the last ACE of the ACL. '''

        count = acl.get_count()

        acl.erase(count - 1)
        count_tag = acl.get_count()
        self.assertEqual(count_tag, count - 1)

    def do_test_route_default(self, is_svi=False):
        if (is_svi):
            run_and_compare(self, self.device,
                            INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                            EXPECTED_DEFAULT_OUTPUT_PACKET_SVI, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_SVI_DEF)
        else:
            run_and_compare(self, self.device,
                            INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                            EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

    def do_test_route_default_with_drop(self):
        run_and_drop(self, self.device, INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def verify_key_packet_acl(self, acl, acl_key, acl_packet):

        # Verify a specific packet is caught by the ACL key.
        # For every tuple of key-packet
        # 1. Add the ACE with the key to the ACL with drop action.
        # 2. Check that the default packet not dropped.
        # 3. Verify that the special packet is dropped.
        # 4. Remove the ACE from the ACL

        count_pre = acl.get_count()

        commands = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = True
        commands.append(action1)

        acl.insert(0, acl_key, commands)

        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

        self.do_test_route_default()
        run_and_drop(self, self.device, acl_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        acl.erase(0)

        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre)

    def _test_drop_acl(self, is_svi=False):

        if (is_svi):
            self.delete_default_route()
            self.add_default_route(is_svi)

        acl_group = self.create_simple_sec_acl_group()

        l3_port = self.topology.tx_svi.hld_obj if is_svi else self.topology.tx_l3_ac_def.hld_obj
        # Test default route
        drop_offset = 1
        self.do_test_route_default(is_svi)
        l3_port.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group)
        self.do_test_route_default(is_svi)

       # Add drop ACE
        acl1 = acl_group.get_acls(sdk.la_acl_packet_format_e_IPV4)[0]
        self.insert_drop_ace(acl1)
        l3_port.set_drop_counter_offset(sdk.la_stage_e_EGRESS, drop_offset)

        # Test dropped packet
        self.do_test_route_default_with_drop()

        # Check counter
        packet_count, byte_count = self.drop_counter.read(drop_offset, True, True)
        self.assertEqual(packet_count, 1)

        # Detach ACL
        l3_port.clear_acl_group(sdk.la_acl_direction_e_EGRESS)

        # Test default route
        self.do_test_route_default(is_svi)

    def _test_ipv4_fields_acl(self):
        acl_group = self.create_simple_sec_acl_group()

        # Test default route
        self.do_test_route_default()

        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group)
        self.do_test_route_default()

        # Create a list with special ACL key and modified packet that will be catched by the key
        acl1 = acl_group.get_acls(sdk.la_acl_packet_format_e_IPV4)[0]

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_PROTOCOL
        f1.val.protocol = 17
        f1.mask.protocol = 0xff
        k1.append(f1)
        in_packet = INPUT_PACKET.copy()
        in_packet[IP].proto = 17

        self.verify_key_packet_acl(acl1, k1, in_packet)

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_TTL
        f2.val.ttl = 32
        f2.mask.ttl = 0xff
        k2.append(f2)
        in_packet = INPUT_PACKET.copy()
        in_packet[IP].ttl = 33

        self.verify_key_packet_acl(acl1, k2, in_packet)

        k3 = []
        f3 = sdk.la_acl_field()
        f3.type = sdk.la_acl_field_type_e_IPV4_FLAGS
        f3.val.ipv4_flags.fragment = 0x1
        f3.mask.ipv4_flags.fragment = 0x1
        k3.append(f3)
        in_packet = INPUT_PACKET.copy()
        in_packet[IP].frag = 4

        self.verify_key_packet_acl(acl1, k3, in_packet)

        k4 = []
        f4 = sdk.la_acl_field()
        f4.type = sdk.la_acl_field_type_e_PROTOCOL
        in_packet = INPUT_PACKET_TCP.copy()
        f4.val.protocol = in_packet[IP].proto
        f4.mask.protocol = 0xff
        k4.append(f4)

        self.verify_key_packet_acl(acl1, k4, in_packet)

        k5 = []
        f5 = sdk.la_acl_field()
        f5.type = sdk.la_acl_field_type_e_TCP_FLAGS
        in_packet = INPUT_PACKET_TCP.copy()
        in_packet[TCP].flags = "SA"
        f5.val.tcp_flags.fields.syn = 1
        f5.val.tcp_flags.fields.ack = 1
        f5.mask.tcp_flags.flat = 0x3f
        k5.append(f5)

        self.verify_key_packet_acl(acl1, k5, in_packet)

        k6 = []
        f6 = sdk.la_acl_field()
        f6.type = sdk.la_acl_field_type_e_SPORT
        in_packet = INPUT_PACKET_TCP.copy()
        in_packet[TCP].sport = 0xab12
        f6.val.sport = in_packet[TCP].sport
        f6.mask.sport = 0xffff
        k6.append(f6)

        self.verify_key_packet_acl(acl1, k6, in_packet)

        k7 = []
        f7 = sdk.la_acl_field()
        f7.type = sdk.la_acl_field_type_e_DPORT
        in_packet = INPUT_PACKET_TCP.copy()
        in_packet[TCP].dport = 0xfa34
        f7.val.dport = in_packet[TCP].dport
        f7.mask.dport = 0xffff
        k7.append(f7)

        self.verify_key_packet_acl(acl1, k7, in_packet)

        # Detach ACL
        self.topology.tx_l3_ac_def.hld_obj.clear_acl_group(sdk.la_acl_direction_e_EGRESS)

        # Test default route
        self.do_test_route_default()

    def _test_multislice_acl(self):
        acl_group = self.create_simple_sec_acl_group()
        acl1 = acl_group.get_acls(sdk.la_acl_packet_format_e_IPV4)[0]
        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group)
        self.insert_nop_ace(acl1)

        # Apply on another slice
        self.topology.tx_l3_ac_reg.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group)
        self.do_test_route_default()
        self.insert_drop_ace(acl1)
        self.do_test_route_default_with_drop()

        # Check counter
        packet_count, byte_count = self.drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        # Remove and reapply on slice, while still applied to other
        self.topology.tx_l3_ac_def.hld_obj.clear_acl_group(sdk.la_acl_direction_e_EGRESS)

        self.do_test_route_default()
        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group)
        self.do_test_route_default_with_drop()

        # Check counter (not clearing)
        packet_count, byte_count = self.drop_counter.read(0, True, False)
        self.assertEqual(packet_count, 1)

        # Remove in other order
        self.topology.tx_l3_ac_reg.hld_obj.clear_acl_group(sdk.la_acl_direction_e_EGRESS)

        self.do_test_route_default_with_drop()

        # Check counter
        packet_count, byte_count = self.drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 2)

        self.topology.tx_l3_ac_def.hld_obj.clear_acl_group(sdk.la_acl_direction_e_EGRESS)

        self.do_test_route_default()

    def _test_nop_acl(self, is_svi=False):
        if (is_svi):
            self.delete_default_route()
            self.add_default_route(is_svi)

        acl_group = self.create_simple_sec_acl_group()
        acl1 = acl_group.get_acls(sdk.la_acl_packet_format_e_IPV4)[0]

        l3_port = self.topology.tx_svi.hld_obj if is_svi else self.topology.tx_l3_ac_def.hld_obj

        # Test default route
        self.do_test_route_default(is_svi)
        l3_port.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group)
        self.do_test_route_default(is_svi)

        # Add drop ACE
        self.insert_drop_ace(acl1)
        self.do_test_route_default_with_drop()

        # Check counter
        packet_count, byte_count = self.drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        # Add NOP ACE
        self.insert_nop_ace(acl1)
        self.do_test_route_default(is_svi)

        packet_count, byte_count = self.nop_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        # Detach ACL
        l3_port.clear_acl_group(sdk.la_acl_direction_e_EGRESS)

        # Test default route
        self.do_test_route_default(is_svi)

    def _test_route_default_and_acl(self):
        acl_group = self.create_simple_sec_acl_group()
        acl1 = acl_group.get_acls(sdk.la_acl_packet_format_e_IPV4)[0]

        # Test default route
        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group)
        self.do_test_route_default()

        # Detach ACL
        self.topology.tx_l3_ac_def.hld_obj.clear_acl_group(sdk.la_acl_direction_e_EGRESS)

        # Test default route
        self.do_test_route_default()

    def _test_route_default_delete_acl(self):
        acl_group = self.create_simple_sec_acl_group()
        acl1 = acl_group.get_acls(sdk.la_acl_packet_format_e_IPV4)[0]

        # Test default route
        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group)
        self.do_test_route_default()

        # Delete ACE
        self.trim_acl_invalid(acl1)
        self.trim_acl(acl1)

        # Test default route
        self.do_test_route_default()
        self.trim_acl(acl1)

        # Test default route
        self.do_test_route_default()

        # Detach ACL
        self.topology.tx_l3_ac_def.hld_obj.clear_acl_group(sdk.la_acl_direction_e_EGRESS)

    def _test_route_default_delete_all_acl(self):

        # Test default route
        self.do_test_route_default()
        acl_group = self.create_simple_sec_acl_group()
        acl1 = acl_group.get_acls(sdk.la_acl_packet_format_e_IPV4)[0]
        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group)

        self.do_test_route_default()

        # Delete ALL ACEs
        acl1.clear()
        count = acl1.get_count()
        self.assertEqual(count, 0)

        # Test default route
        self.do_test_route_default()

        # Detach ACL
        self.topology.tx_l3_ac_def.hld_obj.clear_acl_group(sdk.la_acl_direction_e_EGRESS)

    def _test_two_acls(self):
       # Create two ACLs, add NOP to the first and DROP to the second. Attach the second to the port.

        acl_group1 = self.create_simple_sec_acl_group()
        acl1 = acl_group1.get_acls(sdk.la_acl_packet_format_e_IPV4)[0]
        acl_group2 = self.create_simple_sec_acl_group()
        acl2 = acl_group2.get_acls(sdk.la_acl_packet_format_e_IPV4)[0]

        # Test default route
        self.do_test_route_default()

        # Attach the second ACL
        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group2)

        # get the attached acl
        acl = self.topology.tx_l3_ac_def.hld_obj.get_acl_group(sdk.la_acl_direction_e_EGRESS)
        self.assertEqual(acl.this, acl_group2.this)

        self.do_test_route_default()

        # Add NOP ACE to the first ACL - should have no effect
        self.insert_nop_ace(acl1)
        self.do_test_route_default()

        # Add drop ACE to the second ACL
        self.insert_drop_ace(acl2)
        self.do_test_route_default_with_drop()

        # Check counter
        packet_count, byte_count = self.drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        # Switch to use first ACL
        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group1)

        # Execute a get on the acl
        acl = self.topology.tx_l3_ac_def.hld_obj.get_acl_group(sdk.la_acl_direction_e_EGRESS)

        self.assertEqual(acl.this, acl_group1.this)

        # Test default route (NOP)
        self.do_test_route_default()

        # Switch back to second ACL
        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group2)

        # Execute a get on the acl
        acl = self.topology.tx_l3_ac_def.hld_obj.get_acl_group(sdk.la_acl_direction_e_EGRESS)

        self.assertEqual(acl.this, acl_group2.this)

        self.do_test_route_default_with_drop()

        # Check counter
        packet_count, byte_count = self.drop_counter.read(0, True, False)
        self.assertEqual(packet_count, 1)

        # Delete first ACL, should have no affect
        self.device.destroy(acl_group1)

        # Execute a get on the acl
        acl = self.topology.tx_l3_ac_def.hld_obj.get_acl_group(sdk.la_acl_direction_e_EGRESS)

        self.assertEqual(acl.this, acl_group2.this)

        self.do_test_route_default_with_drop()

        # Check counter
        packet_count, byte_count = self.drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 2)

        # Detach ACL
        self.topology.tx_l3_ac_def.hld_obj.clear_acl_group(sdk.la_acl_direction_e_EGRESS)

        # Execute a get on the acl
        acl = self.topology.tx_l3_ac_def.hld_obj.get_acl_group(sdk.la_acl_direction_e_EGRESS)

        self.assertEqual(acl, None)

        # Test default route
        self.do_test_route_default()

    def _test_punt_acl(self):

        acl_group = self.create_simple_sec_acl_group()
        acl1 = acl_group.get_acls(sdk.la_acl_packet_format_e_IPV4)[0]

        # Test default route
        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group)
        self.do_test_route_default()

        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        punt_dest = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN)

        self.device.set_trap_configuration(
            sdk.LA_EVENT_L3_ACL_FORCE_PUNT,
            0,
            None,
            punt_dest,
            False,
            False,
            True, 0)

        # Add punt ACE
        self.insert_punt_ace(acl1)

        # Test punted packet
        punt_packet_base = Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
                 next_header_offset=0,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_EGRESS_ACL,
                 code=nplapi.NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT,
                 source_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 destination_sp=T.TX_L3_AC_SYS_PORT_DEF_GID,
                 source_lp=T.RX_L3_AC_GID,
                 destination_lp=T.TX_L3_AC_DEF_GID,
                 relay_id=T.VRF_GID, lpts_flow_type=0
                 ) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1, len=140) / \
            TCP(sport=0x1234, dport=0x2345)

        punt_packet = add_payload(punt_packet_base, PAYLOAD_SIZE)

        # punt packet has TTL-1 but the checksum is still TTL's checksum
        # get ip check from scapy
        in_ip = INPUT_PACKET_TCP[IP].build()
        in_ip = IP(in_ip)
        # put ip checksum from input packet to the output packet
        punt_packet[IP].chksum = in_ip.chksum
        run_and_compare(self, self.device,
                        INPUT_PACKET_TCP, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        punt_packet, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)

        # Check counter
        packet_count, byte_count = self.punt_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        # Detach ACL
        self.topology.tx_l3_ac_def.hld_obj.clear_acl_group(sdk.la_acl_direction_e_EGRESS)

        # Test default route
        self.do_test_route_default()
