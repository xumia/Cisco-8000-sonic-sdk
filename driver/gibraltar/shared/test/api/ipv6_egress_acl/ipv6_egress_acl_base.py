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
import ip_test_base
from packet_test_utils import *
import sim_utils
import topology as T
from scapy.all import *
from sdk_test_case_base import *

PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
SA = T.mac_addr('be:ef:5d:35:7a:35')

SIMPLE_QOS_COUNTER_OFFSET = 3
QOS_MARK_DSCP = 0x21


class ipv6_egress_acl_base(sdk_test_case_base):
    ip_impl_class = ip_test_base.ipv6_test_base

    SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

    TTL = 127

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL) / \
        TCP()

    EXPECTED_DEFAULT_OUTPUT_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL - 1) / \
        TCP()

    EXPECTED_SVI_OUTPUT_PACKET_BASE = \
        Ether(dst=T.NH_SVI_DEF_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL - 1) / \
        TCP()

    INPUT_PACKET, EXPECTED_DEFAULT_OUTPUT_PACKET = pad_input_and_output_packets(
        INPUT_PACKET_BASE, EXPECTED_DEFAULT_OUTPUT_PACKET_BASE)

    INPUT_PACKET, EXPECTED_DEFAULT_OUTPUT_PACKET_SVI = pad_input_and_output_packets(
        INPUT_PACKET_BASE, EXPECTED_SVI_OUTPUT_PACKET_BASE)

    def setUp(self):

        super().setUp()

        self.ip_impl = self.ip_impl_class()

        self.add_default_route()

    def add_default_route(self, is_svi=False):
        prefix = self.ip_impl.build_prefix(self.DIP, length=0)
        self.topology.vrf.hld_obj.add_ipv6_route(prefix, self.topology.nh_l3_ac_def.hld_obj if (
            is_svi is False) else self.topology.nh_svi_def.hld_obj, PRIVATE_DATA_DEFAULT, False)

    def delete_default_route(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=0)
        self.topology.vrf.hld_obj.delete_ipv6_route(prefix)

    def create_empty_acl(self):
        ''' Create empty ACL. '''
        acl0 = self.device.create_acl(self.topology.egress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl0, None)

        count = acl0.get_count()
        self.assertEqual(count, 0)

        return acl0

    def create_simple_sec_acl(self):
        ''' Create simple security ACL. '''
        acl1 = self.device.create_acl(self.topology.egress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl1, None)

        count = acl1.get_count()
        self.assertEqual(count, 0)

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV6_SIP
        q0 = sdk.get_ipv6_addr_q0(self.SIP.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(self.SIP.hld_obj)
        # Should not catch
        sdk.set_ipv6_addr(f1.val.ipv6_sip, q0 + 1, q1)
        sdk.set_ipv6_addr(f1.mask.ipv6_sip, 0xffffffffffffffff, 0xffffffffffffffff)
        k1.append(f1)

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_IPV6_DIP
        q0 = sdk.get_ipv6_addr_q0(self.DIP.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(self.DIP.hld_obj)
        # Will catch
        sdk.set_ipv6_addr(f2.val.ipv6_dip, q0 & 0xffffffffffff0000, q1)
        sdk.set_ipv6_addr(f2.mask.ipv6_dip, 0xffffffffffff0000, 0xffffffffffffffff)
        k2.append(f2)

        k3 = []
        f3 = sdk.la_acl_field()
        f3.type = sdk.la_acl_field_type_e_IPV6_DIP
        sdk.set_ipv6_addr(f3.val.ipv6_dip, q0, q1)
        sdk.set_ipv6_addr(f3.mask.ipv6_dip, 0xffffffffffffffff, 0xffffffffffffffff)
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

        return acl1

    def create_simple_sec_acl_group(self):
        acl1 = self.create_simple_sec_acl()

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [acl1])

        return acl_group

    def insert_drop_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in drop. '''

        k1 = []

        counter = self.device.create_counter(8)
        self.drop_counter = counter

        commands = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = True
        commands.append(action1)

        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_COUNTER
        action2.data.counter = counter
        commands.append(action2)

        count_pre = acl.get_count()
        acl.insert(0, k1, commands)

        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

    def insert_nop_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in NOP. '''

        k1 = []

        counter = self.device.create_counter(8)
        self.nop_counter = counter

        commands = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = False
        commands.append(action1)

        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_COUNTER
        action2.data.counter = counter
        commands.append(action2)

        count_pre = acl.get_count()
        acl.insert(0, k1, commands)
        count_post = acl.get_count()

        self.assertEqual(count_post, count_pre + 1)

    def trim_acl_invalid(self, acl):
        ''' Invalid removal from an ACL - expect failure. '''

        count = acl.get_count()

        try:
            acl.erase(count)
            self.assertFail()
        except sdk.BaseException:
            pass

        count_tag = acl.get_count()
        self.assertEqual(count, count_tag)

    def trim_acl(self, acl):
        ''' Remove the last ACE of the ACL.'''

        count = acl.get_count()
        acl.erase(count - 1)
        count_tag = acl.get_count()
        self.assertEqual(count_tag, count - 1)

    def do_test_route_default(self, is_svi=False):
        if (is_svi):
            run_and_compare(self, self.device,
                            self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                            self.EXPECTED_DEFAULT_OUTPUT_PACKET_SVI, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_SVI_DEF)
        else:
            run_and_compare(self, self.device,
                            self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                            self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

    def do_test_route_default_with_drop(self):
        run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_drop_acl(self, is_svi=False):
        if (is_svi):
            self.delete_default_route()
            self.add_default_route(is_svi)

        acl_group = self.create_simple_sec_acl_group()

        l3_port = self.topology.tx_svi.hld_obj if is_svi else self.topology.tx_l3_ac_def.hld_obj
        # Test default route
        self.do_test_route_default(is_svi)
        l3_port.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group)
        self.do_test_route_default(is_svi)

        # Add drop ACE
        drop_offset = 1
        acl1 = acl_group.get_acls(sdk.la_acl_packet_format_e_IPV6)[0]
        self.insert_drop_ace(acl1)
        l3_port.set_drop_counter_offset(sdk.la_stage_e_EGRESS, drop_offset)
        self.do_test_route_default_with_drop()

        # Check counter
        packet_count, byte_count = self.drop_counter.read(drop_offset, True, True)
        self.assertEqual(packet_count, 1)

        # Detach ACL
        l3_port.clear_acl_group(sdk.la_acl_direction_e_EGRESS)

        # Test default route
        self.do_test_route_default(is_svi)

    def _test_tcp_flags_ace(self):

        run_and_compare(self, self.device,
                        self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        acl_group = self.create_simple_sec_acl_group()
        acl1 = acl_group.get_acls(sdk.la_acl_packet_format_e_IPV6)[0]
        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group)

        k = []
        f = sdk.la_acl_field()
        f.type = sdk.la_acl_field_type_e_TCP_FLAGS
        in_packet = self.INPUT_PACKET.copy()
        in_packet[TCP].flags = "SA"
        f.val.tcp_flags.fields.syn = 1
        f.val.tcp_flags.fields.ack = 1
        f.mask.tcp_flags.flat = 0x3f
        k.append(f)

        counter = self.device.create_counter(8)

        commands = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = True
        commands.append(action1)

        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_COUNTER
        action2.data.counter = counter
        commands.append(action2)

        acl1.insert(0, k, commands)

        run_and_compare(self, self.device,
                        self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        run_and_drop(self, self.device, in_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Check counter
        packet_count, byte_count = counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

    def _test_multislice_acl(self):
        acl_group = self.create_simple_sec_acl_group()
        acl1 = acl_group.get_acls(sdk.la_acl_packet_format_e_IPV6)[0]
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

    def _test_nop_acl(self):
        acl_group = self.create_simple_sec_acl_group()
        acl1 = acl_group.get_acls(sdk.la_acl_packet_format_e_IPV6)[0]

        # Test default route
        self.do_test_route_default()
        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group)
        self.do_test_route_default()

        # Add drop ACE
        self.insert_drop_ace(acl1)
        self.do_test_route_default_with_drop()

        # Check counter
        packet_count, byte_count = self.drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        # Add NOP ACE
        self.insert_nop_ace(acl1)
        self.do_test_route_default()

        packet_count, byte_count = self.nop_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        # Detach ACL
        self.topology.tx_l3_ac_def.hld_obj.clear_acl_group(sdk.la_acl_direction_e_EGRESS)

        # Test default route
        self.do_test_route_default()

    def _test_route_default_and_acl(self):
        acl_group = self.create_simple_sec_acl_group()
        acl1 = acl_group.get_acls(sdk.la_acl_packet_format_e_IPV6)[0]

        # Test default route
        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group)
        self.do_test_route_default()

        # Detach ACL
        self.topology.tx_l3_ac_def.hld_obj.clear_acl_group(sdk.la_acl_direction_e_EGRESS)

        # Test default route
        self.do_test_route_default()

    def _test_route_default_delete_acl(self):
        acl_group = self.create_simple_sec_acl_group()
        acl1 = acl_group.get_acls(sdk.la_acl_packet_format_e_IPV6)[0]

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
        ''' Test default route after ACL delete. '''

        self.do_test_route_default()
        acl_group = self.create_simple_sec_acl_group()
        acl1 = acl_group.get_acls(sdk.la_acl_packet_format_e_IPV6)[0]
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
        return
       # Create two ACLs, add NOP to the first and DROP to the second. Attach the second to the port.

        acl_group1 = self.create_simple_sec_acl_group()
        acl1 = acl_group1.get_acls(sdk.la_acl_packet_format_e_IPV6)[0]
        acl_group2 = self.create_simple_sec_acl_group()
        acl2 = acl_group2.get_acls(sdk.la_acl_packet_format_e_IPV6)[0]

        # Test default route
        self.do_test_route_default()

        # Attach the second ACL
        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group2)

        # get the attached acl
        acl = self.topology.tx_l3_ac_def.hld_obj.get_acl_group(sdk.la_acl_direction_e_EGRESS)
        self.assertEqual(acl.this, acl_group2.this)

        self.do_test_route_default()

        # Add NOP ACE to the first ACL - should have no affect
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

        # get the attached acl
        acl = self.topology.tx_l3_ac_def.hld_obj.get_acl_group(sdk.la_acl_direction_e_EGRESS)

        self.assertEqual(acl.this, acl_group1.this)

        # Test default route (NOP)
        self.do_test_route_default()

        # Switch back to second ACL
        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group2)

        # get the attached acl
        acl = self.topology.tx_l3_ac_def.hld_obj.get_acl_group(sdk.la_acl_direction_e_EGRESS)

        self.assertEqual(acl.this, acl_group2.this)

        self.do_test_route_default_with_drop()

        # Check counter
        packet_count, byte_count = self.drop_counter.read(0, True, False)
        self.assertEqual(packet_count, 1)

        # Delete first ACL, should have no affect
        self.device.destroy(acl_group1)

        # get the attached acl
        acl = self.topology.tx_l3_ac_def.hld_obj.get_acl_group(sdk.la_acl_direction_e_EGRESS)

        self.assertEqual(acl.this, acl_group2.this)

        self.do_test_route_default_with_drop()

        # Check counter
        packet_count, byte_count = self.drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 2)

        # Detach ACL
        self.topology.tx_l3_ac_def.hld_obj.clear_acl_group(sdk.la_acl_direction_e_EGRESS)

        # get the attached acl
        acl = self.topology.tx_l3_ac_def.hld_obj.get_acl_group(sdk.la_acl_direction_e_EGRESS)

        self.assertEqual(acl, None)

        # Test default route
        self.do_test_route_default()
