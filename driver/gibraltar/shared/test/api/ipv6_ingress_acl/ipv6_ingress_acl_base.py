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

SIMPLE_QOS_COUNTER_OFFSET = 2
QOS_MARK_DSCP = 0x13


class ipv6_ingress_acl_base(sdk_test_case_base):
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

    INPUT_PACKET_WITH_ICMP_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL, nh=0x3a) / \
        ICMP()

    INPUT_PACKET_WITH_EH_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL) / IPv6ExtHdrDestOpt() / \
        UDP()

    INPUT_PACKET_WITH_EH_AND_ICMP_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL) / IPv6ExtHdrDestOpt(nh=0x3a) / \
        ICMP()

    INPUT_PACKET_W_MULTIPLE_EH_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL) / IPv6ExtHdrDestOpt() / IPv6ExtHdrRouting() / TCP()

    INPUT_PACKET_W_TCP_EH_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL) / TCP()

    INPUT_PACKET_W_FRAG_EH_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL) / IPv6ExtHdrFragment()

    INPUT_PACKET_SVI_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL) / \
        TCP()

    INPUT_PACKET_RAW_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL, nh=0x2f) / GRE()

    EXPECTED_DEFAULT_OUTPUT_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL - 1) / \
        TCP()

    EXPECTED_EXTRA_OUTPUT_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL - 1) / \
        TCP()

    INPUT_PACKET_SVI, INPUT_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_SVI_BASE)
    INPUT_PACKET = add_payload(INPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_WITH_EH = add_payload(INPUT_PACKET_WITH_EH_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_W_MULTIPLE_EH = add_payload(INPUT_PACKET_W_MULTIPLE_EH_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_W_TCP_EH = add_payload(INPUT_PACKET_W_TCP_EH_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_W_FRAG_EH = add_payload(INPUT_PACKET_W_FRAG_EH_BASE, INPUT_PACKET_PAYLOAD_SIZE)

    INPUT_PACKET_WITH_ICMP = add_payload(INPUT_PACKET_WITH_ICMP_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_WITH_EH_AND_ICMP = add_payload(INPUT_PACKET_WITH_EH_AND_ICMP_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_RAW = add_payload(INPUT_PACKET_RAW_BASE, INPUT_PACKET_PAYLOAD_SIZE)

    EXPECTED_DEFAULT_OUTPUT_PACKET = add_payload(EXPECTED_DEFAULT_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_EXTRA_OUTPUT_PACKET = add_payload(EXPECTED_EXTRA_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)

    def setUp(self):
        super().setUp()
        self.ip_impl = self.ip_impl_class()
        self.add_default_route()

    def add_default_route(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=0)
        self.topology.vrf.hld_obj.add_ipv6_route(prefix, self.topology.nh_l3_ac_def.hld_obj, PRIVATE_DATA_DEFAULT, False)

    def create_empty_acl(self):
        ''' Create empty ACL. '''
        acl0 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl0, None)

        count = acl0.get_count()
        self.assertEqual(count, 0)

        return acl0

    def create_simple_sec_acl(self):
        ''' Create simple security ACL. '''
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)
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
        action2.type = sdk.la_acl_action_type_e_L3_DESTINATION
        action2.data.l3_dest = self.topology.fec_l3_ac_ext.hld_obj
        commands2.append(action2)

        commands3 = []
        action3 = sdk.la_acl_command_action()
        action3.type = sdk.la_acl_action_type_e_DROP
        action3.data.drop = True
        commands3.append(action3)

        counter = self.device.create_counter(8)
        action4 = sdk.la_acl_command_action()
        action4.type = sdk.la_acl_action_type_e_COUNTER
        action4.data.counter = counter
        commands3.append(action4)

        acl1.append(k1, commands1)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        acl1.append(k2, commands2)
        count = acl1.get_count()
        self.assertEqual(count, 2)

        acl1.append(k3, commands3)
        count = acl1.get_count()
        self.assertEqual(count, 3)

        return acl1

    def insert_ace(self, acl, is_drop, is_punt, l3_dest, position=0):
        ''' Insert ACE that catch all traffic and result in drop if is_drop True. '''

        k1 = []
        counter = self.device.create_counter(8)

        commands = []
        if (is_drop):
            action1 = sdk.la_acl_command_action()
            action1.type = sdk.la_acl_action_type_e_DROP
            action1.data.drop = is_drop
            commands.append(action1)

        if (is_punt):
            action2 = sdk.la_acl_command_action()
            action2.type = sdk.la_acl_action_type_e_PUNT
            action2.data.punt = is_punt
            commands.append(action2)

        if (l3_dest is not None):
            action3 = sdk.la_acl_command_action()
            action3.type = sdk.la_acl_action_type_e_L3_DESTINATION
            action3.data.l3_dest = l3_dest
            commands.append(action3)
        else:
            action4 = sdk.la_acl_command_action()
            action4.type = sdk.la_acl_action_type_e_COUNTER
            action4.data.counter = counter
            commands.append(action4)

        count_pre = acl.get_count()
        acl.insert(0, k1, commands)

        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

        return counter

    def insert_drop_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in drop. '''
        self.drop_counter = self.insert_ace(acl, True, False, None)

    def insert_punt_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in drop. '''
        self.punt_counter = self.insert_ace(acl, False, True, None)

    def insert_nop_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in NOP. '''
        self.nop_counter = self.insert_ace(acl, False, False, None)

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

    def update_simple_acl_to_default(self, acl):
        ''' Update the simple ACL to redirect to the default FEC. '''

        count = acl.get_count()

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_IPV6_DIP
        q0 = sdk.get_ipv6_addr_q0(self.DIP.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(self.DIP.hld_obj)
        sdk.set_ipv6_addr(f2.val.ipv6_dip, q0 & 0xffffffffffff0000, q1)
        sdk.set_ipv6_addr(f2.mask.ipv6_dip, 0xffffffffffff0000, 0xffffffffffffffff)
        k2.append(f2)

        commands = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_L3_DESTINATION
        action1.data.l3_dest = self.topology.fec_l3_ac_def.hld_obj
        commands.append(action1)

        acl.set(1, k2, commands)

        # No change in ACE count
        count_tag = acl.get_count()
        self.assertEqual(count_tag, count)

    def do_test_route_default(self):
        run_and_compare(self, self.device,
                        self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

    def do_test_route_default_with_acl(self):
        run_and_compare(self, self.device,
                        self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        self.EXPECTED_EXTRA_OUTPUT_PACKET, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT)

    def do_test_route_default_with_drop(self, is_svi=False):
        input_packet = self.INPUT_PACKET_SVI if is_svi else self.INPUT_PACKET
        run_and_drop(self, self.device, input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def create_simple_qos_acl(self):
        ''' Create simple QoS ACL. '''

        self.device.set_acl_scaled_enabled(False)
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)
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
        action2.type = sdk.la_acl_action_type_e_TRAFFIC_CLASS
        action2.data.traffic_class = 7
        commands2.append(action2)

        action3 = sdk.la_acl_command_action()
        action3.type = sdk.la_acl_action_type_e_COLOR
        action3.data.color = 3
        commands2.append(action3)

        action4 = sdk.la_acl_command_action()
        action4.type = sdk.la_acl_action_type_e_COUNTER_TYPE
        action4.data.counter_type = sdk.la_acl_counter_type_e_DO_QOS_COUNTING
        commands2.append(action4)

        action5 = sdk.la_acl_command_action()
        action5.type = sdk.la_acl_action_type_e_QOS_OR_METER_COUNTER_OFFSET
        action5.data.qos_offset = SIMPLE_QOS_COUNTER_OFFSET
        commands2.append(action5)

        action6 = sdk.la_acl_command_action()
        action6.type = sdk.la_acl_action_type_e_REMARK_FWD
        action6.data.remark_fwd = QOS_MARK_DSCP
        commands2.append(action6)

        action7 = sdk.la_acl_command_action()
        action7.type = sdk.la_acl_action_type_e_ENCAP_EXP
        action7.data.encap_exp = 0
        commands2.append(action7)

        action8 = sdk.la_acl_command_action()
        action8.type = sdk.la_acl_action_type_e_REMARK_GROUP
        action8.data.remark_group = 0
        commands2.append(action8)

        acl1.append(k1, commands1)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        acl1.append(k2, commands2)
        count = acl1.get_count()
        self.assertEqual(count, 2)

        return acl1

    def create_simple_unified_acl(self):
        ''' Create simple unified ACL. '''

        self.device.set_acl_scaled_enabled(False)
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)
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
        action2.type = sdk.la_acl_action_type_e_L3_DESTINATION
        action2.data.l3_dest = self.topology.nh_l3_ac_ext.hld_obj
        commands2.append(action2)

        action3 = sdk.la_acl_command_action()
        action3.type = sdk.la_acl_action_type_e_TRAFFIC_CLASS
        action3.data.traffic_class = 7
        commands2.append(action3)

        action4 = sdk.la_acl_command_action()
        action4.type = sdk.la_acl_action_type_e_COLOR
        action4.data.color = 3
        commands2.append(action4)

        action5 = sdk.la_acl_command_action()
        action5.type = sdk.la_acl_action_type_e_COUNTER_TYPE
        action5.data.counter_type = sdk.la_acl_counter_type_e_DO_QOS_COUNTING
        commands2.append(action5)

        action6 = sdk.la_acl_command_action()
        action6.type = sdk.la_acl_action_type_e_QOS_OR_METER_COUNTER_OFFSET
        action6.data.qos_offset = SIMPLE_QOS_COUNTER_OFFSET
        commands2.append(action6)

        action7 = sdk.la_acl_command_action()
        action7.type = sdk.la_acl_action_type_e_REMARK_FWD
        action7.data.remark_fwd = QOS_MARK_DSCP
        commands2.append(action7)

        action8 = sdk.la_acl_command_action()
        action8.type = sdk.la_acl_action_type_e_ENCAP_EXP
        action8.data.encap_exp = 0
        commands2.append(action8)

        action9 = sdk.la_acl_command_action()
        action9.type = sdk.la_acl_action_type_e_REMARK_GROUP
        action9.data.remark_group = 0
        commands2.append(action9)

        acl1.append(k1, commands1)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        acl1.append(k2, commands2)
        count = acl1.get_count()
        self.assertEqual(count, 2)

        return acl1

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

        run_and_drop(self, self.device, acl_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        acl.erase(0)
        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre)
