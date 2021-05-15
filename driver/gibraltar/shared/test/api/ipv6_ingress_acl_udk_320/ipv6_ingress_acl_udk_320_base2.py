#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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


class udf_data:

    NUM_OF_SHORTS = 8
    BITS_IN_SHORT = 16
    BITS_IN_QWORD = 64

    def __init__(self, data_str):
        self.data_str = data_str
        self.hld_obj = sdk.la_acl_udf_data()
        q0 = self.to_num() & ((1 << udf_data.BITS_IN_QWORD) - 1)
        q1 = (self.to_num() >> udf_data.BITS_IN_QWORD) & ((1 << udf_data.BITS_IN_QWORD) - 1)
        sdk.set_udf_data(self.hld_obj, q0, q1)

    def to_num(self):
        shorts = self.data_str.split(':')
        assert(len(shorts) == udf_data.NUM_OF_SHORTS)
        c = udf_data.NUM_OF_SHORTS - 1
        n = 0
        for s in shorts:
            if len(s) > 0:
                sn = int(s, 16)
                n += (1 << udf_data.BITS_IN_SHORT) ** c * sn
            c -= 1

        return n


class ipv6_ingress_acl_udk_320_base2(sdk_test_case_base):
    ip_impl_class = ip_test_base.ipv6_test_base

    SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')
    INNER_PACKET_SIP = T.ipv6_addr('4444:0db8:0a0b:12f0:0000:0000:0000:4444')
    INNER_PACKET_DIP = T.ipv6_addr('3333:0db8:0a0b:12f0:0000:0000:0000:3333')

    TTL = 127

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL) / \
        TCP()

    INPUT_PACKET_WITH_EH_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL) / IPv6ExtHdrFragment() / \
        TCP()

    INPUT_PACKET_SVI_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL) / \
        TCP()

    EXPECTED_DEFAULT_OUTPUT_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL - 1) / \
        TCP()

    EXPECTED_EXTRA_OUTPUT_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL - 1) / \
        TCP()

    INPUT_PACKET_UDP_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL) / \
        UDP()

    # Outer IPv6, Inner IPv6 with TCP
    INPUT_IP_IN_IP_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL, nh=41) / \
        IPv6(src=INNER_PACKET_SIP.addr_str, dst=INNER_PACKET_DIP.addr_str, hlim=TTL, nh=6) / \
        TCP()

    EXPECTED_DEFAULT_OUTPUT_IP_IN_IP_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL - 1, nh=41) / \
        IPv6(src=INNER_PACKET_SIP.addr_str, dst=INNER_PACKET_DIP.addr_str, hlim=TTL, nh=6) / \
        TCP()

    EXPECTED_EXTRA_OUTPUT_IP_IN_IP_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL - 1, nh=41) / \
        IPv6(src=INNER_PACKET_SIP.addr_str, dst=INNER_PACKET_DIP.addr_str, hlim=TTL, nh=6) / \
        TCP()

    INPUT_PACKET_SVI, INPUT_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_SVI_BASE)
    INPUT_PACKET = add_payload(INPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_WITH_EH = add_payload(INPUT_PACKET_WITH_EH_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_DEFAULT_OUTPUT_PACKET = add_payload(EXPECTED_DEFAULT_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_EXTRA_OUTPUT_PACKET = add_payload(EXPECTED_EXTRA_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_UDP = add_payload(INPUT_PACKET_UDP_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_IP_IN_IP_PACKET = INPUT_IP_IN_IP_PACKET_BASE
    EXPECTED_DEFAULT_OUTPUT_IP_IN_IP_PACKET = EXPECTED_DEFAULT_OUTPUT_IP_IN_IP_PACKET_BASE
    EXPECTED_EXTRA_OUTPUT_IP_IN_IP_PACKET = EXPECTED_EXTRA_OUTPUT_IP_IN_IP_PACKET_BASE

    def setUp(self):
        super().setUp()
        self.ip_impl = self.ip_impl_class()
        self.create_acl_key_profile()
        self.add_default_route()
        self.inserted_drop_counter = None

    def create_acl_key_profile(self):
        self.device.destroy(self.topology.ingress_acl_key_profile_ipv6_def)
        udk = []
        udf1 = sdk.la_acl_field_def()
        udf1.type = sdk.la_acl_field_type_e_IPV6_SIP
        udk.append(udf1)
        # Inner IPv6 packet DIP
        udf13 = sdk.la_acl_field_def()
        udf13.type = sdk.la_acl_field_type_e_UDF
        udf13.udf_desc.index = 1
        udf13.udf_desc.protocol_layer = 0  # was 1
        udf13.udf_desc.header = 0
        udf13.udf_desc.offset = 64  # was 24
        udf13.udf_desc.width = 16
        udf13.udf_desc.is_relative = True
        udk.append(udf13)
        # Inner IPv6 packet Hop-Limit
        udf14 = sdk.la_acl_field_def()
        udf14.type = sdk.la_acl_field_type_e_UDF
        udf14.udf_desc.index = 2
        udf14.udf_desc.protocol_layer = 0  # was 1
        udf14.udf_desc.header = 0
        udf14.udf_desc.offset = 47  # was 7
        udf14.udf_desc.width = 1
        udf14.udf_desc.is_relative = True
        udk.append(udf14)
        # Inner IPv6 packet Dport
        udf16 = sdk.la_acl_field_def()
        udf16.type = sdk.la_acl_field_type_e_UDF
        udf16.udf_desc.index = 5
        udf16.udf_desc.protocol_layer = 0  # was 2
        udf16.udf_desc.header = 0
        udf16.udf_desc.offset = 82  # was 2
        udf16.udf_desc.width = 2
        udf16.udf_desc.is_relative = True
        udk.append(udf16)

        key_type = sdk.la_acl_key_type_e_IPV6
        direction = sdk.la_acl_direction_e_INGRESS
        tcam_pool_id = 0
        self.acl_key_profile_ipv6_320_udk = self.device.create_acl_key_profile(key_type, direction, udk, tcam_pool_id)

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
        acl1 = self.device.create_acl(self.acl_key_profile_ipv6_320_udk, self.topology.acl_command_profile_def)
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

        UDF = udf_data('3333:0db8:0a0b:12f0:0000:0000:0000:3333')
        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_UDF
        f2.udf_index = 1
        q0 = sdk.get_udf_data_q0(UDF.hld_obj)
        q1 = sdk.get_udf_data_q1(UDF.hld_obj)
        sdk.set_udf_data(f2.val.udf, q0 & 0xffffffffffff0000, q1)
        sdk.set_udf_data(f2.mask.udf, 0xffffffffffff0000, 0xffffffffffffffff)
        k2.append(f2)

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

        acl1.append(k1, commands1)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        acl1.append(k2, commands2)
        count = acl1.get_count()
        self.assertEqual(count, 2)

        acl_entry_desc = acl1.get(0)
        self.assertEqual(acl_entry_desc.key_val[0].type, k1[0].type)
        self.assertEqual(acl_entry_desc.key_val[0].val.ipv6_sip.q_addr[1], f1.val.ipv6_sip.q_addr[1])
        self.assertEqual(acl_entry_desc.key_val[0].val.ipv6_sip.q_addr[0], f1.val.ipv6_sip.q_addr[0])
        self.assertEqual(acl_entry_desc.key_val[0].mask.ipv6_sip.q_addr[1], f1.mask.ipv6_sip.q_addr[1])
        self.assertEqual(acl_entry_desc.key_val[0].mask.ipv6_sip.q_addr[0], f1.mask.ipv6_sip.q_addr[0])

        acl_entry_desc = acl1.get(1)
        self.assertEqual(acl_entry_desc.key_val[0].type, k2[0].type)
        self.assertEqual(acl_entry_desc.key_val[0].udf_index, k2[0].udf_index)
        self.assertEqual(acl_entry_desc.key_val[0].val.udf.q_data[1], f2.val.udf.q_data[1])
        self.assertEqual(acl_entry_desc.key_val[0].val.udf.q_data[0], f2.val.udf.q_data[0])
        self.assertEqual(acl_entry_desc.key_val[0].mask.udf.q_data[1], f2.mask.udf.q_data[1])
        self.assertEqual(acl_entry_desc.key_val[0].mask.udf.q_data[0], f2.mask.udf.q_data[0])
        self.assertEqual(acl_entry_desc.cmd_actions[0].type, action2.type)

        return acl1

    def insert_ace(self, acl, is_drop, is_punt, l3_dest):
        ''' Insert ACE that catch all traffic and result in drop if is_drop True. '''

        k1 = []
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
            action4 = sdk.la_acl_command_action()
            action4.type = sdk.la_acl_action_type_e_L3_DESTINATION
            action4.data.l3_dest = l3_dest
            commands.append(action4)
        else:
            counter = self.device.create_counter(8)
            action3 = sdk.la_acl_command_action()
            action3.type = sdk.la_acl_action_type_e_COUNTER
            action3.data.counter = counter
            commands.append(action3)
            self.inserted_drop_counter = counter

        count_pre = acl.get_count()
        acl.insert(0, k1, commands)

        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

    def insert_drop_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in drop. '''
        print(''' Insert ACE that catch all traffic and result in drop. ''')
        self.insert_ace(acl, True, False, None)

    def insert_punt_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in drop. '''
        self.insert_ace(acl, False, True, None)

    def insert_nop_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in NOP. '''
        self.insert_ace(acl, False, False, None)

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

    def do_test_route_default(self):
        run_and_compare(self, self.device,
                        self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

    def do_test_route_default_with_acl(self):
        run_and_compare(self, self.device,
                        self.INPUT_IP_IN_IP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        self.EXPECTED_EXTRA_OUTPUT_IP_IN_IP_PACKET, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT)

    def do_test_route_default_with_drop(self, is_svi=False):
        input_packet = self.INPUT_PACKET_SVI if is_svi else self.INPUT_PACKET
        run_and_drop(self, self.device, input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

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

        self.do_test_route_default_with_acl()
        run_and_drop(self, self.device, acl_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        acl.erase(0)
        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre)
