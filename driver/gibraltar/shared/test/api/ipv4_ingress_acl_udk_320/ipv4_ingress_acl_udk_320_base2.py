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
from packet_test_utils import *
import sim_utils
import topology as T
from scapy.all import *
from binascii import hexlify, unhexlify
from sdk_test_case_base import *

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
#    UDP(sport=0x1234, dport=0x2345)

EXPECTED_DEFAULT_OUTPUT_PACKET_BASE = \
    Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1) / \
    ICMP()
#    UDP(sport=0x1234, dport=0x2345)

EXPECTED_EXTRA_OUTPUT_PACKET_BASE = \
    Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1) / \
    ICMP()
#    UDP(sport=0x1234, dport=0x2345)

INPUT_PACKET_TCP_BASE = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
    TCP(sport=0x1234, dport=0x2345)

INPUT_PACKET_WITH_PAYLOAD = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
    Raw(load=unhexlify('22220db80a0b12f00000000000002222'))

REMOTE_IP = T.ipv4_addr('12.10.12.10')
LOCAL_IP = T.ipv4_addr('192.168.95.250')
TUNNEL_TTL = 255

INPUT_IP_IN_IP_PACKET_BASE = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=REMOTE_IP.addr_str, dst=LOCAL_IP.addr_str, ttl=TUNNEL_TTL) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
    TCP()

EXPECTED_IP_IN_IP_OUTPUT_PACKET_BASE = \
    Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1)

INPUT_PACKET, INPUT_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_BASE)
EXPECTED_DEFAULT_OUTPUT_PACKET = add_payload(EXPECTED_DEFAULT_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
EXPECTED_EXTRA_OUTPUT_PACKET = add_payload(EXPECTED_EXTRA_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
INPUT_PACKET_TCP = add_payload(INPUT_PACKET_TCP_BASE, INPUT_PACKET_PAYLOAD_SIZE)
INPUT_IP_IN_IP_PACKET, PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_IP_IN_IP_PACKET_BASE)
EXPECTED_IP_IN_IP_OUTPUT_PACKET = add_payload(EXPECTED_IP_IN_IP_OUTPUT_PACKET_BASE, PAYLOAD_SIZE)

SIMPLE_QOS_COUNTER_OFFSET = 2
QOS_MARK_DSCP = 0x18


class ipv4_ingress_acl_udk_320_base2(sdk_test_case_base):
    acl_key_profile_ipv4_320_udk = None

    @staticmethod
    def populate_udf(udf, index, protocol_layer, header, offset, width, is_relative):
        udf.type = sdk.la_acl_field_type_e_UDF
        udf.udf_desc.index = index
        udf.udf_desc.protocol_layer = protocol_layer
        udf.udf_desc.header = header
        udf.udf_desc.offset = offset
        udf.udf_desc.width = width
        udf.udf_desc.is_relative = is_relative

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            udk = []
            udf1 = sdk.la_acl_field_def()
            udf1.type = sdk.la_acl_field_type_e_IPV4_SIP
            udk.append(udf1)
            udf2 = sdk.la_acl_field_def()
            udf2.type = sdk.la_acl_field_type_e_IPV4_DIP
            udk.append(udf2)
            udf3 = sdk.la_acl_field_def()
            udf3.type = sdk.la_acl_field_type_e_PROTOCOL
            udk.append(udf3)
            udf4 = sdk.la_acl_field_def()
            udf4.type = sdk.la_acl_field_type_e_TTL
            udk.append(udf4)
            # Inner IPv4 packet SIP
            udf5 = sdk.la_acl_field_def()
            ipv4_ingress_acl_udk_320_base2.populate_udf(udf5, 1, 1, 0, 12, 4, True)
            udk.append(udf5)
            # Inner IPv4 packet DIP
            udf6 = sdk.la_acl_field_def()
            ipv4_ingress_acl_udk_320_base2.populate_udf(udf6, 2, 1, 0, 16, 4, True)
            # udk.append(udf6)
            # Inner IPv4 packet TCP sport
            udf7 = sdk.la_acl_field_def()
            ipv4_ingress_acl_udk_320_base2.populate_udf(udf7, 3, 1, 1, 0, 2, True)
            udk.append(udf7)
            # Inner IPv4 packet TCP dport
            udf8 = sdk.la_acl_field_def()
            ipv4_ingress_acl_udk_320_base2.populate_udf(udf8, 4, 1, 1, 2, 2, True)
            udk.append(udf8)
            key_type = sdk.la_acl_key_type_e_IPV4
            direction = sdk.la_acl_direction_e_INGRESS
            tcam_pool_id = 0
            ipv4_ingress_acl_udk_320_base2.acl_key_profile_ipv4_320_udk = device.create_acl_key_profile(
                key_type, direction, udk, tcam_pool_id)

    @classmethod
    def setUpClass(cls):
        super(ipv4_ingress_acl_udk_320_base2, cls).setUpClass(
            device_config_func=ipv4_ingress_acl_udk_320_base2.device_config_func)

    def setUp(self):
        super().setUp()
        self.add_default_route()
        self.inserted_drop_counter = None

    def tearDown(self):
        super().tearDown()

    def add_default_route(self):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = 0x0
        prefix.length = 0
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.topology.nh_l3_ac_def.hld_obj, PRIVATE_DATA_DEFAULT, False)

    def create_empty_acl(self):
        ''' Create empty ACL. '''

        acl0 = self.device.create_acl(
            ipv4_ingress_acl_udk_320_base2.acl_key_profile_ipv4_320_udk,
            self.topology.acl_command_profile_def)
        self.assertNotEqual(acl0, None)

        count = acl0.get_count()
        self.assertEqual(count, 0)

        return acl0

    def create_simple_sec_acl(self):
        ''' Create simple security ACL. '''

        acl1 = self.device.create_acl(
            ipv4_ingress_acl_udk_320_base2.acl_key_profile_ipv4_320_udk,
            self.topology.acl_command_profile_def)
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
        action2.type = sdk.la_acl_action_type_e_L3_DESTINATION
        action2.data.l3_dest = self.topology.fec_l3_ac_ext.hld_obj
        commands2.append(action2)

        commands3 = []
        action3 = sdk.la_acl_command_action()
        action3.type = sdk.la_acl_action_type_e_DROP
        action3.data.drop = True
        commands3.append(action3)

        acl1.append(k1, commands1)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        acl1.append(k2, commands2)
        count = acl1.get_count()
        self.assertEqual(count, 2)

        acl1.append(k3, commands3)
        count = acl1.get_count()
        self.assertEqual(count, 3)

        acl_entry_desc = acl1.get(0)
        self.assertEqual(acl_entry_desc.key_val[0].type, k1[0].type)
        self.assertEqual(acl_entry_desc.key_val[0].val.ipv4_sip.s_addr, k1[0].val.ipv4_sip.s_addr)
        self.assertEqual(acl_entry_desc.key_val[0].mask.ipv4_sip.s_addr, k1[0].mask.ipv4_sip.s_addr)
        self.assertEqual(acl_entry_desc.cmd_actions[0].type, action1.type)
        self.assertEqual(acl_entry_desc.cmd_actions[0].data.drop, action1.data.drop)

        acl_entry_desc = acl1.get(1)
        self.assertEqual(acl_entry_desc.key_val[0].type, k2[0].type)
        self.assertEqual(acl_entry_desc.key_val[0].val.ipv4_dip.s_addr, k2[0].val.ipv4_dip.s_addr)
        self.assertEqual(acl_entry_desc.key_val[0].mask.ipv4_dip.s_addr, k2[0].mask.ipv4_dip.s_addr)
        self.assertEqual(acl_entry_desc.cmd_actions[0].type, action2.type)
        self.assertEqual(acl_entry_desc.cmd_actions[0].data.l3_dest.this, action2.data.l3_dest.this)

        return acl1

    def insert_ace(self, acl, is_drop, is_punt, l3_dest, position=0):
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
        acl.insert(position, k1, commands)

        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

    def insert_drop_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in drop.'''
        self.insert_ace(acl, True, False, None)

    def insert_punt_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in punt.'''
        self.insert_ace(acl, False, True, None)

    def insert_nop_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in NOP. '''
        self.insert_ace(acl, False, False, None)

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

    def trim_acl(self, acl):
        ''' Remove the last ACE of the ACL. '''

        count = acl.get_count()

        acl.erase(count - 1)
        count_tag = acl.get_count()
        self.assertEqual(count_tag, count - 1)

    def do_test_route_default(self):
        run_and_compare(self, self.device,
                        INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

    def do_test_route_default_with_acl(self):
        run_and_compare(self, self.device,
                        INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_EXTRA_OUTPUT_PACKET, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT)

    def do_test_route_default_with_drop(self):
        run_and_drop(self, self.device, INPUT_IP_IN_IP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

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
