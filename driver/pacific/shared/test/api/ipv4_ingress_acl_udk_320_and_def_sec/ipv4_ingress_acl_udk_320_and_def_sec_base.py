#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
SA_udk = T.mac_addr('be:ef:5d:35:7a:35')
SA_def_sec = T.mac_addr('be:ef:5d:35:7a:40')

# IPv4
# 0xc0c1c2c3
SIP_UDK = T.ipv4_addr('192.193.194.195')
# 0xBFC1C3C8
SIP_DEF_SEC = T.ipv4_addr('191.193.195.200')
# 0xd0d1d2d3
DIP_UDK = T.ipv4_addr('208.209.210.211')
DIP_DEF_SEC = T.ipv4_addr('210.209.210.211')

TTL = 127

INPUT_PACKET_BASE = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA_udk.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP_UDK.addr_str, dst=DIP_UDK.addr_str, ttl=TTL) / \
    ICMP()
#    UDP(sport=0x1234, dport=0x2345)

INPUT_PACKET_BASE_DEF_SEC = \
    Ether(dst=T.RX_L3_AC_MAC1.addr_str, src=SA_def_sec.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP_DEF_SEC.addr_str, dst=DIP_DEF_SEC.addr_str, ttl=TTL) / \
    ICMP()

EXPECTED_DEFAULT_OUTPUT_PACKET_BASE = \
    Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) / \
    IP(src=SIP_UDK.addr_str, dst=DIP_UDK.addr_str, ttl=TTL - 1) / \
    ICMP()
#    UDP(sport=0x1234, dport=0x2345)

EXPECTED_EXTRA_OUTPUT_PACKET_BASE = \
    Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str) / \
    IP(src=SIP_UDK.addr_str, dst=DIP_UDK.addr_str, ttl=TTL - 1) / \
    ICMP()
#    UDP(sport=0x1234, dport=0x2345)

INPUT_PACKET_TCP_BASE = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA_udk.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP_UDK.addr_str, dst=DIP_UDK.addr_str, ttl=TTL) / \
    TCP(sport=0x1234, dport=0x2345)

INPUT_PACKET, INPUT_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_BASE)
INPUT_PACKET_DEF_SEC, INPUT_PACKET_PAYLOAD_SIZE_DEF_SEC = enlarge_packet_to_min_length(INPUT_PACKET_BASE_DEF_SEC)
EXPECTED_DEFAULT_OUTPUT_PACKET = add_payload(EXPECTED_DEFAULT_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
EXPECTED_EXTRA_OUTPUT_PACKET = add_payload(EXPECTED_EXTRA_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
INPUT_PACKET_TCP = add_payload(INPUT_PACKET_TCP_BASE, INPUT_PACKET_PAYLOAD_SIZE)

INPUT_PACKET_WITH_PAYLOAD = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA_udk.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP_UDK.addr_str, dst=DIP_UDK.addr_str, ttl=TTL) / \
    Raw(load=unhexlify('22220db80a0b12f00000000000002222'))

SIMPLE_QOS_COUNTER_OFFSET = 2
QOS_MARK_DSCP = 0x18


class ipv4_ingress_acl_udk_320_and_def_sec_base(sdk_test_case_base):
    acl_key_profile_ipv4_320_udk = None

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
            udf5 = sdk.la_acl_field_def()
            udf5.type = sdk.la_acl_field_type_e_IPV4_FLAGS
            udk.append(udf5)
            udf6 = sdk.la_acl_field_def()
            udf6.type = sdk.la_acl_field_type_e_TCP_FLAGS
            udk.append(udf6)
            udf7 = sdk.la_acl_field_def()
            udf7.type = sdk.la_acl_field_type_e_SPORT
            udk.append(udf7)
            udf8 = sdk.la_acl_field_def()
            udf8.type = sdk.la_acl_field_type_e_DPORT
            udk.append(udf8)
            #udf9 = sdk.la_acl_field_def()
            #udf9.type = sdk.la_acl_field_type_e_MSG_TYPE
            # udk.append(udf9)
            #udf10 = sdk.la_acl_field_def()
            #udf10.type = sdk.la_acl_field_type_e_MSG_CODE
            # udk.append(udf10)
            udf11 = sdk.la_acl_field_def()
            udf11.type = sdk.la_acl_field_type_e_UDF
            udf11.udf_desc.index = 1
            udf11.udf_desc.protocol_layer = 0
            udf11.udf_desc.header = 0
            udf11.udf_desc.offset = 20
            udf11.udf_desc.width = 16
            udf11.udf_desc.is_relative = True
            udk.append(udf11)
            key_type = sdk.la_acl_key_type_e_IPV4
            direction = sdk.la_acl_direction_e_INGRESS
            tcam_pool_id = 0
            ipv4_ingress_acl_udk_320_and_def_sec_base.acl_key_profile_ipv4_320_udk = device.create_acl_key_profile(
                key_type, direction, udk, tcam_pool_id)

    @classmethod
    def setUpClass(cls):
        super(
            ipv4_ingress_acl_udk_320_and_def_sec_base,
            cls).setUpClass(
            device_config_func=ipv4_ingress_acl_udk_320_and_def_sec_base.device_config_func)

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

    def create_simple_sec_acl_for_udk(self):
        ''' Create simple security ACL. '''

        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl1, None)

        count = acl1.get_count()
        self.assertEqual(count, 0)

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV4_SIP
        f1.val.ipv4_sip.s_addr = SIP_UDK.to_num() + 1  # should not catch
        f1.mask.ipv4_sip.s_addr = 0xffffffff
        k1.append(f1)

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_IPV4_DIP
        f2.val.ipv4_dip.s_addr = DIP_UDK.to_num() & 0xffffff00
        f2.mask.ipv4_dip.s_addr = 0xffffff00
        k2.append(f2)

        k3 = []
        f3 = sdk.la_acl_field()
        f3.type = sdk.la_acl_field_type_e_IPV4_DIP
        f3.val.ipv4_dip.s_addr = DIP_UDK.to_num()
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

    def create_simple_sec_acl_for_def_sec(self):
        ''' Create simple security ACL. for default sec'''

        # add default acl
        def_acl = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)

        self.assertNotEqual(def_acl, None)

        return def_acl

    def insert_drop_ace_for_def_sec(self, acl):
        count_pre = acl.get_count()

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV4_SIP
        f1.val.ipv4_sip.s_addr = SIP_DEF_SEC.to_num()
        f1.mask.ipv4_sip.s_addr = 0xffffffff
        k1.append(f1)

        commands = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = True
        commands.append(action1)

        acl.insert(0, k1, commands)

        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

    def insert_ace(self, acl, is_drop, is_punt, l3_dest, position=0):
        ''' Insert ACE that catch all traffic and result in drop if is_drop True. '''

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV4_SIP
        f1.val.ipv4_sip.s_addr = SIP_UDK.to_num()
        f1.mask.ipv4_sip.s_addr = 0xffffffff
        k1.append(f1)

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

    def insert_drop_ace_for_udk(self, acl):
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

    def do_test_route_default_for_udk(self):
        run_and_compare(self, self.device,
                        INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

    def do_test_route_default_with_acl_for_udk(self):
        run_and_compare(self, self.device,
                        INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_EXTRA_OUTPUT_PACKET, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3)

    def do_test_route_default_with_drop_for_udk(self):
        run_and_drop(self, self.device, INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def do_test_drop_ace_for_def_sec(self):
        run_and_drop(self, self.device, INPUT_PACKET_DEF_SEC, T.RX_SLICE, T.RX_IFG1, T.FIRST_SERDES1)

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

        self.do_test_route_default_with_acl_for_udk()
        run_and_drop(self, self.device, acl_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        acl.erase(0)
        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre)
