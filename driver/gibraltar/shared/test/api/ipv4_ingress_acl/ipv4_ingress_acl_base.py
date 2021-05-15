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

import ip_test_base

PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
SA = T.mac_addr('be:ef:5d:35:7a:35')
HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
PUNT_VLAN = 0xB13

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

PUNT_PACKET_UC_BASE = \
    Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
         next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
         code=0,
         source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         source_lp=T.RX_L3_AC_GID, destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
         relay_id=T.VRF_GID, lpts_flow_type=0) / \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
    ICMP()

INPUT_PACKET_SVI_BASE = \
    Ether(dst=T.RX_SVI_MAC.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
    TCP()

INPUT_PACKET_SVI, INPUT_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_SVI_BASE)
INPUT_PACKET, INPUT_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_BASE)
EXPECTED_DEFAULT_OUTPUT_PACKET = add_payload(EXPECTED_DEFAULT_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
EXPECTED_EXTRA_OUTPUT_PACKET = add_payload(EXPECTED_EXTRA_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
INPUT_PACKET_TCP = add_payload(INPUT_PACKET_TCP_BASE, INPUT_PACKET_PAYLOAD_SIZE)

INPUT_PACKET_UC, PUNT_PACKET_UC = pad_input_and_output_packets(INPUT_PACKET_BASE, PUNT_PACKET_UC_BASE)

SIMPLE_QOS_COUNTER_OFFSET = 2
EXT_QOS_COUNTER_OFFSET = 31
SIMPLE_QOS_METER_OFFSET = 1
QOS_MARK_DSCP = 0x18


class ipv4_ingress_acl_base(sdk_test_case_base):
    slice_modes = sim_utils.STANDALONE_DEV

    @classmethod
    def setUpClass(cls):
        super(ipv4_ingress_acl_base, cls).setUpClass(slice_modes=cls.slice_modes)

    def setUp(self):
        super().setUp()
        self.add_default_route()
        self.drop_counter = None

    def add_default_route(self):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = 0x0
        prefix.length = 0
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.topology.nh_l3_ac_def.hld_obj, PRIVATE_DATA_DEFAULT, False)

    def create_empty_acl(self):
        ''' Create empty ACL. '''

        acl0 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl0, None)

        count = acl0.get_count()
        self.assertEqual(count, 0)

        return acl0

    def create_simple_sec_acl(self):
        ''' Create simple security ACL. '''
        acl = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl, None)

        count = acl.get_count()
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
        action1.type = sdk.la_acl_action_type_e_COUNTER
        self.nop_counter = self.device.create_counter(1)
        action1.data.counter = self.nop_counter
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

        action4 = sdk.la_acl_command_action()
        action4.type = sdk.la_acl_action_type_e_COUNTER
        action4.data.counter = self.device.create_counter(8)
        commands3.append(action4)

        acl.append(k1, commands1)
        count = acl.get_count()
        self.assertEqual(count, 1)

        acl.append(k2, commands2)
        count = acl.get_count()
        self.assertEqual(count, 2)

        acl.append(k3, commands3)
        count = acl.get_count()
        self.assertEqual(count, 3)

        acl_entry_desc = acl.get(0)
        self.assertEqual(acl_entry_desc.key_val[0].type, k1[0].type)
        self.assertEqual(acl_entry_desc.key_val[0].val.ipv4_sip.s_addr, k1[0].val.ipv4_sip.s_addr)
        self.assertEqual(acl_entry_desc.key_val[0].mask.ipv4_sip.s_addr, k1[0].mask.ipv4_sip.s_addr)
        self.assertEqual(acl_entry_desc.cmd_actions[0].type, action1.type)
        self.assertEqual(acl_entry_desc.cmd_actions[0].data.drop, action1.data.drop)

        acl_entry_desc = acl.get(1)
        self.assertEqual(acl_entry_desc.key_val[0].type, k2[0].type)
        self.assertEqual(acl_entry_desc.key_val[0].val.ipv4_dip.s_addr, k2[0].val.ipv4_dip.s_addr)
        self.assertEqual(acl_entry_desc.key_val[0].mask.ipv4_dip.s_addr, k2[0].mask.ipv4_dip.s_addr)
        self.assertEqual(acl_entry_desc.cmd_actions[0].type, action2.type)
        self.assertEqual(acl_entry_desc.cmd_actions[0].data.l3_dest.this, action2.data.l3_dest.this)

        return acl

    def insert_ace(self, acl, is_drop, is_punt, l3_dest, position=0):
        ''' Insert ACE that catch all traffic and result in drop if is_drop True. '''

        k1 = []
        counter = self.device.create_counter(4)

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
            action3 = sdk.la_acl_command_action()
            action3.type = sdk.la_acl_action_type_e_COUNTER
            action3.data.counter = counter
            commands.append(action3)

        count_pre = acl.get_count()
        acl.insert(position, k1, commands)

        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

        return counter

    def insert_drop_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in drop.'''
        self.drop_counter = self.insert_ace(acl, True, False, None)

    def insert_punt_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in punt.'''
        self.punt_counter = self.insert_ace(acl, False, True, None)

    def insert_nop_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in NOP. '''
        self.nop_counter = self.insert_ace(acl, False, False, None)

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

    def update_simple_acl_to_default(self, acl):
        ''' Update the simple ACL to redirect to the default FEC. '''

        count = acl.get_count()

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_IPV4_DIP
        f2.val.ipv4_dip.s_addr = DIP.to_num() & 0xffff0000
        f2.mask.ipv4_dip.s_addr = 0xffff0000
        k2.append(f2)

        commands = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_L3_DESTINATION
        action1.data.l3_dest = self.topology.fec_l3_ac_def.hld_obj
        commands.append(action1)

        acl.set(1, k2, commands)
        acl_entry_desc = acl.get(1)
        self.assertEqual(acl_entry_desc.key_val[0].val.ipv4_sip.s_addr, k2[0].val.ipv4_sip.s_addr)
        self.assertEqual(acl_entry_desc.cmd_actions[0].type, action1.type)

        # No change in ACE count
        count_tag = acl.get_count()
        self.assertEqual(count_tag, count)

    def create_simple_scaled_acl(self):
        ''' Create simple scaled ACL. '''

        self.device.set_acl_scaled_enabled(True)
        acl1 = self.device.create_acl_scaled(sdk.la_acl.stage_e_INGRESS_FWD,
                                             sdk.la_acl.type_e_UNIFIED, self.topology.acl_profile_ipv4_def)
        self.assertNotEqual(acl1, None)

        count = acl1.get_count()
        self.assertEqual(count, 0)

        count_sip = acl1.get_count(sdk.la_acl_scaled.scale_field_e_SIP)
        self.assertEqual(count_sip, 0)

        count_dip = acl1.get_count(sdk.la_acl_scaled.scale_field_e_DIP)
        self.assertEqual(count_dip, 0)

        sfk1 = sdk.la_acl_scale_field_key()
        sfk1.type = sdk.la_acl_scale_field_type_e_IPV4
        sfk1.val.ipv4.s_addr = SIP.to_num() + 1  # should not catch
        sfk1.mask.ipv4.s_addr = 0xffffffff
        sfv1 = 1

        sfk2 = sdk.la_acl_scale_field_key()
        sfk2.type = sdk.la_acl_scale_field_type_e_IPV4
        sfk2.val.ipv4.s_addr = DIP.to_num() & 0xffffff00
        sfk2.mask.ipv4.s_addr = 0xffffff00
        sfv2 = 1

        sfk3 = sdk.la_acl_scale_field_key()
        sfk3.type = sdk.la_acl_scale_field_type_e_IPV4
        sfk3.val.ipv4.s_addr = DIP.to_num()
        sfk3.mask.ipv4.s_addr = 0xffffffff
        sfv3 = 2

        acl1.append(sdk.la_acl_scaled.scale_field_e_SIP, sfk1, sfv1)

        count_sip = acl1.get_count(sdk.la_acl_scaled.scale_field_e_SIP)
        self.assertEqual(count_sip, 1)

        acl1.append(sdk.la_acl_scaled.scale_field_e_DIP, sfk2, sfv2)

        count_dip = acl1.get_count(sdk.la_acl_scaled.scale_field_e_DIP)
        self.assertEqual(count_dip, 1)

        acl1.append(sdk.la_acl_scaled.scale_field_e_DIP, sfk3, sfv3)

        count_dip = acl1.get_count(sdk.la_acl_scaled.scale_field_e_DIP)
        self.assertEqual(count_dip, 2)

        k1 = sdk.la_acl_key()
        k1.val.scaled_res.compress_sip = sfv1
        k1.mask.scaled_res.compress_sip = 0xff

        k2 = sdk.la_acl_key()
        k2.val.scaled_res.compress_dip = sfv2
        k2.mask.scaled_res.compress_dip = 0xff

        k3 = sdk.la_acl_key()
        k3.val.scaled_res.compress_dip = sfv3
        k3.mask.scaled_res.compress_dip = 0xff

        counter = self.device.create_counter(8)
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

    def do_test_route_default(self):
        run_and_compare(self, self.device,
                        INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

    def do_test_route_default_with_acl(self):
        run_and_compare(self, self.device,
                        INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_EXTRA_OUTPUT_PACKET, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT)

    def do_test_route_default_with_drop(self, is_svi=False):
        input_packet = INPUT_PACKET_SVI if is_svi else INPUT_PACKET
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

        acl_entry_desc = acl.get(0)
        #self.assertEqual(acl_entry_desc.key_val.val[0].data.mtype, acl_key.val[0].data.mtype)
        #self.assertEqual(acl_entry_desc.key_val.mask[0].data.mtype, acl_key.mask[0].data.mtype)
        #self.assertEqual(acl_entry_desc.key_val.val[1].data.mcode, acl_key.val[1].data.mcode)
        #self.assertEqual(acl_entry_desc.key_val.mask[1].data.mcode, acl_key.mask[1].data.mcode)

        self.do_test_route_default_with_acl()
        run_and_drop(self, self.device, acl_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        acl.erase(0)
        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre)

    def create_simple_qos_acl(self):
        ''' Create simple QoS ACL. '''

        self.device.set_acl_scaled_enabled(False)
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl1, None)

        count = acl1.get_count()
        self.assertEqual(count, 0)

        # Should not catch
        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV4_SIP
        f1.val.ipv4_sip.s_addr = SIP.to_num() + 1
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
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl1, None)

        count = acl1.get_count()
        self.assertEqual(count, 0)

        # Should not catch
        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV4_SIP
        f1.val.ipv4_sip.s_addr = SIP.to_num() + 1
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
        action5.type = sdk.la_acl_action_type_e_L3_DESTINATION
        action5.data.l3_dest = self.topology.nh_l3_ac_ext.hld_obj
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

    def create_simple_qos_acl2(self):
        ''' Create a second QoS ACL. '''

        self.device.set_acl_scaled_enabled(False)
        acl2 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl2, None)

        count = acl2.get_count()
        self.assertEqual(count, 0)

        k4 = []
        f4 = sdk.la_acl_field()
        f4.type = sdk.la_acl_field_type_e_IPV4_SIP
        f4.val.ipv4_sip.s_addr = SIP.to_num()
        f4.mask.ipv4_sip.s_addr = 0xffffff00
        k4.append(f4)

        commands = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_TRAFFIC_CLASS
        action1.data.traffic_class = 7
        commands.append(action1)

        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_COLOR
        action2.data.color = 3
        commands.append(action2)

        action3 = sdk.la_acl_command_action()
        action3.type = sdk.la_acl_action_type_e_COUNTER_TYPE
        action3.data.counter_type = sdk.la_acl_counter_type_e_DO_QOS_COUNTING
        commands.append(action3)

        action4 = sdk.la_acl_command_action()
        action4.type = sdk.la_acl_action_type_e_QOS_OR_METER_COUNTER_OFFSET
        action4.data.qos_offset = EXT_QOS_COUNTER_OFFSET
        commands.append(action4)

        action5 = sdk.la_acl_command_action()
        action5.type = sdk.la_acl_action_type_e_REMARK_FWD
        action5.data.remark_fwd = QOS_MARK_DSCP
        commands.append(action5)

        action6 = sdk.la_acl_command_action()
        action6.type = sdk.la_acl_action_type_e_ENCAP_EXP
        action6.data.encap_exp = 0
        commands.append(action6)

        action7 = sdk.la_acl_command_action()
        action7.type = sdk.la_acl_action_type_e_REMARK_GROUP
        action7.data.remark_group = 0
        commands.append(action7)

        acl2.append(k4, commands)
        count = acl2.get_count()
        self.assertEqual(count, 1)

        return acl2

    def create_simple_qos_acl3(self):
        ''' Create a third QoS ACL. '''

        self.device.set_acl_scaled_enabled(False)
        acl3 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl3, None)

        count = acl3.get_count()
        self.assertEqual(count, 0)

        k5 = []
        f5 = sdk.la_acl_field()
        f5.type = sdk.la_acl_field_type_e_TOS
        f5.val.tos.fields.dscp = 0x8
        f5.mask.tos.flat = 0xfc
        k5.append(f5)

        commands = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_COUNTER_TYPE
        action1.data.counter_type = sdk.la_acl_counter_type_e_DO_METERING
        commands.append(action1)

        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_QOS_OR_METER_COUNTER_OFFSET
        action2.data.meter_offset = SIMPLE_QOS_METER_OFFSET
        commands.append(action2)

        acl3.append(k5, commands)
        count = acl3.get_count()
        self.assertEqual(count, 1)

        return acl3

    def create_simple_qos_acl4(self):
        ''' Create a fourth QoS ACL. '''

        self.device.set_acl_scaled_enabled(False)
        acl4 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl4, None)

        count = acl4.get_count()
        self.assertEqual(count, 0)

        k6 = []
        f6 = sdk.la_acl_field()
        f6.type = sdk.la_acl_field_type_e_TOS
        f6.val.tos.fields.dscp = 0x10
        f6.mask.tos.flat = 0xfc
        k6.append(f6)

        commands = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_TRAFFIC_CLASS
        action1.data.traffic_class = 7
        commands.append(action1)

        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_COLOR
        action2.data.color = 3
        commands.append(action2)

        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_COUNTER_TYPE
        action1.data.counter_type = sdk.la_acl_counter_type_e_DO_QOS_COUNTING
        commands.append(action1)

        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_QOS_OR_METER_COUNTER_OFFSET
        action2.data.meter_offset = SIMPLE_QOS_COUNTER_OFFSET
        commands.append(action2)

        acl4.append(k6, commands)
        count = acl4.get_count()
        self.assertEqual(count, 1)

        return acl4

    def create_simple_qos_acl5(self):
        ''' Create a fifth QoS ACL. '''

        self.device.set_acl_scaled_enabled(False)
        acl5 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl5, None)

        count = acl5.get_count()
        self.assertEqual(count, 0)

        k6 = []
        f6 = sdk.la_acl_field()
        f6.type = sdk.la_acl_field_type_e_TOS
        f6.val.tos.fields.dscp = 0x10
        f6.mask.tos.flat = 0xfc
        k6.append(f6)

        commands = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_REMARK_FWD
        QOS_MARK_DSCP = 0x38
        action1.data.remark_fwd = QOS_MARK_DSCP
        commands.append(action1)

        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_COUNTER_TYPE
        action1.data.counter_type = sdk.la_acl_counter_type_e_DO_QOS_COUNTING
        commands.append(action1)

        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_QOS_OR_METER_COUNTER_OFFSET
        SIMPLE_QOS_COUNTER_OFFSET = 0
        action2.data.meter_offset = SIMPLE_QOS_COUNTER_OFFSET
        commands.append(action2)

        acl5.append(k6, commands)
        count = acl5.get_count()
        self.assertEqual(count, 1)

        return acl5
