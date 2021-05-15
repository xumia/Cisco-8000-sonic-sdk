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

HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
PUNT_VLAN = 0xB13
PUNT_SLICE = T.get_device_slice(3)
PUNT_IFG = 0
PUNT_PIF_FIRST = T.get_device_first_serdes(8)
PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
PUNT_SP_GID = 20

INPUT_PACKET_BASE = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
    ICMP()

INPUT_PACKET_BASE_SVI = \
    Ether(dst=T.RX_SVI_MAC.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
    ICMP()

EXPECTED_DEFAULT_OUTPUT_PACKET_BASE = \
    Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1) / \
    ICMP()

EXPECTED_DEFAULT_OUTPUT_PACKET_BASE_SVI = \
    Ether(dst=T.NH_SVI_DEF_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1) / \
    ICMP()

EXPECTED_EXTRA_OUTPUT_PACKET_BASE = \
    Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1) / \
    ICMP()

EXPECTED_EXTRA_OUTPUT_PACKET_BASE_SVI = \
    Ether(dst=T.NH_SVI_EXT_MAC.addr_str, src=T.TX_SVI_EXT_MAC.addr_str) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1) / \
    ICMP()

INPUT_PACKET_TCP_BASE = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
    TCP(sport=0x1234, dport=0x2345)

INPUT_PACKET_TCP_BASE_SVI = \
    Ether(dst=T.RX_SVI_MAC.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
    TCP(sport=0x1234, dport=0x2345)

INPUT_PACKET, INPUT_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_BASE)
EXPECTED_DEFAULT_OUTPUT_PACKET = add_payload(EXPECTED_DEFAULT_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
EXPECTED_EXTRA_OUTPUT_PACKET = add_payload(EXPECTED_EXTRA_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
INPUT_PACKET_TCP = add_payload(INPUT_PACKET_TCP_BASE, INPUT_PACKET_PAYLOAD_SIZE)

INPUT_PACKET_SVI, INPUT_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_BASE_SVI)
INPUT_PACKET_TCP_SVI = add_payload(INPUT_PACKET_TCP_BASE_SVI, INPUT_PACKET_PAYLOAD_SIZE)
EXPECTED_DEFAULT_OUTPUT_PACKET_SVI = add_payload(EXPECTED_DEFAULT_OUTPUT_PACKET_BASE_SVI, INPUT_PACKET_PAYLOAD_SIZE)
EXPECTED_EXTRA_OUTPUT_PACKET_SVI = add_payload(EXPECTED_EXTRA_OUTPUT_PACKET_BASE_SVI, INPUT_PACKET_PAYLOAD_SIZE)

INPUT_PACKET_WITH_PAYLOAD = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
    Raw(load=unhexlify('22220db80a0b12f00000000000002222'))

PUNT_PACKET = Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
         next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
         code=nplapi.NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT,
         source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         source_lp=T.RX_L3_AC_GID, destination_lp=nplapi.NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT,
         relay_id=T.VRF_GID, lpts_flow_type=0
         ) / \
    INPUT_PACKET

SIMPLE_QOS_COUNTER_OFFSET = 2
QOS_MARK_DSCP = 0x18


class ipv4_ingress_acl_udk_160_base(sdk_test_case_base):
    acl_key_profile_ipv4_160_udk = None

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
            udf4.type = sdk.la_acl_field_type_e_IPV4_FLAGS
            udk.append(udf4)
            udf6 = sdk.la_acl_field_def()
            udf6.type = sdk.la_acl_field_type_e_TCP_FLAGS
            udk.append(udf6)
            udf7 = sdk.la_acl_field_def()
            udf7.type = sdk.la_acl_field_type_e_SPORT
            udk.append(udf7)
            udf8 = sdk.la_acl_field_def()
            udf8.type = sdk.la_acl_field_type_e_DPORT
            udk.append(udf8)
            udf9 = sdk.la_acl_field_def()
            udf9.type = sdk.la_acl_field_type_e_MSG_TYPE
            udk.append(udf9)
            udf10 = sdk.la_acl_field_def()
            udf10.type = sdk.la_acl_field_type_e_MSG_CODE
            udk.append(udf10)
            udf11 = sdk.la_acl_field_def()
            udf11.type = sdk.la_acl_field_type_e_TOS
            udk.append(udf11)
            key_type = sdk.la_acl_key_type_e_IPV4
            direction = sdk.la_acl_direction_e_INGRESS
            tcam_pool_id = 0
            ipv4_ingress_acl_udk_160_base.acl_key_profile_ipv4_160_udk = device.create_acl_key_profile(
                key_type, direction, udk, tcam_pool_id)

    @classmethod
    def setUpClass(cls):
        super(ipv4_ingress_acl_udk_160_base, cls).setUpClass(
            device_config_func=ipv4_ingress_acl_udk_160_base.device_config_func)

    def setUp(self):
        super().setUp()
        self.PUNT_SLICE = T.choose_active_slices(self.device, PUNT_SLICE, [3, 1, 5])

        self.add_default_route()
        self.drop_counter = None

        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.PUNT_SLICE,
            PUNT_IFG,
            PUNT_SP_GID,
            PUNT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        self.punt_dest = T.create_l2_punt_destination(
            self, self.device, T.L2_PUNT_DESTINATION2_GID, pi_port, HOST_MAC_ADDR, PUNT_VLAN)

    def tearDown(self):
        super().tearDown()

    def add_default_route(self, is_svi=False):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = 0x0
        prefix.length = 0
        self.topology.vrf.hld_obj.add_ipv4_route(
            prefix,
            self.topology.nh_svi_def.hld_obj if is_svi else self.topology.nh_l3_ac_def.hld_obj,
            PRIVATE_DATA_DEFAULT,
            False)

    def delete_default_route(self):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = 0x0
        prefix.length = 0
        self.topology.vrf.hld_obj.delete_ipv4_route(prefix)

    def create_empty_acl(self):
        ''' Create empty ACL. '''

        acl0 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl0, None)

        count = acl0.get_count()
        self.assertEqual(count, 0)

        return acl0

    def create_simple_sec_acl(self, is_svi=False):
        ''' Create simple security ACL. '''
        acl1 = self.device.create_acl(
            ipv4_ingress_acl_udk_160_base.acl_key_profile_ipv4_160_udk,
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

        cmd_nop = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = False
        cmd_nop.append(action1)

        cmd_redirect = []
        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_L3_DESTINATION
        action2.data.l3_dest = self.topology.fec_svi_ext.hld_obj if is_svi else self.topology.fec_l3_ac_ext.hld_obj
        cmd_redirect.append(action2)

        # cmd_drop
        cmd_drop = []
        action3 = sdk.la_acl_command_action()
        action3.type = sdk.la_acl_action_type_e_DROP
        action3.data.drop = True
        cmd_drop.append(action3)

        acl1.append(k1, cmd_nop)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        acl1.append(k2, cmd_redirect)
        count = acl1.get_count()
        self.assertEqual(count, 2)

        acl1.append(k3, cmd_drop)
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

    def create_simple_unified_acl(self, is_punt=False, is_svi=False):
        ''' Create simple unified ACL. '''

        acl1 = self.device.create_acl(
            ipv4_ingress_acl_udk_160_base.acl_key_profile_ipv4_160_udk,
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

        cmd_nop = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = False
        cmd_nop.append(action1)

        commands2 = []
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

        if (is_punt):
            action10 = sdk.la_acl_command_action()
            action10.type = sdk.la_acl_action_type_e_PUNT
            action10.data.punt = is_punt
            commands2.append(action10)
        else:
            action2 = sdk.la_acl_command_action()
            action2.type = sdk.la_acl_action_type_e_L3_DESTINATION
            action2.data.l3_dest = self.topology.nh_svi_ext.hld_obj if is_svi else self.topology.nh_l3_ac_ext.hld_obj
            commands2.append(action2)

        acl1.append(k1, cmd_nop)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        acl1.append(k2, commands2)
        count = acl1.get_count()
        self.assertEqual(count, 2)

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
            action4 = sdk.la_acl_command_action()
            action4.type = sdk.la_acl_action_type_e_L3_DESTINATION
            action4.data.l3_dest = l3_dest
            commands.append(action4)
        else:
            action3 = sdk.la_acl_command_action()
            action3.type = sdk.la_acl_action_type_e_COUNTER
            action3.data.counter = counter
            commands.append(action3)
            self.inserted_drop_counter = counter

        count_pre = acl.get_count()
        acl.insert(position, k1, commands)

        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)
        return counter

    def insert_drop_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in drop.'''
        return self.insert_ace(acl, True, False, None)

    def insert_punt_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in punt.'''
        return self.insert_ace(acl, False, True, None)

    def insert_nop_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in NOP. '''
        return self.insert_ace(acl, False, False, None)

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

        acl.set(1, k2, command)
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

        return acl1

    def do_test_route_default(self, is_svi=False):
        if (is_svi):
            run_and_compare(self, self.device,
                            INPUT_PACKET_SVI, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                            EXPECTED_DEFAULT_OUTPUT_PACKET_SVI, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_SVI_DEF)
        else:
            run_and_compare(self, self.device,
                            INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                            EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

    def do_test_route_default_with_acl(self, is_svi=False):
        if (is_svi):
            run_and_compare(self, self.device,
                            INPUT_PACKET_SVI, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                            EXPECTED_EXTRA_OUTPUT_PACKET_SVI, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_SVI_EXT)
        else:
            run_and_compare(self, self.device,
                            INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                            EXPECTED_EXTRA_OUTPUT_PACKET, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT)

    def do_test_route_default_with_drop(self, is_svi=False):
        run_and_drop(self, self.device, INPUT_PACKET_SVI if is_svi else INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_permit_acl_counter(self):
        self.device.set_acl_scaled_enabled(False)

        acl1 = self.device.create_acl(
            ipv4_ingress_acl_udk_160_base.acl_key_profile_ipv4_160_udk,
            self.topology.acl_command_profile_def)
        self.assertNotEqual(acl1, None)

        k1 = []
        counter = self.device.create_counter(1)

        commands = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_COUNTER
        action1.data.counter = counter
        commands.append(action1)

        acl1.append(k1, commands)

        ipv4_acls = []
        ipv4_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        self.permit_counter = counter
        run_and_compare(self, self.device,
                        INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    def verify_key_packet_acl(self, acl, acl_key, acl_packet, is_svi=False):

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

        self.do_test_route_default_with_acl(is_svi)
        run_and_drop(self, self.device, acl_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        acl.erase(0)
        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre)

    def create_simple_qos_acl(self):
        ''' Create simple QoS ACL. '''

        self.device.set_acl_scaled_enabled(False)
        acl1 = self.device.create_acl(
            ipv4_ingress_acl_udk_160_base.acl_key_profile_ipv4_160_udk,
            self.topology.acl_command_profile_def)
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
        action5.type = sdk.la_acl_action_type_e_OVERRIDE_QOS
        action5.data.override_qos = True
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
