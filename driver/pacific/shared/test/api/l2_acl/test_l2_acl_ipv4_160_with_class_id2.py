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

import decor
from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
import nplapicli as nplapi
from sdk_test_case_base import *
import ip_test_base
import uut_provider
from binascii import hexlify, unhexlify
from test_l2_acl_ipv_base import test_l2_acl_ipv_base

SYS_PORT_GID_BASE = 23

IN_IFG = 0
OUT_IFG = T.get_device_ifg(1)
ACL_IFG = T.get_device_ifg(1)

IN_PIF_FIRST = 0
IN_PIF_LAST = IN_PIF_FIRST + 1
OUT_PIF_FIRST = 2
OUT_PIF_LAST = OUT_PIF_FIRST + 1
ACL_PIF_FIRST = T.get_device_first_serdes(2)
ACL_PIF_LAST = ACL_PIF_FIRST + 1
PUNT_INJECT_PIF_FIRST = 8
PUNT_INJECT_PIF_LAST = PUNT_INJECT_PIF_FIRST + 1
MIRROR_DEST_PIF_FIRST = 4
MIRROR_DEST_PIF_LAST = MIRROR_DEST_PIF_FIRST + 1

AC_PORT_GID_BASE = 10
PUNT_INJECT_SP_GID = SYS_PORT_GID_BASE + 20

SWITCH_GID = 100

DST_MAC = "ca:fe:ca:fe:ca:fe"
SRC_MAC = "de:ad:de:ad:de:ad"
VLAN = 0xAB9

SIP = T.ipv4_addr('192.193.194.195')
DIP = T.ipv4_addr('208.209.210.211')
TTL = 127

PUNT_INJECT_PORT_MAC_ADDR = "ca:fe:ba:be:ca:fe"
HOST_MAC_ADDR = "ba:be:ca:fe:ba:be"

PUNT_VLAN = 0xA13

MIRROR_CMD_GID = 9
MIRROR_VLAN = 0xA12

MIRROR_GID_INGRESS_OFFSET = 32
MIRROR_GID_EGRESS_OFFSET = 0
MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET


SIMPLE_QOS_COUNTER_OFFSET = 4
QOS_MARK_DSCP = 0x18


@unittest.skipUnless(decor.is_gibraltar(), "Class ID tests supported only on GB")
class test_l2_acl_ipv4_160_with_class_id2(test_l2_acl_ipv_base):

    CLASS_ID = 0xaf

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            device.set_bool_property(sdk.la_device_property_e_ENABLE_CLASS_ID_ACLS, True)
            udk = []
            udf1 = sdk.la_acl_field_def()
            udf1.type = sdk.la_acl_field_type_e_DA
            udk.append(udf1)
            udf2 = sdk.la_acl_field_def()
            udf2.type = sdk.la_acl_field_type_e_IPV4_DIP
            udk.append(udf2)
            udf3 = sdk.la_acl_field_def()
            udf3.type = sdk.la_acl_field_type_e_PROTOCOL
            udk.append(udf3)
            udf4 = sdk.la_acl_field_def()
            udf4.type = sdk.la_acl_field_type_e_SPORT
            udk.append(udf4)
            udf5 = sdk.la_acl_field_def()
            udf5.type = sdk.la_acl_field_type_e_DPORT
            udk.append(udf5)
            udf6 = sdk.la_acl_field_def()
            udf6.type = sdk.la_acl_field_type_e_TOS
            udk.append(udf6)
            udf7 = sdk.la_acl_field_def()
            udf7.type = sdk.la_acl_field_type_e_CLASS_ID
            udk.append(udf7)
            key_type = sdk.la_acl_key_type_e_IPV4
            direction = sdk.la_acl_direction_e_INGRESS
            tcam_pool_id = 0
            test_l2_acl_ipv4_160_with_class_id2.acl_profile_ipv4_160_class_id = device.create_acl_key_profile(
                key_type, direction, udk, tcam_pool_id)

    @classmethod
    def setUpClass(cls):
        super(test_l2_acl_ipv4_160_with_class_id2, cls).setUpClass(
            device_config_func=test_l2_acl_ipv4_160_with_class_id2.device_config_func)

    def setUp(self):
        super().setUp(create_default_topology=False)
        self.create_system_setup()
        self.create_packets()

    def create_system_setup(self):
        self.sw1 = T.switch(self, self.device, SWITCH_GID)

        # Add 'cafecafecafe' to the MAC table, going to AC port 2
        self.src_mac = T.mac_addr(SRC_MAC)
        self.dest_mac = T.mac_addr(DST_MAC)

        self.eth_port1 = T.ethernet_port(self, self.device, self.IN_SLICE, IN_IFG, SYS_PORT_GID_BASE, IN_PIF_FIRST, IN_PIF_LAST)
        self.ac_port1 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port1,
            self.src_mac,
            VLAN,
            0x0)

        self.eth_port2 = T.ethernet_port(
            self,
            self.device,
            self.OUT_SLICE,
            OUT_IFG,
            SYS_PORT_GID_BASE + 1,
            OUT_PIF_FIRST,
            OUT_PIF_LAST)
        self.ac_port2 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 1,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port2,
            self.dest_mac,
            VLAN,
            0x0, None, None, None,
            self.CLASS_ID)

        self.eth_port3 = T.ethernet_port(
            self,
            self.device,
            self.ACL_SLICE,
            ACL_IFG,
            SYS_PORT_GID_BASE + 2,
            ACL_PIF_FIRST,
            ACL_PIF_LAST)
        self.ac_port3 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE +
                                     2, self.topology.filter_group_def, self.sw1, self.eth_port3, None, VLAN, 0x0)

        self.topology.create_inject_ports()

        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            self.PUNT_INJECT_SLICE,
            self.PUNT_INJECT_IFG,
            PUNT_INJECT_SP_GID,
            PUNT_INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        self.punt_dest = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            self.pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN)

        self.mirror_cmd = T.create_l2_mirror_command(self.device, MIRROR_CMD_INGRESS_GID, self.pi_port, HOST_MAC_ADDR, MIRROR_VLAN)

    def create_packets(self):
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            TCP()

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            TCP()

        mirror_packet_base = \
            Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=MIRROR_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET, next_header_offset=0,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR, code=MIRROR_CMD_INGRESS_GID,
                 source_sp=SYS_PORT_GID_BASE, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 source_lp=AC_PORT_GID_BASE | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING, destination_lp=AC_PORT_GID_BASE + 2,
                 relay_id=SWITCH_GID, lpts_flow_type=0) / \
            Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            TCP()

        self.in_packet, base_input_packet_payload_size = enlarge_packet_to_min_length(in_packet_base)
        self.out_packet = add_payload(out_packet_base, base_input_packet_payload_size)
        self.mirror_packet = add_payload(mirror_packet_base, base_input_packet_payload_size)

    def create_ipv4_class_id_unified_acl(self):
        ''' Create simple unified ACL with a Class ID field type. '''

        acl1 = self.device.create_acl(
            test_l2_acl_ipv4_160_with_class_id2.acl_profile_ipv4_160_class_id,
            self.topology.acl_command_profile_def)
        self.assertNotEqual(acl1, None)

        count = acl1.get_count()
        self.assertEqual(count, 0)

        k0 = []
        f0 = sdk.la_acl_field()
        f0.type = sdk.la_acl_field_type_e_DA
        f0.val.da.flat = 0xcafecafe0000
        f0.mask.da.flat = 0xffffffff0000
        k0.append(f0)

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV4_DIP
        f1.val.ipv4_dip.s_addr = DIP.to_num()
        f1.mask.ipv4_dip.s_addr = 0xffffffff
        k1.append(f1)

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_CLASS_ID
        f2.val.class_id = test_l2_acl_ipv4_160_with_class_id2.CLASS_ID
        f2.mask.class_id = 0xff
        k2.append(f0)
        k2.append(f1)
        k2.append(f2)

        cmd_nop = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = False
        cmd_nop.append(action1)

        commands2 = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DO_MIRROR
        action1.data.do_mirror = sdk.la_acl_mirror_src_e_DO_MIRROR_FROM_LP
        commands2.append(action1)

        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_L2_DESTINATION
        action2.data.l2_dest = self.ac_port3.hld_obj
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

        acl1.append(k2, commands2)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        acl1.append(k1, cmd_nop)
        count = acl1.get_count()
        self.assertEqual(count, 2)

        acl1.append(k0, cmd_nop)
        count = acl1.get_count()
        self.assertEqual(count, 3)

        return acl1

    @unittest.skipUnless(decor.is_gibraltar(), "Class ID tests supported only on GB")
    def test_ipv4_acl(self):
        acl1 = self.create_ipv4_class_id_unified_acl()

        # Pass packet from port 2 to port 4, through a relay without ACL hit
        # Ensure PHB remains default (0).
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0}}
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            self.IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            self.OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST, control_expected)

        # Attach a Q counter
        q_counter = self.device.create_counter(8)
        self.ac_port1.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, q_counter)
        self.ac_port1.hld_obj.set_ingress_mirror_command(self.mirror_cmd, is_acl_conditioned=True)

        mirror_cmd, is_acl_conditioned = self.ac_port1.hld_obj.get_ingress_mirror_command()
        self.assertEqual(mirror_cmd.get_gid(), self.mirror_cmd.get_gid())
        self.assertTrue(is_acl_conditioned)

        ipv4_acls = []
        ipv4_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.ac_port1.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1F}}
        expected_output_packet = self.out_packet.copy()
        expected_output_packet[IP].tos = QOS_MARK_DSCP << 2
        run_and_compare_list(self, self.device,
                             {'data': self.in_packet,
                              'slice': self.IN_SLICE,
                              'ifg': IN_IFG,
                              'pif': IN_PIF_FIRST},
                             [{'data': expected_output_packet,
                               'slice': self.ACL_SLICE,
                               'ifg': ACL_IFG,
                               'pif': ACL_PIF_FIRST},
                              {'data': self.mirror_packet,
                               'slice': self.PUNT_INJECT_SLICE,
                               'ifg': self.PUNT_INJECT_IFG,
                               'pif': PUNT_INJECT_PIF_FIRST}])

        # Verify Q counter
        packet_count, byte_count = q_counter.read(SIMPLE_QOS_COUNTER_OFFSET, True, True)
        self.assertEqual(packet_count, 1)
        assertPacketLengthIngress(self, self.in_packet, self.IN_SLICE, byte_count)

        # Detach ACL
        self.ac_port1.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.ac_port1.hld_obj.set_ingress_mirror_command(None, is_acl_conditioned=False)

        # Pass packet from port 2 to port 4, through a relay without ACL hit
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0}}
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            self.IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            self.OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST, control_expected)


if __name__ == '__main__':
    unittest.main()
