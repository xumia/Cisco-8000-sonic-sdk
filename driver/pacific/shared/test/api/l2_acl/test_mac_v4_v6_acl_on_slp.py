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

AC_PORT_GID_BASE = 10

SWITCH_GID = 100

DST_MAC = "ca:fe:ca:fe:ca:fe"
SRC_MAC = "de:ad:de:ad:de:ad"
VLAN = 0xAB9

SIP = T.ipv4_addr('192.193.194.195')
DIP = T.ipv4_addr('208.209.210.211')
IPV6_SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
IPV6_DIP = T.ipv6_addr('5555:5db8:5a5b:12f0:0000:0000:0000:1111')
LABEL = sdk.la_mpls_label()
LABEL.label = 0x64
TTL = 127

SIMPLE_QOS_COUNTER_OFFSET = 4
QOS_MARK_DSCP = 0x18


@unittest.skipIf(decor.is_pacific(), "Test is not enabled on Pacific")
@unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
@unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
class test_mac_v4_v6_acl_on_slp(test_l2_acl_ipv_base):

    CLASS_ID = 0xaf

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            device.set_bool_property(sdk.la_device_property_e_ENABLE_CLASS_ID_ACLS, True)

            # MAC profile
            key_type = sdk.la_acl_key_type_e_ETHERNET
            direction = sdk.la_acl_direction_e_INGRESS
            tcam_pool_id = 0
            test_mac_v4_v6_acl_on_slp.acl_profile_mac_160 = device.create_acl_key_profile(
                key_type, direction, sdk.LA_ACL_KEY_ETHERNET, tcam_pool_id)

            # IPV4 160b Profile
            ipv4_udk = []
            udf1 = sdk.la_acl_field_def()
            udf1.type = sdk.la_acl_field_type_e_DA
            ipv4_udk.append(udf1)
            udf2 = sdk.la_acl_field_def()
            udf2.type = sdk.la_acl_field_type_e_IPV4_DIP
            ipv4_udk.append(udf2)
            udf3 = sdk.la_acl_field_def()
            udf3.type = sdk.la_acl_field_type_e_PROTOCOL
            ipv4_udk.append(udf3)
            udf4 = sdk.la_acl_field_def()
            udf4.type = sdk.la_acl_field_type_e_SPORT
            ipv4_udk.append(udf4)
            udf5 = sdk.la_acl_field_def()
            udf5.type = sdk.la_acl_field_type_e_DPORT
            ipv4_udk.append(udf5)
            udf6 = sdk.la_acl_field_def()
            udf6.type = sdk.la_acl_field_type_e_TOS
            ipv4_udk.append(udf6)
            udf7 = sdk.la_acl_field_def()
            udf7.type = sdk.la_acl_field_type_e_CLASS_ID
            ipv4_udk.append(udf7)

            key_type = sdk.la_acl_key_type_e_IPV4
            direction = sdk.la_acl_direction_e_INGRESS
            tcam_pool_id = 0
            test_mac_v4_v6_acl_on_slp.acl_profile_ipv4_160_class_id = device.create_acl_key_profile(
                key_type, direction, ipv4_udk, tcam_pool_id)

    @classmethod
    def setUpClass(cls):
        super(test_mac_v4_v6_acl_on_slp, cls).setUpClass(
            device_config_func=test_mac_v4_v6_acl_on_slp.device_config_func)

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

        self.permit_counter = self.device.create_counter(1)

        self.topology.create_inject_ports()

    def create_packets(self):
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            MPLS(label=LABEL.label, ttl=TTL) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            TCP()

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            MPLS(label=LABEL.label, ttl=TTL) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            TCP()

        in_ipv4_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            TCP()

        out_ipv4_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            TCP()

        in_ipv6_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IPv6(src=IPV6_SIP.addr_str, dst=IPV6_DIP.addr_str, hlim=TTL) / \
            TCP(dport=0x1234)

        out_ipv6_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IPv6(src=IPV6_SIP.addr_str, dst=IPV6_DIP.addr_str, hlim=TTL) / \
            TCP(dport=0x1234)

        self.in_packet, base_input_packet_payload_size = enlarge_packet_to_min_length(in_packet_base)
        self.out_packet = add_payload(out_packet_base, base_input_packet_payload_size)

        self.in_ipv4_packet, base_input_ipv4_packet_payload_size = enlarge_packet_to_min_length(in_ipv4_packet_base)
        self.out_ipv4_packet = add_payload(out_ipv4_packet_base, base_input_ipv4_packet_payload_size)

        self.in_ipv6_packet, base_input_ipv6_packet_payload_size = enlarge_packet_to_min_length(in_ipv6_packet_base)
        self.out_ipv6_packet = add_payload(out_ipv6_packet_base, base_input_ipv6_packet_payload_size)

    def create_mac_qos_acl(self):
        acl1 = self.device.create_acl(test_mac_v4_v6_acl_on_slp.acl_profile_mac_160,
                                      self.topology.acl_command_profile_def)
        self.assertNotEqual(acl1, None)

        count = acl1.get_count()
        self.assertEqual(count, 0)

        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_SA
        f1.val.sa.flat = 0xdeaddeaddead
        f1.mask.sa.flat = 0xffffffffffff

        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_DA
        f2.val.da.flat = 0xcafecafecafe
        f2.mask.da.flat = 0xffffffffffff

        k1 = []
        k1.append(f1)
        k1.append(f2)

        cmd_phb_overwrite = []
        action3 = sdk.la_acl_command_action()
        action3.type = sdk.la_acl_action_type_e_TRAFFIC_CLASS
        action3.data.traffic_class = 7
        cmd_phb_overwrite.append(action3)

        action4 = sdk.la_acl_command_action()
        action4.type = sdk.la_acl_action_type_e_COLOR
        action4.data.color = 3
        cmd_phb_overwrite.append(action4)

        action5 = sdk.la_acl_command_action()
        action5.type = sdk.la_acl_action_type_e_COUNTER_TYPE
        action5.data.counter_type = sdk.la_acl_counter_type_e_DO_QOS_COUNTING
        cmd_phb_overwrite.append(action5)

        action6 = sdk.la_acl_command_action()
        action6.type = sdk.la_acl_action_type_e_QOS_OR_METER_COUNTER_OFFSET
        action6.data.qos_offset = SIMPLE_QOS_COUNTER_OFFSET
        cmd_phb_overwrite.append(action6)

        action7 = sdk.la_acl_command_action()
        action7.type = sdk.la_acl_action_type_e_REMARK_FWD
        action7.data.remark_fwd = 0
        cmd_phb_overwrite.append(action7)

        action8 = sdk.la_acl_command_action()
        action8.type = sdk.la_acl_action_type_e_ENCAP_EXP
        action8.data.encap_exp = 0
        cmd_phb_overwrite.append(action8)

        action9 = sdk.la_acl_command_action()
        action9.type = sdk.la_acl_action_type_e_REMARK_GROUP
        action9.data.remark_group = 0
        cmd_phb_overwrite.append(action9)

        acl1.append(k1, cmd_phb_overwrite)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        return acl1

    def create_mac_unified_acl(self):
        acl1 = self.device.create_acl(test_mac_v4_v6_acl_on_slp.acl_profile_mac_160,
                                      self.topology.acl_command_profile_def)
        self.assertNotEqual(acl1, None)

        count = acl1.get_count()
        self.assertEqual(count, 0)

        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_SA
        f1.val.sa.flat = 0xdeaddeaddead
        f1.mask.sa.flat = 0xffffffffffff

        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_DA
        f2.val.da.flat = 0xcafecafecafe
        f2.mask.da.flat = 0xffffffffffff

        k1 = []
        k1.append(f1)
        k1.append(f2)

        cmd_unified = []
        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_L2_DESTINATION
        action2.data.l2_dest = self.ac_port3.hld_obj
        cmd_unified.append(action2)

        acl1.append(k1, cmd_unified)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        return acl1

    def create_ipv4_class_id_unified_acl(self):
        ''' Create simple unified ACL with a Class ID field type. '''
        acl1 = self.device.create_acl(test_mac_v4_v6_acl_on_slp.acl_profile_ipv4_160_class_id,
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
        f2.val.class_id = test_mac_v4_v6_acl_on_slp.CLASS_ID
        f2.mask.class_id = 0xff
        k2.append(f0)
        k2.append(f1)
        k2.append(f2)

        cmd_nop = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = False
        cmd_nop.append(action1)

        cmd_unified = []
        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_COUNTER
        action2.data.counter = self.permit_counter
        cmd_unified.append(action2)

        action3 = sdk.la_acl_command_action()
        action3.type = sdk.la_acl_action_type_e_TRAFFIC_CLASS
        action3.data.traffic_class = 7
        cmd_unified.append(action3)

        action4 = sdk.la_acl_command_action()
        action4.type = sdk.la_acl_action_type_e_COLOR
        action4.data.color = 3
        cmd_unified.append(action4)

        action5 = sdk.la_acl_command_action()
        action5.type = sdk.la_acl_action_type_e_COUNTER_TYPE
        action5.data.counter_type = sdk.la_acl_counter_type_e_DO_QOS_COUNTING
        cmd_unified.append(action5)

        action6 = sdk.la_acl_command_action()
        action6.type = sdk.la_acl_action_type_e_QOS_OR_METER_COUNTER_OFFSET
        action6.data.qos_offset = SIMPLE_QOS_COUNTER_OFFSET
        cmd_unified.append(action6)

        action7 = sdk.la_acl_command_action()
        action7.type = sdk.la_acl_action_type_e_REMARK_FWD
        action7.data.remark_fwd = QOS_MARK_DSCP
        cmd_unified.append(action7)

        action8 = sdk.la_acl_command_action()
        action8.type = sdk.la_acl_action_type_e_ENCAP_EXP
        action8.data.encap_exp = 0
        cmd_unified.append(action8)

        action9 = sdk.la_acl_command_action()
        action9.type = sdk.la_acl_action_type_e_REMARK_GROUP
        action9.data.remark_group = 0
        cmd_unified.append(action9)

        acl1.append(k2, cmd_unified)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        acl1.append(k1, cmd_nop)
        count = acl1.get_count()
        self.assertEqual(count, 2)

        acl1.append(k0, cmd_nop)
        count = acl1.get_count()
        self.assertEqual(count, 3)

        return acl1

    def create_ipv6_class_id_unified_acl(self):
        self.device.destroy(self.topology.ingress_acl_key_profile_ipv6_def)

        # IPV6 160b Profile
        ipv6_udk = []
        udf1 = sdk.la_acl_field_def()
        udf1.type = sdk.la_acl_field_type_e_DA
        ipv6_udk.append(udf1)
        udf2 = sdk.la_acl_field_def()
        udf2.type = sdk.la_acl_field_type_e_SPORT
        ipv6_udk.append(udf2)
        udf3 = sdk.la_acl_field_def()
        udf3.type = sdk.la_acl_field_type_e_DPORT
        ipv6_udk.append(udf3)
        udf4 = sdk.la_acl_field_def()
        udf4.type = sdk.la_acl_field_type_e_IPV6_FRAGMENT
        ipv6_udk.append(udf4)
        udf5 = sdk.la_acl_field_def()
        udf5.type = sdk.la_acl_field_type_e_TOS
        ipv6_udk.append(udf5)
        udf6 = sdk.la_acl_field_def()
        udf6.type = sdk.la_acl_field_type_e_CLASS_ID
        ipv6_udk.append(udf6)

        key_type = sdk.la_acl_key_type_e_IPV6
        direction = sdk.la_acl_direction_e_INGRESS
        tcam_pool_id = 0
        test_mac_v4_v6_acl_on_slp.acl_profile_ipv6_160_class_id  = self.device.create_acl_key_profile(
            key_type, direction, ipv6_udk, tcam_pool_id)

        ''' Create simple unified ACL with a Class ID field type. '''
        acl1 = self.device.create_acl(test_mac_v4_v6_acl_on_slp.acl_profile_ipv6_160_class_id,
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
        f1.type = sdk.la_acl_field_type_e_DPORT
        f1.val.dport = 0x1234
        f1.mask.dport = 0xffff
        k1.append(f1)

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_CLASS_ID
        f2.val.class_id = test_mac_v4_v6_acl_on_slp.CLASS_ID
        f2.mask.class_id = 0xff
        k2.append(f0)
        k2.append(f1)
        k2.append(f2)

        cmd_nop = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = False
        cmd_nop.append(action1)

        cmd_unified = []
        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_COUNTER
        action2.data.counter = self.permit_counter
        cmd_unified.append(action2)

        action3 = sdk.la_acl_command_action()
        action3.type = sdk.la_acl_action_type_e_TRAFFIC_CLASS
        action3.data.traffic_class = 7
        cmd_unified.append(action3)

        action4 = sdk.la_acl_command_action()
        action4.type = sdk.la_acl_action_type_e_COLOR
        action4.data.color = 3
        cmd_unified.append(action4)

        action5 = sdk.la_acl_command_action()
        action5.type = sdk.la_acl_action_type_e_COUNTER_TYPE
        action5.data.counter_type = sdk.la_acl_counter_type_e_DO_QOS_COUNTING
        cmd_unified.append(action5)

        action6 = sdk.la_acl_command_action()
        action6.type = sdk.la_acl_action_type_e_QOS_OR_METER_COUNTER_OFFSET
        action6.data.qos_offset = SIMPLE_QOS_COUNTER_OFFSET
        cmd_unified.append(action6)

        action7 = sdk.la_acl_command_action()
        action7.type = sdk.la_acl_action_type_e_REMARK_FWD
        action7.data.remark_fwd = QOS_MARK_DSCP
        cmd_unified.append(action7)

        action8 = sdk.la_acl_command_action()
        action8.type = sdk.la_acl_action_type_e_ENCAP_EXP
        action8.data.encap_exp = 0
        cmd_unified.append(action8)

        action9 = sdk.la_acl_command_action()
        action9.type = sdk.la_acl_action_type_e_REMARK_GROUP
        action9.data.remark_group = 0
        cmd_unified.append(action9)

        acl1.append(k2, cmd_unified)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        acl1.append(k1, cmd_nop)
        count = acl1.get_count()
        self.assertEqual(count, 2)

        acl1.append(k0, cmd_nop)
        count = acl1.get_count()
        self.assertEqual(count, 3)

        return acl1

    @unittest.skipIf(decor.is_asic5(), "RTF is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "RTF is not yet enabled on PL")
    def test_acl(self):
        acl_v6 = self.create_ipv6_class_id_unified_acl()
        qos_mac = self.create_mac_qos_acl()
        acl_mac = self.create_mac_unified_acl()
        acl_v4 = self.create_ipv4_class_id_unified_acl()

        # Attach a Q counter
        q_counter = self.device.create_counter(8)
        self.ac_port1.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, q_counter)

        # Attach a P counter
        p_counter = self.device.create_counter(1)
        self.ac_port1.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, p_counter)

        # Attach the QoS ACL
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_ETHERNET, [qos_mac, acl_mac])
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl_v4])
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [acl_v6])
        self.ac_port1.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1F}}
        expected_output_packet = self.out_ipv4_packet.copy()
        expected_output_packet[IP].tos = QOS_MARK_DSCP << 2
        run_and_compare_inner_fields(
            self,
            self.device,
            self.in_ipv4_packet,
            self.IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            expected_output_packet,
            self.OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST, control_expected)

        # Check ACE counters
        packet_count, byte_count = self.permit_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        assertPacketLengthIngress(self, self.in_ipv4_packet, self.IN_SLICE, byte_count)

        # Verify P counter
        packet_count, byte_count = p_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        assertPacketLengthIngress(self, self.in_ipv4_packet, self.IN_SLICE, byte_count)

        # Verify Q counter
        packet_count, byte_count = q_counter.read(SIMPLE_QOS_COUNTER_OFFSET, True, True)
        self.assertEqual(packet_count, 1)
        assertPacketLengthIngress(self, self.in_ipv4_packet, self.IN_SLICE, byte_count)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1F}}
        expected_output_packet = self.out_ipv6_packet.copy()
        expected_output_packet[IPv6].tc = (QOS_MARK_DSCP << 2)
        run_and_compare_inner_fields(
            self,
            self.device,
            self.in_ipv6_packet,
            self.IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            expected_output_packet,
            self.OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST, control_expected)

        # Check ACE counters
        packet_count, byte_count = self.permit_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        assertPacketLengthIngress(self, self.in_ipv6_packet, self.IN_SLICE, byte_count)

        # Verify P counter
        packet_count, byte_count = p_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        assertPacketLengthIngress(self, self.in_ipv6_packet, self.IN_SLICE, byte_count)

        # Verify Q counter
        packet_count, byte_count = q_counter.read(SIMPLE_QOS_COUNTER_OFFSET, True, True)
        self.assertEqual(packet_count, 1)
        assertPacketLengthIngress(self, self.in_ipv6_packet, self.IN_SLICE, byte_count)

        # Detach ACL
        self.ac_port1.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)


if __name__ == '__main__':
    unittest.main()
