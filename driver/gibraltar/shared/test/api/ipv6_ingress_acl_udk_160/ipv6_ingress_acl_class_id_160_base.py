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

SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
DIP = T.ipv6_addr('5555:5db8:5a5b:12f0:0000:0000:0000:1111')
DIP_HOST = T.ipv6_addr('3333:0db8:0a0b:12f0:0000:0000:0000:3333')
DIP_EM = T.ipv6_addr('4444:4db8:4a4b:12f0:0000:0000:0000:4444')
DIP_DEFAULT = T.ipv6_addr('1111:bbbb:0a0b:12f0:0000:0000:0000:1111')


class ipv6_ingress_acl_class_id_160_base(sdk_test_case_base):
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl_class = ip_test_base.ipv6_test_base
    acl_key_profile_ipv6_160_class_id = None
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    CLASS_ID = 0xaf
    CLASS_ID_HOST = 0xc

    TTL = 127

    INPUT_DEFAULT_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP_DEFAULT.addr_str, hlim=TTL) / \
        TCP()

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL) / \
        TCP()

    INPUT_EM_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP_EM.addr_str, hlim=TTL) / \
        TCP()

    INPUT_HOST_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP_HOST.addr_str, hlim=TTL) / \
        TCP()

    EXPECTED_DEFAULT_OUTPUT_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) / \
        IPv6(src=SIP.addr_str, dst=DIP_DEFAULT.addr_str, hlim=TTL - 1) / \
        TCP()

    EXPECTED_OUTPUT_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL - 1) / \
        TCP()

    EXPECTED_OUTPUT_EM_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str) / \
        IPv6(src=SIP.addr_str, dst=DIP_EM.addr_str, hlim=TTL - 1) / \
        TCP()

    EXPECTED_OUTPUT_HOST_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        IPv6(src=SIP.addr_str, dst=DIP_HOST.addr_str, hlim=TTL - 1) / \
        TCP()

    INPUT_DEFAULT_PACKET, INPUT_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_DEFAULT_PACKET_BASE)
    INPUT_PACKET = add_payload(INPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_EM_PACKET = add_payload(INPUT_EM_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_HOST_PACKET = add_payload(INPUT_HOST_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_DEFAULT_OUTPUT_PACKET = add_payload(EXPECTED_DEFAULT_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET = add_payload(EXPECTED_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_EM_PACKET = add_payload(EXPECTED_OUTPUT_EM_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_HOST_PACKET = add_payload(EXPECTED_OUTPUT_HOST_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            device.set_bool_property(sdk.la_device_property_e_ENABLE_CLASS_ID_ACLS, True)

    @classmethod
    def setUpClass(cls):
        super(ipv6_ingress_acl_class_id_160_base, cls).setUpClass(
            device_config_func=ipv6_ingress_acl_class_id_160_base.device_config_func)

    def setUp(self):
        super().setUp()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)
        self.ip_impl = self.ip_impl_class()
        self.add_l3_route()

    def tearDown(self):
        super().tearDown()

    def create_ipv6_acl_key_profile(self):
        if ipv6_ingress_acl_class_id_160_base.acl_key_profile_ipv6_160_class_id is None:
            self.device.destroy(self.topology.ingress_acl_key_profile_ipv6_def)
            udk = []
            udf3 = sdk.la_acl_field_def()
            udf3.type = sdk.la_acl_field_type_e_SPORT
            udk.append(udf3)
            udf4 = sdk.la_acl_field_def()
            udf4.type = sdk.la_acl_field_type_e_IPV6_FRAGMENT
            udk.append(udf4)
            udf9 = sdk.la_acl_field_def()
            udf9.type = sdk.la_acl_field_type_e_MSG_TYPE
            udk.append(udf9)
            udf10 = sdk.la_acl_field_def()
            udf10.type = sdk.la_acl_field_type_e_MSG_CODE
            udk.append(udf10)
            udf11 = sdk.la_acl_field_def()
            udf11.type = sdk.la_acl_field_type_e_TOS
            udk.append(udf11)
            udf12 = sdk.la_acl_field_def()
            udf12.type = sdk.la_acl_field_type_e_CLASS_ID
            udk.append(udf12)
            key_type = sdk.la_acl_key_type_e_IPV6
            direction = sdk.la_acl_direction_e_INGRESS
            tcam_pool_id = 0
            ipv6_ingress_acl_class_id_160_base.acl_key_profile_ipv6_160_class_id = self.device.create_acl_key_profile(
                key_type, direction, udk, tcam_pool_id)

    def add_l3_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh, self.PRIVATE_DATA_DEFAULT)

        ecmp_group = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(ecmp_group, None)
        ecmp_group.add_member(self.l3_port_impl.reg_nh.hld_obj)

        prefix = self.ip_impl.build_prefix(DIP, length=64)

        # LPM route
        pref_dests = [
            (sdk.la_route_entry_action_e_ADD,
             prefix,
             ecmp_group,
             self.CLASS_ID,
             self.PRIVATE_DATA,
             False)]
        self.do_ip_route_bulk_updates(self.topology.vrf, pref_dests)

        prefix = self.ip_impl.build_prefix(DIP_EM, length=128)

        # LPM route
        pref_dests = [
            (sdk.la_route_entry_action_e_ADD,
             prefix,
             ecmp_group,
             self.CLASS_ID,
             self.PRIVATE_DATA,
             False)]
        self.do_ip_route_bulk_updates(self.topology.vrf, pref_dests)

        # EM host route
        subnet = self.ip_impl.build_prefix(DIP_HOST, length=128)

        self.ip_impl.add_subnet(self.l3_port_impl.tx_port, subnet)
        self.ip_impl.add_host_with_class_id(
            self.l3_port_impl.tx_port,
            DIP_HOST,
            self.l3_port_impl.reg_nh.mac_addr,
            self.CLASS_ID_HOST)

    def prepare_ip_route_bulk_updates_vec(self, pref_dests):
        prefixes_update_vec = []

        for pref_dest in pref_dests:
            action, prefix, dest, class_id, private_data, latency_sensitive = pref_dest

            prefix_update = self.ip_impl.ip_route_bulk_entry(action, prefix, dest, class_id, private_data, latency_sensitive)
            prefixes_update_vec.append(prefix_update)

        return prefixes_update_vec

    def program_ip_route_bulk(self, vrf, prefixes_update_vec):
        out_count_success = self.ip_impl.ip_route_bulk_updates(vrf, prefixes_update_vec)
        self.assertEqual(out_count_success, len(prefixes_update_vec))

    def do_ip_route_bulk_updates(self, vrf, pref_dests):
        prefixes_update_vec = self.prepare_ip_route_bulk_updates_vec(pref_dests)
        self.program_ip_route_bulk(vrf, prefixes_update_vec)

    def create_lpm_class_id_unified_acl(self):
        ''' Create simple unified ACL with a Class ID field type. '''
        self.create_ipv6_acl_key_profile()
        acl1 = self.device.create_acl(
            ipv6_ingress_acl_class_id_160_base.acl_key_profile_ipv6_160_class_id,
            self.topology.acl_command_profile_def)
        self.assertNotEqual(acl1, None)

        count = acl1.get_count()
        self.assertEqual(count, 0)

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_CLASS_ID
        f1.val.class_id = ipv6_ingress_acl_class_id_160_base.CLASS_ID
        f1.mask.class_id = 0xff
        k1.append(f1)

        cmd_nop = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = False
        cmd_nop.append(action1)

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

        acl1.append(k1, commands2)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        return acl1

    def create_host_class_id_unified_acl(self):
        ''' Create simple unified ACL with a Class ID field type. '''

        self.create_ipv6_acl_key_profile()
        acl1 = self.device.create_acl(
            ipv6_ingress_acl_class_id_160_base.acl_key_profile_ipv6_160_class_id,
            self.topology.acl_command_profile_def)
        self.assertNotEqual(acl1, None)

        count = acl1.get_count()
        self.assertEqual(count, 0)

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_CLASS_ID
        f1.val.class_id = ipv6_ingress_acl_class_id_160_base.CLASS_ID_HOST
        f1.mask.class_id = 0xf
        k1.append(f1)

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

        acl1.append(k1, commands2)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        return acl1
