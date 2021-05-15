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


class udf_data:

    BITS_IN_QWORD = 64

    def __init__(self, data_str):
        self.data_str = data_str
        self.hld_obj = sdk.la_acl_udf_data()
        q0 = self.to_num() & ((1 << udf_data.BITS_IN_QWORD) - 1)
        q1 = (self.to_num() >> udf_data.BITS_IN_QWORD) & ((1 << udf_data.BITS_IN_QWORD) - 1)
        sdk.set_udf_data(self.hld_obj, q0, q1)

    def __init__(self, udf_data_byte_wide):
        self.hld_obj = sdk.la_acl_udf_data()
        q0 = udf_data_byte_wide & ((1 << udf_data.BITS_IN_QWORD) - 1)
        q1 = 0
        sdk.set_udf_data(self.hld_obj, q0, q1)


class ipv6_ingress_acl_udk_160_base(sdk_test_case_base):
    ip_impl_class = ip_test_base.ipv6_test_base

    SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

    DROP_TTL = 63
    FWD_TTL = 64

    INPUT_HLIM64_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=FWD_TTL) / \
        TCP()

    INPUT_HLIM63_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=DROP_TTL) / \
        TCP()

    EXPECTED_ACL_FWD_OUTPUT_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=FWD_TTL - 1) / \
        TCP()

    EXPECTED_ACL_DROP_OUTPUT_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=DROP_TTL - 1) / \
        TCP()

    _, INPUT_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_HLIM64_PACKET_BASE)
    INPUT_HLIM_64_PACKET = add_payload(INPUT_HLIM64_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_HLIM_63_PACKET = add_payload(INPUT_HLIM63_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_ACL_FWD_OUTPUT_PACKET = add_payload(EXPECTED_ACL_FWD_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_ACL_DROP_OUTPUT_PACKET = add_payload(EXPECTED_ACL_DROP_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)

    acl_profile_ipv6_160_udk = None

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            udk = []
            # IPv6 HOP limit
            udf1 = sdk.la_acl_field_def()
            udf1.type = sdk.la_acl_field_type_e_UDF
            udf1.udf_desc.index = 1
            udf1.udf_desc.protocol_layer = 0
            udf1.udf_desc.header = 0
            udf1.udf_desc.offset = 7
            udf1.udf_desc.width = 1
            udf1.udf_desc.is_relative = True
            udk.append(udf1)

            key_type = sdk.la_acl_key_type_e_IPV6
            direction = sdk.la_acl_direction_e_INGRESS
            tcam_pool_id = 0
            ipv6_ingress_acl_udk_160_base.acl_profile_ipv6_160_udk = device.create_acl_key_profile(
                key_type, direction, udk, tcam_pool_id)

    @classmethod
    def setUpClass(cls):
        super(ipv6_ingress_acl_udk_160_base, cls).setUpClass(
            device_config_func=ipv6_ingress_acl_udk_160_base.device_config_func)

    def setUp(self):
        super().setUp()
        self.ip_impl = self.ip_impl_class()
        self.add_default_route()
        self.inserted_drop_counter = None

    def tearDown(self):
        super().tearDown()

    def add_default_route(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=0)
        self.topology.vrf.hld_obj.add_ipv6_route(prefix, self.topology.nh_l3_ac_def.hld_obj, PRIVATE_DATA_DEFAULT, False)

    def create_empty_acl(self):
        ''' Create empty ACL. '''
        acl0 = self.device.create_acl(ipv6_ingress_acl_udk_160_base.acl_profile_ipv6_160_udk, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl0, None)

        count = acl0.get_count()
        self.assertEqual(count, 0)

        return acl0

    def create_simple_sec_acl_hlim_as_udf(self):
        ''' Create simple security ACL. '''
        acl1 = self.device.create_acl(ipv6_ingress_acl_udk_160_base.acl_profile_ipv6_160_udk, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl1, None)

        count = acl1.get_count()
        self.assertEqual(count, 0)

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_UDF
        f1.udf_index = 1
        UDF = udf_data(ipv6_ingress_acl_udk_160_base.FWD_TTL)  # HOPLIMIT value as UDF with no drop acl action
        q0 = sdk.get_udf_data_q0(UDF.hld_obj)
        q1 = sdk.get_udf_data_q1(UDF.hld_obj)
        sdk.set_udf_data(f1.val.udf, q0, q1)
        sdk.set_udf_data(f1.mask.udf, q0, q1)
        k1.append(f1)

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_UDF
        f2.udf_index = 1
        UDF = udf_data(ipv6_ingress_acl_udk_160_base.DROP_TTL)  # HOPLIMIT value as UDF with drop acl action
        q0 = sdk.get_udf_data_q0(UDF.hld_obj)
        q1 = sdk.get_udf_data_q1(UDF.hld_obj)
        sdk.set_udf_data(f2.val.udf, q0, q1)
        sdk.set_udf_data(f2.mask.udf, q0, q1)
        k2.append(f2)

        cmd_nop = []
        cmd_drop = []
        action = sdk.la_acl_command_action()
        action.type = sdk.la_acl_action_type_e_DROP
        action.data.drop = True
        cmd_drop.append(action)

        acl1.append(k1, cmd_nop)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        acl1.append(k2, cmd_drop)
        count = acl1.get_count()
        self.assertEqual(count, 2)

        acl_entry_desc = acl1.get(0)
        self.assertEqual(acl_entry_desc.key_val[0].type, k1[0].type)
        self.assertEqual(acl_entry_desc.key_val[0].udf_index, k1[0].udf_index)
        self.assertEqual(acl_entry_desc.key_val[0].val.udf.q_data[1], f1.val.udf.q_data[1])
        self.assertEqual(acl_entry_desc.key_val[0].val.udf.q_data[0], f1.val.udf.q_data[0])
        self.assertEqual(acl_entry_desc.key_val[0].mask.udf.q_data[1], f1.mask.udf.q_data[1])
        self.assertEqual(acl_entry_desc.key_val[0].mask.udf.q_data[0], f1.mask.udf.q_data[0])

        acl_entry_desc = acl1.get(1)
        self.assertEqual(acl_entry_desc.key_val[0].type, k2[0].type)
        self.assertEqual(acl_entry_desc.key_val[0].udf_index, k2[0].udf_index)
        self.assertEqual(acl_entry_desc.key_val[0].val.udf.q_data[1], f2.val.udf.q_data[1])
        self.assertEqual(acl_entry_desc.key_val[0].val.udf.q_data[0], f2.val.udf.q_data[0])
        self.assertEqual(acl_entry_desc.key_val[0].mask.udf.q_data[1], f2.mask.udf.q_data[1])
        self.assertEqual(acl_entry_desc.key_val[0].mask.udf.q_data[0], f2.mask.udf.q_data[0])
        self.assertEqual(acl_entry_desc.cmd_actions[0].type, action.type)

        return acl1

    def do_test_route_default(self):
        # without acl getting applied.
        run_and_compare(self, self.device,
                        self.INPUT_HLIM_64_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        self.EXPECTED_ACL_FWD_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3)
        run_and_compare(self, self.device,
                        self.INPUT_HLIM_63_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        self.EXPECTED_ACL_DROP_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3)

    def do_test_route_default_with_hlim_acl(self):
        # with acl getting applied.
        run_and_compare(self, self.device,
                        self.INPUT_HLIM_64_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        self.EXPECTED_ACL_FWD_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3)
        # input pkt with hlim 63 should be dropped.
        run_and_drop(self, self.device,
                     self.INPUT_HLIM_63_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
