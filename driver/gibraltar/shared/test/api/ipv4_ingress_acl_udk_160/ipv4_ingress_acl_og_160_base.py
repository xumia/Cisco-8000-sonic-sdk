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
import numpy as np
import ipaddress

PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
SA = T.mac_addr('be:ef:5d:35:7a:35')

# change TEST_MAX_PCL_ID to reflect the real supported max pcl id when CSCvx70714 is fixed
TEST_MAX_PCL_ID = 32


class ipv4_ingress_acl_og_160_base(sdk_test_case_base):
    acl_profile_ipv4_160_udk = None

    # IPv4
    # 0xc0c1c2c3
    SIP = T.ipv4_addr('192.193.194.195')
    # 0xd0d1d2d3
    DIP = T.ipv4_addr('208.209.210.211')
    SBINCODE = 0x7dead
    DBINCODE = 0x7beef

    TTL = 127

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
    EXPECTED_DEFAULT_OUTPUT_PACKET_SVI = add_payload(EXPECTED_DEFAULT_OUTPUT_PACKET_BASE_SVI, INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_EXTRA_OUTPUT_PACKET_SVI = add_payload(EXPECTED_EXTRA_OUTPUT_PACKET_BASE_SVI, INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_TCP_SVI = add_payload(INPUT_PACKET_TCP_BASE_SVI, INPUT_PACKET_PAYLOAD_SIZE)

    INPUT_PACKET_WITH_PAYLOAD = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
        Raw(load=unhexlify('22220db80a0b12f00000000000002222'))

    SIMPLE_QOS_COUNTER_OFFSET = 2
    QOS_MARK_DSCP = 0x18

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            device.set_int_property(sdk.la_device_property_e_MAX_NUM_PCL_GIDS, TEST_MAX_PCL_ID)
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
            udf12 = sdk.la_acl_field_def()
            udf12.type = sdk.la_acl_field_type_e_SRC_PCL_BINCODE
            udk.append(udf12)
            udf13 = sdk.la_acl_field_def()
            udf13.type = sdk.la_acl_field_type_e_DST_PCL_BINCODE
            udk.append(udf13)
            udf14 = sdk.la_acl_field_def()
            udf14.type = sdk.la_acl_field_type_e_IPV4_LENGTH
            udk.append(udf14)
            udf15 = sdk.la_acl_field_def()
            udf15.type = sdk.la_acl_field_type_e_TTL
            udk.append(udf15)
            udf16 = sdk.la_acl_field_def()
            udf16.type = sdk.la_acl_field_type_e_IPV4_FRAG_OFFSET
            udk.append(udf16)
            key_type = sdk.la_acl_key_type_e_IPV4
            direction = sdk.la_acl_direction_e_INGRESS
            tcam_pool_id = 0
            ipv4_ingress_acl_og_160_base.acl_profile_ipv4_160_udk  = device.create_acl_key_profile(
                key_type, direction, udk, tcam_pool_id)

    @classmethod
    def setUpClass(cls):
        super(ipv4_ingress_acl_og_160_base, cls).setUpClass(
            device_config_func=ipv4_ingress_acl_og_160_base.device_config_func)

    def setUp(self):
        print("SETTING MAX_NUM_PCL_GIDS == ", TEST_MAX_PCL_ID)
        super().setUp()
        self.add_default_route()
        self.inserted_drop_counter = None

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
        acl0 = self.device.create_acl(ipv4_ingress_acl_og_160_base.acl_profile_ipv4_160_udk, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl0, None)

        count = acl0.get_count()
        self.assertEqual(count, 0)

        return acl0

    def create_src_pcl(self):
        src_pcl_entry_vec = sdk.pcl_v4_vector()
        src_pcl_entry = sdk.la_pcl_v4()
        src_pcl_entry.prefix.addr.s_addr = 0x01020000
        src_pcl_entry.prefix.length = 16
        src_pcl_entry.bincode = 0x7ffff
        src_pcl_entry_vec.append(src_pcl_entry)
        src_pcl_entry = sdk.la_pcl_v4()
        src_pcl_entry.prefix.addr.s_addr = 0x04020300
        src_pcl_entry.prefix.length = 24
        src_pcl_entry.bincode = 0x7fff0
        src_pcl_entry_vec.append(src_pcl_entry)
        src_pcl_entry = sdk.la_pcl_v4()
        src_pcl_entry.prefix.addr.s_addr = self.SIP.to_num()
        src_pcl_entry.prefix.length = 32
        src_pcl_entry.bincode = self.SBINCODE
        src_pcl_entry_vec.append(src_pcl_entry)
        src_pcl_entry = sdk.la_pcl_v4()
        src_pcl_entry.prefix.addr.s_addr = self.SIP.to_num() & 0xfffffffe
        src_pcl_entry.prefix.length = 31
        src_pcl_entry.bincode = 0xfbeef
        src_pcl_entry_vec.append(src_pcl_entry)
        src_pcl_entry = sdk.la_pcl_v4()
        src_pcl_entry.prefix.addr.s_addr = self.SIP.to_num() + 16
        src_pcl_entry.prefix.length = 32
        src_pcl_entry.bincode = 0xffeed
        src_pcl_entry_vec.append(src_pcl_entry)
        src_pcl_entry = sdk.la_pcl_v4()
        src_pcl_entry.prefix.addr.s_addr = self.SIP.to_num() + 32
        src_pcl_entry.prefix.length = 32
        src_pcl_entry.bincode = 0xfdeef
        src_pcl_entry_vec.append(src_pcl_entry)
        src_pcl_entry = sdk.la_pcl_v4()
        src_pcl_entry.prefix.addr.s_addr = self.SIP.to_num() + 64
        src_pcl_entry.prefix.length = 32
        src_pcl_entry.bincode = 0xfeeef
        src_pcl_entry_vec.append(src_pcl_entry)
        src_pclEntry8 = sdk.la_pcl_v4()
        src_pclEntry8.prefix.addr.s_addr = 0x04020302
        src_pclEntry8.prefix.length = 31
        src_pclEntry8.bincode = 0x7beef
        src_pcl_entry_vec.append(src_pclEntry8)
        src_pclEntry9 = sdk.la_pcl_v4()
        src_pclEntry9.prefix.addr.s_addr = 0
        src_pclEntry9.prefix.length = 0
        src_pclEntry9.bincode = 0x70000
        src_pcl_entry_vec.append(src_pclEntry9)
        src_pcl = self.device.create_pcl(src_pcl_entry_vec, sdk.pcl_feature_type_e_ACL)
        self.assertNotEqual(src_pcl, None)
        return src_pcl

    def create_dst_pcl(self):
        dst_pcl_entry_vec = sdk.pcl_v4_vector()
        dst_pcl_entry = sdk.la_pcl_v4()
        dst_pcl_entry.prefix.addr.s_addr = 0x01020000
        dst_pcl_entry.prefix.length = 16
        dst_pcl_entry.bincode = 0x7ffff
        dst_pcl_entry_vec.append(dst_pcl_entry)
        dst_pcl_entry = sdk.la_pcl_v4()
        dst_pcl_entry.prefix.addr.s_addr = 0x04020300
        dst_pcl_entry.prefix.length = 24
        dst_pcl_entry.bincode = 0x7fff0
        dst_pcl_entry_vec.append(dst_pcl_entry)
        dst_pcl_entry = sdk.la_pcl_v4()
        dst_pcl_entry.prefix.addr.s_addr = self.DIP.to_num() & 0xfffffffe
        dst_pcl_entry.prefix.length = 31
        dst_pcl_entry.bincode = self.DBINCODE
        dst_pcl_entry_vec.append(dst_pcl_entry)
        dst_pcl_entry = sdk.la_pcl_v4()
        dst_pcl_entry.prefix.addr.s_addr = self.DIP.to_num() + 16
        dst_pcl_entry.prefix.length = 32
        dst_pcl_entry.bincode = 0xfdead
        dst_pcl_entry_vec.append(dst_pcl_entry)
        dst_pcl_entry = sdk.la_pcl_v4()
        dst_pcl_entry.prefix.addr.s_addr = self.DIP.to_num() + 32
        dst_pcl_entry.prefix.length = 32
        dst_pcl_entry.bincode = 0xfbeef
        dst_pcl_entry_vec.append(dst_pcl_entry)
        dst_pcl_entry = sdk.la_pcl_v4()
        dst_pcl_entry.prefix.addr.s_addr = self.DIP.to_num() + 48
        dst_pcl_entry.prefix.length = 32
        dst_pcl_entry.bincode = 0xffeed
        dst_pcl_entry_vec.append(dst_pcl_entry)
        dst_pcl_entry = sdk.la_pcl_v4()
        dst_pcl_entry.prefix.addr.s_addr = 0
        dst_pcl_entry.prefix.length = 0
        dst_pcl_entry.bincode = 0x70000
        dst_pcl_entry_vec.append(dst_pcl_entry)
        dst_pcl = self.device.create_pcl(dst_pcl_entry_vec, sdk.pcl_feature_type_e_ACL)
        self.assertNotEqual(dst_pcl, None)
        return dst_pcl

    def print_pcl(self, pcl, info):
        v4_vec = sdk.pcl_v4_vector()
        pcl.get_prefixes(v4_vec)
        print(info)
        for x in range(len(v4_vec)):
            print('bincode=' + hex(v4_vec[x].bincode))
            print('address=' + ipaddress.IPv4Address(v4_vec[x].prefix.addr.s_addr).__str__())
            print('length =' + str(v4_vec[x].prefix.length))

    def create_simple_sec_acl(self, is_udk, is_svi=False):
        # PCLs are only supported with UDK profiles
        if (is_udk):
            src_pcl = self.create_src_pcl()
            dst_pcl = self.create_dst_pcl()
        else:
            src_pcl = None
            dst_pcl = None

        acl1 = self.device.create_acl(ipv4_ingress_acl_og_160_base.acl_profile_ipv4_160_udk,
                                      self.topology.acl_command_profile_def,
                                      src_pcl,
                                      dst_pcl)

        self.assertNotEqual(acl1, None)

        count = acl1.get_count()
        self.assertEqual(count, 0)

        if (is_udk):
            k1 = []
            f1a = sdk.la_acl_field()
            f1a.type = sdk.la_acl_field_type_e_SRC_PCL_BINCODE
            f1a.val.src_pcl_bincode = 0x9
            f1a.mask.src_pcl_bincode = 0x7ffff
            k1.append(f1a)
            f1b = sdk.la_acl_field()
            f1b.type = sdk.la_acl_field_type_e_DST_PCL_BINCODE
            f1b.val.src_pcl_bincode = 0x5
            f1b.mask.src_pcl_bincode = 0x07ffff
            k1.append(f1b)
        else:
            k1 = []
            f1 = sdk.la_acl_field()
            f1.type = sdk.la_acl_field_type_e_IPV4_SIP
            f1.val.ipv4_sip.s_addr = self.SIP.to_num() + 1  # should not catch
            f1.mask.ipv4_sip.s_addr = 0xffffffff
            k1.append(f1)

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_IPV4_DIP
        f2.val.ipv4_dip.s_addr = self.DIP.to_num() & 0xffffff00
        f2.mask.ipv4_dip.s_addr = 0xffffff00
        k2.append(f2)
        if (is_udk):
            f2a = sdk.la_acl_field()
            f2a.type = sdk.la_acl_field_type_e_SRC_PCL_BINCODE
            f2a.val.src_pcl_bincode = self.SBINCODE
            f2a.mask.src_pcl_bincode = 0x7ffff
            k2.append(f2a)
            f2b = sdk.la_acl_field()
            f2b.type = sdk.la_acl_field_type_e_DST_PCL_BINCODE
            f2b.val.dst_pcl_bincode = self.DBINCODE
            f2b.mask.dst_pcl_bincode = 0x7ffff
            k2.append(f2b)

        k3 = []
        f3 = sdk.la_acl_field()
        f3.type = sdk.la_acl_field_type_e_IPV4_DIP
        f3.val.ipv4_dip.s_addr = self.DIP.to_num()
        f3.mask.ipv4_dip.s_addr = 0xffffffff
        k3.append(f3)
        if (is_udk):
            f3a = sdk.la_acl_field()
            f3a.type = sdk.la_acl_field_type_e_SRC_PCL_BINCODE
            f3a.val.src_pcl_bincode = self.SBINCODE
            f3a.mask.src_pcl_bincode = 0x7ffff
            k3.append(f3a)
            f3b = sdk.la_acl_field()
            f3b.type = sdk.la_acl_field_type_e_DST_PCL_BINCODE
            f3b.val.dst_pcl_bincode = self.DBINCODE
            f3b.mask.dst_pcl_bincode = 0x7ffff
            k3.append(f3b)

        cmd_nop = []

        cmd_redirect = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_L3_DESTINATION
        action1.data.l3_dest = self.topology.fec_svi_ext.hld_obj if is_svi else self.topology.fec_l3_ac_ext.hld_obj
        cmd_redirect.append(action1)

        cmd_drop = []
        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_DROP
        action2.data.drop = True
        cmd_drop.append(action2)

        acl1.append(k1, cmd_nop)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        acl1.append(k2, cmd_redirect)
        count = acl1.get_count()
        self.assertEqual(count, 2)

        acl1.append(k3, cmd_drop)
        count = acl1.get_count()
        self.assertEqual(count, 3)

        count = acl1.get_count()
        self.assertEqual(count, 3)

        acl_entry_desc = acl1.get(0)
        self.assertEqual(acl_entry_desc.key_val[0].type, k1[0].type)
        if (is_udk):
            self.assertEqual(acl_entry_desc.key_val[0].val.src_pcl_bincode, k1[0].val.src_pcl_bincode)
            self.assertEqual(acl_entry_desc.key_val[0].mask.src_pcl_bincode, k1[0].mask.src_pcl_bincode)
            self.assertEqual(acl_entry_desc.key_val[1].val.dst_pcl_bincode, k1[1].val.dst_pcl_bincode)
            self.assertEqual(acl_entry_desc.key_val[1].mask.dst_pcl_bincode, k1[1].mask.dst_pcl_bincode)
        else:
            self.assertEqual(acl_entry_desc.key_val[0].val.ipv4_sip.s_addr, k1[0].val.ipv4_sip.s_addr)
            self.assertEqual(acl_entry_desc.key_val[0].mask.ipv4_sip.s_addr, k1[0].mask.ipv4_sip.s_addr)

        acl_entry_desc = acl1.get(1)
        self.assertEqual(acl_entry_desc.key_val[0].type, k2[0].type)
        self.assertEqual(acl_entry_desc.key_val[0].val.ipv4_dip.s_addr, k2[0].val.ipv4_dip.s_addr)
        self.assertEqual(acl_entry_desc.key_val[0].mask.ipv4_dip.s_addr, k2[0].mask.ipv4_dip.s_addr)
        if (is_udk):
            self.assertEqual(acl_entry_desc.key_val[1].val.src_pcl_bincode, k2[1].val.src_pcl_bincode)
            self.assertEqual(acl_entry_desc.key_val[1].mask.src_pcl_bincode, k2[1].mask.src_pcl_bincode)
            self.assertEqual(acl_entry_desc.key_val[2].val.dst_pcl_bincode, k2[2].val.dst_pcl_bincode)
            self.assertEqual(acl_entry_desc.key_val[2].mask.dst_pcl_bincode, k2[2].mask.dst_pcl_bincode)
        self.assertEqual(acl_entry_desc.cmd_actions[0].type, action1.type)
        self.assertEqual(acl_entry_desc.cmd_actions[0].data.l3_dest.this, action1.data.l3_dest.this)

        return acl1

    def create_simple_unified_acl(self):
        acl1 = self.device.create_acl(ipv4_ingress_acl_og_160_base.acl_profile_ipv4_160_udk, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl1, None)

        count = acl1.get_count()
        self.assertEqual(count, 0)

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV4_SIP
        f1.val.ipv4_sip.s_addr = self.SIP.to_num() + 1  # should not catch
        f1.mask.ipv4_sip.s_addr = 0xffffffff
        k1.append(f1)

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_IPV4_DIP
        f2.val.ipv4_dip.s_addr = self.DIP.to_num() & 0xffffff00
        f2.mask.ipv4_dip.s_addr = 0xffffff00
        k2.append(f2)

        cmd_nop = []
        cmd_unified = []

        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_L3_DESTINATION
        action1.data.l3_dest = self.topology.nh_l3_ac_ext.hld_obj

        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_TRAFFIC_CLASS
        action2.data.traffic_class = 7

        action3 = sdk.la_acl_command_action()
        action3.type = sdk.la_acl_action_type_e_COLOR
        action3.data.color = 3

        action4 = sdk.la_acl_command_action()
        action4.type = sdk.la_acl_action_type_e_COUNTER_TYPE
        action4.data.counter_type = sdk.la_acl_counter_type_e_DO_QOS_COUNTING

        action5 = sdk.la_acl_command_action()
        action5.type = sdk.la_acl_action_type_e_QOS_OR_METER_COUNTER_OFFSET
        action5.data.qos_offset = SIMPLE_QOS_COUNTER_OFFSET

        action6 = sdk.la_acl_command_action()
        action6.type = sdk.la_acl_action_type_e_REMARK_FWD
        action6.data.remark_fwd = QOS_MARK_DSCP

        action7 = sdk.la_acl_command_action()
        action7.type = sdk.la_acl_action_type_e_ENCAP_EXP
        action7.data.encap_exp = 0

        action8 = sdk.la_acl_command_action()
        action8.type = sdk.la_acl_action_type_e_REMARK_GROUP
        action8.data.remark_group = 0

        cmd_unified.append(action1)
        cmd_unified.append(action2)
        cmd_unified.append(action3)
        cmd_unified.append(action4)
        cmd_unified.append(action5)
        cmd_unified.append(action6)
        cmd_unified.append(action7)
        cmd_unified.append(action8)

        acl1.append(k1, cmd_nop)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        acl1.append(k2, cmd_unified)
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

        if (is_punt or is_drop):
            if self.inserted_drop_counter is None:
                action3 = sdk.la_acl_command_action()
                action3.type = sdk.la_acl_action_type_e_COUNTER
                action3.data.counter = counter
                commands.append(action3)

        if (l3_dest is not None):
            action4 = sdk.la_acl_command_action()
            action4.type = sdk.la_acl_action_type_e_L3_DESTINATION
            action4.data.l3_dest = l3_dest
            commands.append(action4)

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
        f2.val.ipv4_dip.s_addr = self.DIP.to_num() & 0xffff0000
        f2.mask.ipv4_dip.s_addr = 0xffff0000
        k2.append(f2)

        cmd_redirect = []
        action1 = sdk.la_acl_command_action()
        action1.type = dk.la_acl_action_type_e_L3_DESTINATION
        action1.data.l3_dest = self.topology.fec_l3_ac_def.hld_obj
        cmd_redirect.append(action1)

        acl.set(1, k2, cmd_redirect)
        acl_entry_desc = acl.get(1)
        self.assertEqual(acl_entry_desc.key_val[0].val.ipv4_sip.s_addr, k2[0].val.ipv4_sip.s_addr)
        self.assertEqual(acl_entry_desc.cmd_actions[0].type, action1.type)

        # No change in ACE count
        count_tag = acl.get_count()
        self.assertEqual(count_tag, count)

    def create_simple_scaled_acl(self):

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
        sfk1.val.ipv4.s_addr = self.SIP.to_num() + 1  # should not catch
        sfk1.mask.ipv4.s_addr = 0xffffffff
        sfv1 = 1

        sfk2 = sdk.la_acl_scale_field_key()
        sfk2.type = sdk.la_acl_scale_field_type_e_IPV4
        sfk2.val.ipv4.s_addr = self.DIP.to_num() & 0xffffff00
        sfk2.mask.ipv4.s_addr = 0xffffff00
        sfv2 = 1

        sfk3 = sdk.la_acl_scale_field_key()
        sfk3.type = sdk.la_acl_scale_field_type_e_IPV4
        sfk3.val.ipv4.s_addr = self.DIP.to_num()
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

        cmd_nop = []

        cmd_redirect = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_L3_DESTINATION
        action1.data.l3_dest = self.topology.fec_l3_ac_ext.hld_obj
        cmd_redirect.append(action1)

        cmd_drop = []
        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_DROP
        action2.data.drop = True
        cmd_drop.append(action2)

        acl1.append(k1, cmd_nop)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        acl1.append(k2, cmd_redirect)
        count = acl1.get_count()
        self.assertEqual(count, 2)

        acl1.append(k3, cmd_drop)
        count = acl1.get_count()
        self.assertEqual(count, 3)

        return acl1

    def do_test_route_default(self, is_svi=False):
        if (is_svi):
            run_and_compare(self, self.device,
                            self.INPUT_PACKET_SVI, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                            self.EXPECTED_DEFAULT_OUTPUT_PACKET_SVI, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_SVI_DEF)
        else:
            run_and_compare(self, self.device,
                            self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                            self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

    def do_test_route_default_with_acl(self, is_svi=False):
        if (is_svi):
            run_and_compare(self, self.device,
                            self.INPUT_PACKET_SVI, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                            self.EXPECTED_EXTRA_OUTPUT_PACKET_SVI, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_SVI_EXT)
        else:
            run_and_compare(self, self.device,
                            self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                            self.EXPECTED_EXTRA_OUTPUT_PACKET, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT)

    def do_test_route_default_with_drop(self, is_svi=False):
        run_and_drop(
            self,
            self.device,
            self.INPUT_PACKET_SVI if is_svi else self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES)

    def verify_key_packet_acl(self, acl, acl_key, acl_packet, is_svi):

        # Verify a specific packet is caught by the ACL key.
        # For every tuple of key-packet
        # 1. Add the ACE with the key to the ACL with drop action.
        # 2. Check that the default packet not dropped.
        # 3. Verify that the special packet is dropped.
        # 4. Remove the ACE from the ACL

        count_pre = acl.get_count()

        cmd_drop = []
        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_DROP
        action2.data.drop = True
        cmd_drop.append(action2)

        acl.insert(0, acl_key, cmd_drop)
        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

        self.do_test_route_default_with_acl(is_svi)

        run_and_drop(self, self.device, acl_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        acl.erase(0)
        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre)

    def create_simple_qos_acl(self):

        self.device.set_acl_scaled_enabled(False)
        acl1 = self.device.create_acl(ipv4_ingress_acl_og_160_base.acl_profile_ipv4_160_udk, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl1, None)

        count = acl1.get_count()
        self.assertEqual(count, 0)

        # Should not catch
        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV4_SIP
        f1.val.ipv4_sip.s_addr = self.SIP.to_num() + 1
        f1.mask.ipv4_sip.s_addr = 0xffffffff
        k1.append(f1)

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_IPV4_DIP
        f2.val.ipv4_dip.s_addr = self.DIP.to_num() & 0xffffff00
        f2.mask.ipv4_dip.s_addr = 0xffffff00
        k2.append(f2)

        k3 = []
        f3 = sdk.la_acl_field()
        f3.type = sdk.la_acl_field_type_e_IPV4_DIP
        f3.val.ipv4_dip.s_addr = self.DIP.to_num()
        f3.mask.ipv4_dip.s_addr = 0xffffffff
        k3.append(f3)

        cmd_nop = []

        cmd_overwrite = []

        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_TRAFFIC_CLASS
        action2.data.traffic_class = 7

        action3 = sdk.la_acl_command_action()
        action3.type = sdk.la_acl_action_type_e_COLOR
        action3.data.color = 3

        action4 = sdk.la_acl_command_action()
        action4.type = sdk.la_acl_action_type_e_COUNTER_TYPE
        action4.data.counter_type = sdk.la_acl_counter_type_e_DO_QOS_COUNTING

        action5 = sdk.la_acl_command_action()
        action5.type = sdk.la_acl_action_type_e_QOS_OR_METER_COUNTER_OFFSET
        action5.data.qos_offset = SIMPLE_QOS_COUNTER_OFFSET

        action6 = sdk.la_acl_command_action()
        action6.type = sdk.la_acl_action_type_e_REMARK_FWD
        action6.data.remark_fwd = QOS_MARK_DSCP

        action7 = sdk.la_acl_command_action()
        action7.type = sdk.la_acl_action_type_e_ENCAP_EXP
        action7.data.encap_exp = 0

        action8 = sdk.la_acl_command_action()
        action8.type = sdk.la_acl_action_type_e_REMARK_GROUP
        action8.data.remark_group = 0

        cmd_overwrite.append(action2)
        cmd_overwrite.append(action3)
        cmd_overwrite.append(action4)
        cmd_overwrite.append(action5)
        cmd_overwrite.append(action6)
        cmd_overwrite.append(action7)
        cmd_overwrite.append(action8)

        acl1.append(k1, cmd_nop)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        acl1.append(k2, cmd_overwrite)
        count = acl1.get_count()
        self.assertEqual(count, 2)

        return acl1
