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
from ip_test_base import ipv6_test_base
import ipaddress

PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
SA = T.mac_addr('be:ef:5d:35:7a:35')

SIMPLE_QOS_COUNTER_OFFSET = 2
QOS_MARK_DSCP = 0x13


class ipv6_ingress_acl_og_160_base(sdk_test_case_base):
    ip_impl_class = ip_test_base.ipv6_test_base

    SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')
    SBINCODE1 = 0x7eeee
    DBINCODE1 = 0x7daaa
    SBINCODE2 = 0x70fff
    DBINCODE2 = 0x55555
    DEFAULT = T.ipv6_addr('0000:0000:0000:0000:0000:0000:0000:0000')

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

    INPUT_PACKET_SVI, INPUT_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_SVI_BASE)
    INPUT_PACKET = add_payload(INPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_WITH_EH = add_payload(INPUT_PACKET_WITH_EH_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_DEFAULT_OUTPUT_PACKET = add_payload(EXPECTED_DEFAULT_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_EXTRA_OUTPUT_PACKET = add_payload(EXPECTED_EXTRA_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_UDP = add_payload(INPUT_PACKET_UDP_BASE, INPUT_PACKET_PAYLOAD_SIZE)

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            device.set_int_property(sdk.la_device_property_e_MAX_NUM_PCL_GIDS, 32)

    @classmethod
    def setUpClass(cls):
        super(ipv6_ingress_acl_og_160_base, cls).setUpClass(
            device_config_func=ipv6_ingress_acl_og_160_base.device_config_func)

    def setUp(self):
        super().setUp()
        self.ip_impl = self.ip_impl_class()
        self.add_default_route()
        self.inserted_drop_counter = None
        self.acl_profile_ipv6_160_udk = self.create_acl_profile_ipv6_160_udk()

    def tearDown(self):
        super().tearDown()

    def add_default_route(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=0)
        self.topology.vrf.hld_obj.add_ipv6_route(prefix, self.topology.nh_l3_ac_def.hld_obj, PRIVATE_DATA_DEFAULT, False)

    def create_acl_profile_ipv6_160_udk(self):
        udk = []
        udf1 = sdk.la_acl_field_def()
        udf1.type = sdk.la_acl_field_type_e_SPORT
        udk.append(udf1)
        udf2 = sdk.la_acl_field_def()
        udf2.type = sdk.la_acl_field_type_e_DPORT
        udk.append(udf2)
        udf3 = sdk.la_acl_field_def()
        udf3.type = sdk.la_acl_field_type_e_IPV6_FRAGMENT
        udk.append(udf3)
        udf4 = sdk.la_acl_field_def()
        udf4.type = sdk.la_acl_field_type_e_IPV6_LENGTH
        udk.append(udf4)
        udf5 = sdk.la_acl_field_def()
        udf5.type = sdk.la_acl_field_type_e_TCP_FLAGS
        udk.append(udf5)
        udf6 = sdk.la_acl_field_def()
        udf6.type = sdk.la_acl_field_type_e_TOS
        udk.append(udf6)
        udf7 = sdk.la_acl_field_def()
        udf7.type = sdk.la_acl_field_type_e_SRC_PCL_BINCODE
        udk.append(udf7)
        udf8 = sdk.la_acl_field_def()
        udf8.type = sdk.la_acl_field_type_e_DST_PCL_BINCODE
        udk.append(udf8)
        udf9 = sdk.la_acl_field_def()
        udf9.type = sdk.la_acl_field_type_e_HOP_LIMIT
        udk.append(udf9)

        key_type = sdk.la_acl_key_type_e_IPV6
        direction = sdk.la_acl_direction_e_INGRESS
        tcam_pool_id = 0
        acl_key_profile = self.device.create_acl_key_profile(key_type, direction, udk, tcam_pool_id)

        return acl_key_profile

    def create_empty_acl(self):
        acl0 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl0, None)

        count = acl0.get_count()
        self.assertEqual(count, 0)

        return acl0

    def b_prefix(self, dip, length):
        prefix = sdk.la_ipv6_prefix_t()
        q0 = sdk.get_ipv6_addr_q0(dip.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(dip.hld_obj)
        masked_q0, masked_q1 = ipv6_test_base.apply_prefix_mask(q0, q1, length)
        sdk.set_ipv6_addr(prefix.addr, masked_q0, masked_q1)
        prefix.length = length
        return prefix

    def create_src_pcl(self, is_em):
        SIP2 = T.ipv6_addr('4444:0db8:0a0b:12f0:0000:0000:0000:2222')
        SIP3 = T.ipv6_addr('6666:0db8:0a0b:12f0:0000:0000:0000:2222')
        SIP4 = T.ipv6_addr('7666:0db8:0a0b:12f0:0000:0000:0000:7222')
        SIP5 = T.ipv6_addr('6666:5db8:0a0b:12f0:0000:0000:0000:9222')
        src_pcl_entry_vec = sdk.pcl_v6_vector()
        src_pcl_entry = sdk.la_pcl_v6()
        if (is_em):
            src_pcl_entry.prefix = self.b_prefix(self.SIP, 128)
            src_pcl_entry.bincode = self.SBINCODE2
        else:
            src_pcl_entry.prefix = self.b_prefix(self.SIP, 127)
            src_pcl_entry.bincode = self.SBINCODE1
        src_pcl_entry_vec.append(src_pcl_entry)
        src_pcl_entry = sdk.la_pcl_v6()
        if (is_em):
            src_pcl_entry.prefix = self.b_prefix(self.SIP, 127)
        else:
            src_pcl_entry.prefix = self.b_prefix(SIP2, 128)
        src_pcl_entry.bincode = 0xdbeef
        src_pcl_entry_vec.append(src_pcl_entry)
        src_pcl_entry = sdk.la_pcl_v6()
        src_pcl_entry.prefix = self.b_prefix(SIP2, 64)
        src_pcl_entry.bincode = 0x71234
        src_pcl_entry_vec.append(src_pcl_entry)
        src_pcl_entry = sdk.la_pcl_v6()
        src_pcl_entry.prefix = self.b_prefix(SIP3, 32)
        src_pcl_entry.bincode = 0x75678
        src_pcl_entry_vec.append(src_pcl_entry)
        src_pcl_entry = sdk.la_pcl_v6()
        src_pcl_entry.prefix = self.b_prefix(SIP4, 128)
        src_pcl_entry.bincode = 0x75678
        src_pcl_entry_vec.append(src_pcl_entry)
        src_pcl_entry = sdk.la_pcl_v6()
        src_pcl_entry.prefix = self.b_prefix(SIP5, 127)
        src_pcl_entry.bincode = 0x75678
        src_pcl_entry_vec.append(src_pcl_entry)
        src_pcl_entry = sdk.la_pcl_v6()
        src_pcl_entry.prefix = self.b_prefix(self.DEFAULT, 0)
        src_pcl_entry.bincode = 0x7dead
        src_pcl_entry_vec.append(src_pcl_entry)
        src_pcl = self.device.create_pcl(src_pcl_entry_vec, sdk.pcl_feature_type_e_ACL)
        self.assertNotEqual(src_pcl, None)
        return src_pcl

    def create_dst_pcl(self, is_em):
        DIP2 = T.ipv6_addr('5555:0db8:0a0b:12f0:0000:0000:0000:1111')
        DIP3 = T.ipv6_addr('7777:0db8:0a0b:12f0:0000:0000:0000:1111')
        DIP4 = T.ipv6_addr('7776:0db8:0a0b:12f0:0000:0000:0000:1112')
        DIP5 = T.ipv6_addr('8776:0db8:0a0b:12f0:0000:0000:0000:1112')
        dst_pcl_entry_vec = sdk.pcl_v6_vector()
        dst_pcl_entry = sdk.la_pcl_v6()
        if (is_em):
            dst_pcl_entry.prefix = self.b_prefix(self.DIP, 128)
            dst_pcl_entry.bincode = self.DBINCODE1
        else:
            dst_pcl_entry.prefix = self.b_prefix(self.DIP, 127)
            dst_pcl_entry.bincode = self.DBINCODE2
        dst_pcl_entry_vec.append(dst_pcl_entry)
        dst_pcl_entry = sdk.la_pcl_v6()
        if (is_em):
            dst_pcl_entry.prefix = self.b_prefix(self.DIP, 127)
        else:
            dst_pcl_entry.prefix = self.b_prefix(DIP2, 128)
        dst_pcl_entry.bincode = 0xfdead
        dst_pcl_entry_vec.append(dst_pcl_entry)
        dst_pcl_entry = sdk.la_pcl_v6()
        dst_pcl_entry.prefix = self.b_prefix(DIP2, 64)
        dst_pcl_entry.bincode = 0x7d234
        dst_pcl_entry_vec.append(dst_pcl_entry)
        dst_pcl_entry = sdk.la_pcl_v6()
        dst_pcl_entry.prefix = self.b_prefix(DIP3, 32)
        dst_pcl_entry.bincode = 0x7d678
        dst_pcl_entry_vec.append(dst_pcl_entry)
        dst_pcl_entry = sdk.la_pcl_v6()
        dst_pcl_entry.prefix = self.b_prefix(DIP4, 128)
        dst_pcl_entry.bincode = 0x7c678
        dst_pcl_entry_vec.append(dst_pcl_entry)
        dst_pcl_entry = sdk.la_pcl_v6()
        dst_pcl_entry.prefix = self.b_prefix(DIP5, 128)
        dst_pcl_entry.bincode = 0x7d978
        dst_pcl_entry_vec.append(dst_pcl_entry)
        dst_pcl_entry = sdk.la_pcl_v6()
        dst_pcl_entry.prefix = self.b_prefix(self.DEFAULT, 0)
        dst_pcl_entry.bincode = 0x7dead
        dst_pcl_entry_vec.append(dst_pcl_entry)

        dst_pcl = self.device.create_pcl(dst_pcl_entry_vec, sdk.pcl_feature_type_e_ACL)
        self.assertNotEqual(dst_pcl, None)
        return dst_pcl

    def print_pcl(self, pcl, info):
        v6_vec = sdk.pcl_v6_vector()
        pcl.get_prefixes(v6_vec)
        print(info)
        for x in range(len(v6_vec)):
            print('bincode=' + hex(v6_vec[x].bincode))
            print('address=' + ipaddress.IPv6Address(v6_vec[x].prefix.addr.q_addr[1] <<
                                                     64 | v6_vec[x].prefix.addr.q_addr[0]).__str__())
            print('length =' + str(v6_vec[x].prefix.length))

    def create_simple_sec_acl(self, src_is_em, dst_is_em, is_udk):
        if (is_udk):
            src_pcl = self.create_src_pcl(src_is_em)
            dst_pcl = self.create_dst_pcl(dst_is_em)
            acl_key_profile = self.acl_profile_ipv6_160_udk
        else:
            src_pcl = None
            dst_pcl = None
            acl_key_profile = self.topology.ingress_acl_key_profile_ipv6_def

        acl1 = self.device.create_acl(acl_key_profile,
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
            f1a.val.src_pcl_bincode = 0x0
            f1a.mask.src_pcl_bincode = 0x7ffff
            k1.append(f1a)
            f1b = sdk.la_acl_field()
            f1b.type = sdk.la_acl_field_type_e_DST_PCL_BINCODE
            f1b.val.src_pcl_bincode = 0x0
            f1b.mask.src_pcl_bincode = 0x07ffff
            k1.append(f1b)

            k2 = []
            f4 = sdk.la_acl_field()
            f4.type = sdk.la_acl_field_type_e_SRC_PCL_BINCODE
            if (src_is_em):
                f4.val.src_pcl_bincode = self.SBINCODE2
            else:
                f4.val.src_pcl_bincode = self.SBINCODE1
            f4.mask.src_pcl_bincode = 0x7ffff
            k2.append(f4)

            k3 = []
            f3 = sdk.la_acl_field()
            f3.type = sdk.la_acl_field_type_e_SRC_PCL_BINCODE
            f3.val.src_pcl_bincode = 0
            f3.mask.src_pcl_bincode = 0
            k3.append(f3)
            f6 = sdk.la_acl_field()
            f6.type = sdk.la_acl_field_type_e_DST_PCL_BINCODE
            f6.val.dst_pcl_bincode = 0
            f6.mask.dst_pcl_bincode = 0
            k3.append(f6)

            f5 = sdk.la_acl_field()
            f5.type = sdk.la_acl_field_type_e_DST_PCL_BINCODE
            if (dst_is_em):
                f5.val.dst_pcl_bincode = self.DBINCODE1
            else:
                f5.val.dst_pcl_bincode = self.DBINCODE2
            f5.mask.dst_pcl_bincode = 0x7ffff
            k2.append(f5)

        else:
            k1 = []
            f1 = sdk.la_acl_field()
            f1.type = sdk.la_acl_field_type_e_IPV6_SIP
            q0 = sdk.get_ipv6_addr_q0(self.SIP.hld_obj)
            q1 = sdk.get_ipv6_addr_q1(self.SIP.hld_obj)
            # Should not catch
            sdk.set_ipv6_addr(f1.val.ipv6_sip, q0 + 1, q1)
            sdk.set_ipv6_addr(f1.mask.ipv6_sip, 0xffffffffffffffff, 0xffffffffffffffff)
            k1.append(f1)

            k2 = []
            f2 = sdk.la_acl_field()
            f2.type = sdk.la_acl_field_type_e_IPV6_DIP
            q0 = sdk.get_ipv6_addr_q0(self.DIP.hld_obj)
            q1 = sdk.get_ipv6_addr_q1(self.DIP.hld_obj)
            # Will catch
            sdk.set_ipv6_addr(f2.val.ipv6_dip, q0 & 0xffffffffffff0000, q1)
            sdk.set_ipv6_addr(f2.mask.ipv6_dip, 0xffffffffffff0000, 0xffffffffffffffff)
            k2.append(f2)

            k3 = []
            f3 = sdk.la_acl_field()
            f3.type = sdk.la_acl_field_type_e_IPV6_DIP
            sdk.set_ipv6_addr(f3.val.ipv6_dip, q0, q1)
            sdk.set_ipv6_addr(f3.mask.ipv6_dip, 0xffffffffffffffff, 0xffffffffffffffff)
            k3.append(f3)

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

    def create_simple_unified_acl(self):
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)
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

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_IPV6_DIP
        q0 = sdk.get_ipv6_addr_q0(self.DIP.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(self.DIP.hld_obj)
        # Will catch
        sdk.set_ipv6_addr(f2.val.ipv6_dip, q0 & 0xffffffffffff0000, q1)
        sdk.set_ipv6_addr(f2.mask.ipv6_dip, 0xffffffffffff0000, 0xffffffffffffffff)
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

    def insert_ace(self, acl, is_drop, is_punt, l3_dest):
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
            action3 = sdk.la_acl_command_action()
            action3.type = sdk.la_acl_action_type_e_COUNTER
            action3.data.counter = counter
            commands.append(action3)
            self.inserted_drop_counter = counter

        if (l3_dest is not None):
            action4 = sdk.la_acl_command_action()
            action4.type = sdk.la_acl_action_type_e_L3_DESTINATION
            action4.data.l3_dest = l3_dest
            commands.append(action4)

        count_pre = acl.get_count()
        acl.insert(0, k1, commands)

        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)
        return counter

    def insert_drop_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in drop. '''
        print(''' Insert ACE that catch all traffic and result in drop. ''')
        return self.insert_ace(acl, True, False, None)

    def insert_punt_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in drop. '''
        return self.insert_ace(acl, False, True, None)

    def insert_nop_ace(self, acl):
        ''' Insert ACE that catch all traffic and result in NOP. '''
        return self.insert_ace(acl, False, False, None)

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

    def update_simple_acl_to_default(self, acl):
        ''' Update the simple ACL to redirect to the default FEC. '''

        count = acl.get_count()

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_IPV6_DIP
        q0 = sdk.get_ipv6_addr_q0(self.DIP.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(self.DIP.hld_obj)
        sdk.set_ipv6_addr(f2.val.ipv6_dip, q0 & 0xffffffffffff0000, q1)
        sdk.set_ipv6_addr(f2.mask.ipv6_dip, 0xffffffffffff0000, 0xffffffffffffffff)
        k2.append(f2)

        cmd_redirect = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_L3_DESTINATION
        action1.data.l3_dest = self.topology.fec_l3_ac_def.hld_obj
        cmd_redirect.append(action1)

        acl.set(1, k2, cmd_redirect)

        # No change in ACE count
        count_tag = acl.get_count()
        self.assertEqual(count_tag, count)

    def do_test_route_default(self, is_svi=False):
        run_and_compare(self, self.device,
                        self.INPUT_PACKET_SVI if is_svi else self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

    def do_test_route_default_with_acl(self, is_svi=False):
        run_and_compare(self, self.device,
                        self.INPUT_PACKET_SVI if is_svi else self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        self.EXPECTED_EXTRA_OUTPUT_PACKET, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3)

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

        cmd_drop = []
        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_DROP
        action2.data.drop = True
        cmd_drop.append(action2)

        acl.insert(0, acl_key, cmd_drop)
        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

        self.do_test_route_default_with_acl()
        run_and_drop(self, self.device, acl_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        acl.erase(0)
        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre)

    def create_simple_qos_acl(self):
        self.device.set_acl_scaled_enabled(False)
        acl1 = self.device.create_acl(sdk.la_acl.stage_e_INGRESS_FWD,
                                      sdk.la_acl.type_e_QOS, self.topology.acl_profile_ipv6_def)
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

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_IPV6_DIP
        q0 = sdk.get_ipv6_addr_q0(self.DIP.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(self.DIP.hld_obj)
        # Will catch
        sdk.set_ipv6_addr(f2.val.ipv6_dip, q0 & 0xffffffffffff0000, q1)
        sdk.set_ipv6_addr(f2.mask.ipv6_dip, 0xffffffffffff0000, 0xffffffffffffffff)
        k2.append(f2)

        k3 = []
        f3 = sdk.la_acl_field()
        f3.type = sdk.la_acl_field_type_e_IPV6_DIP
        sdk.set_ipv6_addr(f3.val.ipv6_dip, q0, q1)
        sdk.set_ipv6_addr(f3.mask.ipv6_dip, 0xffffffffffffffff, 0xffffffffffffffff)
        k3.append(f3)

        cmd_nop = []
        cmd_overwrite = []

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

        cmd_overwrite.append(action1)
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
