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
import unittest
from leaba import sdk
from scapy.all import *
from packet_test_utils import *
from ipv4_ingress_acl_base import *
import sim_utils
import topology as T
import smart_slices_choise as ssch


import ip_test_base
HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
PUNT_VLAN = 0xB13
PUNT_IFG = T.get_device_ifg(0)
PUNT_PIF_FIRST = T.get_device_first_serdes(6)
PUNT_SP_GID = 120
PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"


RX_SLICE_1 = T.get_device_slice(1)
RX_SLICE_2 = T.get_device_slice(2)
RX_IFG = 0
FIRST_SERDES = T.get_device_first_serdes(10)
LAST_SERDES = FIRST_SERDES + 1
RX_SYS_PORT_GID = 1000

PACIFIC_MAX_ACL_ENTRIES = 1024
GB_NUM_DEFAULT_ENTRIES = 21
# GB_NUM_DEFAULT_ENTRIES = 12 #MERGE HELP!
GB_MAX_ACL_ENTRIES = 5 * 1024 - GB_NUM_DEFAULT_ENTRIES
PL_MAX_ACL_ENTRIES = 4 * 1024
# We need to get the correct ipv4 sizes for Asic3 and Asic5.  The 1K and
# 8K below are the total TCAM sizes, not the size that is carved for
# ipv4 entries.
GR_MAX_ACL_ENTRIES = 1024
AR_MAX_ACL_ENTRIES = 8 * 1024


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
class test_ipv4_ingress_acl(ipv4_ingress_acl_base):
    INJECT_SLICE = T.get_device_slice(3)
    INJECT_IFG = T.get_device_ifg(0)
    INJECT_PIF_FIRST = T.get_device_first_serdes(8)
    INJECT_SP_GID = 20

    ipv4_ingress_acl_base.slice_modes = sim_utils.STANDALONE_DEV
    qos_input_packets = []
    # need to use a value 3 time smaller for AR since all ports are on one slice not 3
    RX_L3_AC_QOS_ID = 15 if decor.is_asic5() else 45
    rx_slice1_serdes = T.get_device_out_first_serdes(FIRST_SERDES)
    rx_slice2_serdes = T.get_device_out_next_first_serdes(FIRST_SERDES)
    rx_slice = T.get_device_slice(T.RX_SLICE)
    slice_ifg_serdes = [(rx_slice, T.RX_IFG, T.FIRST_SERDES),
                        (RX_SLICE_1, RX_IFG, rx_slice1_serdes),
                        (RX_SLICE_2, RX_IFG, rx_slice2_serdes)]

    def setUp(self):
        super().setUp()
        ssch.rechoose_odd_inject_slice(self, self.device)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_drop_acl_svi(self):
        acls = []
        acls.append(self.create_simple_sec_acl())

        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, acls)
        self.topology.rx_svi.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        # Add drop ACE
        self.insert_drop_ace(acls[0])
        port_counter = self.device.create_counter(1)
        self.topology.rx_svi.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, port_counter)
        self.do_test_route_default_with_drop(is_svi=True)

        # Check counter
        packet_count, byte_count = self.drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        packets, bytes = port_counter.read(0, True, True)  # Port counter should be incremented even though
        self.assertEqual(packet_count, 1)                 # the packet was dropped

        # Detach ACL
        self.topology.rx_svi.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_route_default_and_acl(self):
        acl = self.create_simple_sec_acl()

        # Test default route
        self.do_test_route_default()

        ipv4_acls = []
        ipv4_acls.append(acl)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Test default route
        self.do_test_route_default()

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_route_default_delete_acl(self):
        acl = self.create_simple_sec_acl()

        # Test default route
        self.do_test_route_default()

        ipv4_acls = []
        ipv4_acls.append(acl)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()

        # Delete ACE
        self.trim_acl_invalid(acl)
        self.trim_acl(acl)

        # Test default route
        self.do_test_route_default_with_acl()
        self.trim_acl(acl)

        # Test default route
        self.do_test_route_default()

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_route_default_delete_all_acl(self):

        # Test default route
        self.do_test_route_default()
        acl = self.create_simple_sec_acl()

        ipv4_acls = []
        ipv4_acls.append(acl)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()

        # Delete ALL ACEs
        acl.clear()
        count = acl.get_count()
        self.assertEqual(count, 0)

        # Test default route
        self.do_test_route_default()

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_route_default_update_acl(self):

        # Test default route
        self.do_test_route_default()
        acl = self.create_simple_sec_acl()

        ipv4_acls = []
        ipv4_acls.append(acl)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()
        self.update_simple_acl_to_default(acl)

        # Test default route
        self.do_test_route_default()

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skip("Test is skipped because of slow performance with dynamic allocation")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_acl_sa_scale(self):
        acl = self.create_simple_sec_acl()
        count = acl.get_count()

        ipv4_acls = []
        ipv4_acls.append(acl)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        rev = self.device.ll_device.get_device_revision()
        asic_is_pacific = rev >= sdk.la_device_revision_e_PACIFIC_A0 and rev <= sdk.la_device_revision_e_PACIFIC_B1
        asic_is_gibraltar = rev == sdk.la_device_revision_e_GIBRALTAR_A0 or rev <= sdk.la_device_revision_e_GIBRALTAR_A1
        asic_is_asic4 = rev == sdk.la_device_revision_e_ASIC4_A0
        asic_is_asic3 = rev == sdk.la_device_revision_e_ASIC3_A0
        asic_is_asic5 = rev == sdk.la_device_revision_e_ASIC5_A0
        if asic_is_pacific:
            max_acl = PACIFIC_MAX_ACL_ENTRIES
        elif asic_is_gibraltar:
            max_acl = GB_MAX_ACL_ENTRIES
        elif asic_is_asic4:
            max_acl = PL_MAX_ACL_ENTRIES
        elif asic_is_asic3:
            max_acl = GR_MAX_ACL_ENTRIES
        elif asic_is_asic5:
            max_acl = AR_MAX_ACL_ENTRIES
        else:
            raise Exception('max ACL for this ASIC version is not known')

        for i in range(count, max_acl):
            # Inserting in high position causes the ACL to be inserted at the highest line+1
            # This avoids the need to push all existing entries up, and makes the test run much faster
            self.insert_ace(acl, False, False, None, position=1000000)

        count = acl.get_count()
        self.assertEqual(count, max_acl)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_force_next_hop_acl(self):

        # Test default route
        self.do_test_route_default()
        acl = self.create_simple_sec_acl()

        ipv4_acls = []
        ipv4_acls.append(acl)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()

        # Add drop ACE
        self.insert_drop_ace(acl)
        self.do_test_route_default_with_drop()

        # Add force next hop
        self.insert_ace(acl, False, False, self.topology.nh_l3_ac_ext.hld_obj)
        self.do_test_route_default_with_acl()

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Test default route
        self.do_test_route_default()

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_ipv4_fields_acl(self):

        # Test default route
        self.do_test_route_default()
        acl = self.create_simple_sec_acl()

        ipv4_acls = []
        ipv4_acls.append(acl)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()

        key_list = []

        # Create a list with special ACL key and modified packet that will be caught by the key
        # sdk.la_set_logging_level(1, sdk.la_logger_component_e_ACCESS, sdk.la_logger_level_e_DEBUG)

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_PROTOCOL
        f1.val.protocol = 17
        f1.mask.protocol = 0xff
        k1.append(f1)
        in_packet = INPUT_PACKET.copy()
        in_packet[IP].proto = 17
        key_list.append((k1, in_packet))

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_TTL
        f2.val.ttl = 33
        f2.mask.ttl = 0xff
        k2.append(f2)
        in_packet = INPUT_PACKET.copy()
        in_packet[IP].ttl = 33
        key_list.append((k2, in_packet))

        k3 = []
        f3 = sdk.la_acl_field()
        f3.type = sdk.la_acl_field_type_e_IPV4_FLAGS
        f3.val.ipv4_flags.fragment = 0x1
        f3.mask.ipv4_flags.fragment = 0x1
        k3.append(f3)
        in_packet = INPUT_PACKET.copy()
        in_packet[IP].frag = 4
        key_list.append((k3, in_packet))

        k4 = []
        f4 = sdk.la_acl_field()
        f4.type = sdk.la_acl_field_type_e_PROTOCOL
        in_packet = INPUT_PACKET_TCP.copy()
        f4.val.protocol = in_packet[IP].proto
        f4.mask.protocol = 0xff
        k4.append(f4)
        key_list.append((k4, in_packet))

        k5 = []
        f5 = sdk.la_acl_field()
        f5.type = sdk.la_acl_field_type_e_TCP_FLAGS
        in_packet = INPUT_PACKET_TCP.copy()
        in_packet[TCP].flags = "SA"
        f5.val.tcp_flags.fields.syn = 1
        f5.val.tcp_flags.fields.ack = 1
        f5.mask.tcp_flags.flat = 0x3f
        k5.append(f5)
        key_list.append((k5, in_packet))

        k6 = []
        f6 = sdk.la_acl_field()
        f6.type = sdk.la_acl_field_type_e_SPORT
        in_packet = INPUT_PACKET_TCP.copy()
        in_packet[TCP].sport = 0xab12
        f6.val.sport = in_packet[TCP].sport
        f6.mask.sport = 0xffff
        k6.append(f6)
        key_list.append((k6, in_packet))

        k7 = []
        f7 = sdk.la_acl_field()
        f7.type = sdk.la_acl_field_type_e_DPORT
        in_packet = INPUT_PACKET_TCP.copy()
        in_packet[TCP].dport = 0xfa34
        f7.val.dport = in_packet[TCP].dport
        f7.mask.dport = 0xffff
        k7.append(f7)
        key_list.append((k7, in_packet))

        k8 = []
        f8 = sdk.la_acl_field()
        f8.type = sdk.la_acl_field_type_e_MSG_TYPE
        in_packet = INPUT_PACKET.copy()
        in_packet[ICMP].type = 8
        in_packet[ICMP].code = 23
        f8.val.mtype = in_packet[ICMP].type
        f8.mask.mtype = 0xff
        k8.append(f8)
        f9 = sdk.la_acl_field()
        f9.type = sdk.la_acl_field_type_e_MSG_CODE
        f9.val.mcode = in_packet[ICMP].code
        f9.mask.mcode = 0xff
        k8.append(f9)
        key_list.append((k8, in_packet))

        # For every tuple of key-packet in the list
        for key_packet in key_list:
            self.verify_key_packet_acl(acl, key_packet[0], key_packet[1])

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Test default route
        self.do_test_route_default()

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_ipv4_fields2_acl(self):

        # Test default route
        self.do_test_route_default()
        acl = self.create_simple_sec_acl()

        ipv4_acls = []
        ipv4_acls.append(acl)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()

        key_list = []

        # Create a list with special ACL key and modified packet that will be caught by the key
        # sdk.la_set_logging_level(1, sdk.la_logger_component_e_ACCESS, sdk.la_logger_level_e_DEBUG)

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_PROTOCOL
        f1.val.protocol = 17
        f1.mask.protocol = 0xff
        k1.append(f1)
        in_packet = INPUT_PACKET.copy()
        in_packet[IP].proto = 17
        key_list.append((k1, in_packet))

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_TTL
        f2.val.ttl = 33
        f2.mask.ttl = 0xff
        k2.append(f2)
        in_packet = INPUT_PACKET.copy()
        in_packet[IP].ttl = 33
        key_list.append((k2, in_packet))

        k3 = []
        f3 = sdk.la_acl_field()
        f3.type = sdk.la_acl_field_type_e_IPV4_FLAGS
        f3.val.ipv4_flags.fragment = 0x1
        f3.mask.ipv4_flags.fragment = 0x1
        k3.append(f3)
        in_packet = INPUT_PACKET.copy()
        in_packet[IP].frag = 4
        key_list.append((k3, in_packet))

        k4 = []
        f4 = sdk.la_acl_field()
        f4.type = sdk.la_acl_field_type_e_PROTOCOL
        in_packet = INPUT_PACKET_TCP.copy()
        f4.val.protocol = in_packet[IP].proto
        f4.mask.protocol = 0xff
        k4.append(f4)
        key_list.append((k4, in_packet))

        k5 = []
        f5 = sdk.la_acl_field()
        f5.type = sdk.la_acl_field_type_e_TCP_FLAGS
        in_packet = INPUT_PACKET_TCP.copy()
        in_packet[TCP].flags = "SA"
        f5.val.tcp_flags.fields.syn = 1
        f5.val.tcp_flags.fields.ack = 1
        f5.mask.tcp_flags.flat = 0x3f
        k5.append(f5)
        key_list.append((k5, in_packet))

        k6 = []
        f6 = sdk.la_acl_field()
        f6.type = sdk.la_acl_field_type_e_SPORT
        in_packet = INPUT_PACKET_TCP.copy()
        in_packet[TCP].sport = 0xab12
        f6.val.sport = in_packet[TCP].sport
        f6.mask.sport = 0xffff
        k6.append(f6)
        key_list.append((k6, in_packet))

        k7 = []
        f7 = sdk.la_acl_field()
        f7.type = sdk.la_acl_field_type_e_DPORT
        in_packet = INPUT_PACKET_TCP.copy()
        in_packet[TCP].dport = 0xfa34
        f7.val.dport = in_packet[TCP].dport
        f7.mask.dport = 0xffff
        k7.append(f7)
        key_list.append((k7, in_packet))

        k8 = []
        f8 = sdk.la_acl_field()
        f8.type = sdk.la_acl_field_type_e_MSG_TYPE
        in_packet = INPUT_PACKET.copy()
        in_packet[ICMP].type = 8
        in_packet[ICMP].code = 23
        f8.val.mtype = in_packet[ICMP].type
        f8.mask.mtype = 0xff

        f9 = sdk.la_acl_field()
        f9.type = sdk.la_acl_field_type_e_MSG_CODE
        f9.val.mcode = in_packet[ICMP].code
        f9.mask.mcode = 0xff
        k8.append(f9)
        k8.append(f8)
        key_list.append((k8, in_packet))

        # For every tuple of key-packet in the list
        for key_packet in key_list:
            self.verify_key_packet_acl(acl, key_packet[0], key_packet[1])

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Test default route
        self.do_test_route_default()

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_multislice_acl(self):
        acl = self.create_simple_sec_acl()
        ipv4_acls = []
        ipv4_acls.append(acl)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        self.insert_nop_ace(acl)

        # Apply on another slice
        self.topology.tx_l3_ac_reg.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default()
        self.insert_drop_ace(acl)
        self.do_test_route_default_with_drop()

        # Check counter (not clearing)
        packet_count, byte_count = self.drop_counter.read(0, True, False)
        self.assertEqual(packet_count, 1)

        # Remove and reapply on slice, while still applied to other
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # self.do_test_route_default()
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_drop()

        # Check counter (not clearing)
        packet_count, byte_count = self.drop_counter.read(0, True, False)
        self.assertEqual(packet_count, 2)

        # Remove in other order
        self.topology.tx_l3_ac_reg.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.do_test_route_default_with_drop()

        # Check counter
        packet_count, byte_count = self.drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 3)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        self.do_test_route_default()

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_nop_acl(self):
        acl = self.create_simple_sec_acl()

        # Test default route
        self.do_test_route_default()

        ipv4_acls = []
        ipv4_acls.append(acl)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()

        # Add drop ACE
        self.insert_drop_ace(acl)
        self.do_test_route_default_with_drop()

        # Check counter
        packet_count, byte_count = self.drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        port_counter = self.device.create_counter(8)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, port_counter)
        self.topology.rx_l3_ac.hld_obj.set_drop_counter_offset(sdk.la_stage_e_INGRESS, 1)

        # Add NOP ACE
        self.insert_nop_ace(acl)
        self.do_test_route_default()

        # Check port counter
        packet_count, bytes = port_counter.read(0, True, True)  # Port counter should be incremented
        self.assertEqual(packet_count, 1)

        # Check counter
        packet_count, byte_count = self.nop_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Test default route
        self.do_test_route_default()

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_drop_acl(self):
        acl = self.create_simple_sec_acl()

        # Test default route
        self.do_test_route_default()

        ipv4_acls = []
        ipv4_acls.append(acl)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()

        # Add drop ACE
        self.insert_drop_ace(acl)

        port_counter = self.device.create_counter(8)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, port_counter)
        self.topology.rx_l3_ac.hld_obj.set_drop_counter_offset(sdk.la_stage_e_INGRESS, 1)

        # Test dropped packet
        self.do_test_route_default_with_drop()

        # Check counters
        packet_count, byte_count = self.drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 0)

        packet_count, byte_count = self.drop_counter.read(1, True, True)
        self.assertEqual(packet_count, 1)

        packet_count, bytes = port_counter.read(0, True, True)  # Port counter shouldn't be incremented if the packet was dropped
        self.assertEqual(packet_count, 0)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Test default route
        self.do_test_route_default()

    def create_lpts_instance(self):
        ssch.rechoose_odd_inject_slice(self, self.device)
        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            PUNT_SP_GID,
            PUNT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        self.punt_dest1 = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION1_GID,
            pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN)

        self.lpts = self.device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV4)
        self.assertNotEqual(self.lpts, None)

        k0 = sdk.la_lpts_key()
        k0.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k0.val.ipv4.sip.s_addr = SIP.to_num()
        k0.mask.ipv4.sip.s_addr = 0xffffffff

        result = sdk.la_lpts_result()
        result.dest = self.punt_dest1
        result.meter = None
        result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True)

        self.lpts.append(k0, result)

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_qos_acl(self):
        acl = self.create_simple_qos_acl()

        # Test default route
        # Pass packet with no ACL applied, ensure PHB remains default (0).
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0}}
        run_and_compare_inner_fields(self, self.device,
                                     INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                     control_expected)

        # Attach a Q counter
        q_counter = self.device.create_counter(8)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, q_counter)

        # Attach a P counter
        p_counter = self.device.create_counter(1)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, p_counter)

        # Attach the QoS ACL
        ipv4_acls = []
        ipv4_acls.append(acl)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # Pass packet with ACL applied, ensure DSCP and PHB changes to non-default.
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1F}}
        expected_output_packet = EXPECTED_DEFAULT_OUTPUT_PACKET.copy()
        expected_output_packet[IP].tos = QOS_MARK_DSCP << 2
        run_and_compare_inner_fields(self, self.device,
                                     INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     expected_output_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                     control_expected)

        # Verify Q counter
        packet_count, byte_count = q_counter.read(SIMPLE_QOS_COUNTER_OFFSET, True, True)
        self.assertEqual(packet_count, 1)
        assertPacketLengthIngress(self, INPUT_PACKET, T.RX_SLICE, byte_count)

        # Verify P counter
        packet_count, byte_count = p_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        assertPacketLengthIngress(self, INPUT_PACKET, T.RX_SLICE, byte_count)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Pass packet with no ACL applied, ensure PHB remains default (0).
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0}}
        run_and_compare_inner_fields(self, self.device,
                                     INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                     control_expected)

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_qos_32_class_map(self):
        acl2 = self.create_simple_qos_acl2()

        # Attach a Q counter
        q_counter = self.device.create_counter(32)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, q_counter)

        # Attach the QoS ACL
        ipv4_acls = []
        ipv4_acls.append(acl2)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # Pass packet with ACL applied, ensure DSCP and PHB changes to non-default.
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1F}}
        expected_output_packet = EXPECTED_DEFAULT_OUTPUT_PACKET.copy()
        expected_output_packet[IP].tos = QOS_MARK_DSCP << 2
        run_and_compare_inner_fields(self, self.device,
                                     INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     expected_output_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                     control_expected)

        # Verify Q counter
        packet_count, byte_count = q_counter.read(EXT_QOS_COUNTER_OFFSET, True, True)
        self.assertEqual(packet_count, 1)
        assertPacketLengthIngress(self, INPUT_PACKET, T.RX_SLICE, byte_count)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_reserve_acl(self):
        # Create reserved drop_acl
        drop_acl = self.create_empty_acl()
        self.insert_drop_ace(drop_acl)
        self.device.reserve_acl(drop_acl)

        # Create user defined simple sec acl acl
        acl = self.create_simple_sec_acl()

        # Test before and after applying acl
        self.do_test_route_default()

        ipv4_acls = []
        ipv4_acls.append(acl)
        acl_group1 = []
        acl_group1 = self.device.create_acl_group()
        acl_group1.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group1)
        self.do_test_route_default_with_acl()

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Test after use drop_acl
        acls_drop = []
        acls_drop.append(drop_acl)
        acl_group2 = []
        acl_group2 = self.device.create_acl_group()
        acl_group2.set_acls(sdk.la_acl_packet_format_e_IPV4, acls_drop)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group2)
        self.do_test_route_default_with_drop()

        # Check drop count
        packet_count, byte_count = self.drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Add drop ACE to acl
        self.insert_drop_ace(acl)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group1)
        self.do_test_route_default_with_drop()

        # Detach ACL acl
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Test default route
        self.do_test_route_default()

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_two_acls(self):

        # Create two ACLs, add NOP to the first and DROP to the second. Attach the second to the port.
        acl1 = self.create_simple_sec_acl()
        acl2 = self.create_simple_sec_acl()

        # Test default route
        self.do_test_route_default()

        ipv4_acls1 = []
        ipv4_acls1.append(acl1)
        acl_group1 = []
        acl_group1 = self.device.create_acl_group()
        acl_group1.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls1)

        ipv4_acls2 = []
        ipv4_acls2.append(acl2)
        acl_group2 = []
        acl_group2 = self.device.create_acl_group()
        acl_group2.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls2)

        # Attach the second ACL
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group2)
        self.do_test_route_default_with_acl()

        # Execute a get on the acl
        acl_group = self.topology.rx_l3_ac.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, acl_group2.this)

        # Add NOP ACE to the first ACL - should have no effect
        self.insert_nop_ace(acl1)
        self.do_test_route_default_with_acl()

        # Add drop ACE to the second ACL
        self.insert_drop_ace(acl2)
        self.do_test_route_default_with_drop()

        # Check counter
        packet_count, byte_count = self.drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Switch to use first ACL
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group1)

        # Execute a get on the acl
        acl_group = self.topology.rx_l3_ac.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, acl_group1.this)

        # Test default route (NOP)
        self.do_test_route_default()

        # Switch back to second ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group2)

        # Execute a get on the acl
        acl_group = self.topology.rx_l3_ac.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, acl_group2.this)

        self.do_test_route_default_with_drop()

        # Check counter
        packet_count, byte_count = self.drop_counter.read(0, True, False)
        self.assertEqual(packet_count, 1)

        # Delete first ACL, should have no affect
        self.device.destroy(acl_group1)
        self.device.destroy(acl1)
        # Execute a get on the acl
        acl_group = self.topology.rx_l3_ac.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, acl_group2.this)

        self.do_test_route_default_with_drop()

        # Check counter
        packet_count, byte_count = self.drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 2)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
        # Execute a get on the acl
        acl_group = self.topology.rx_l3_ac.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group, None)

        # Test default route
        self.do_test_route_default()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_unified_acl(self):
        acl1 = self.create_simple_unified_acl()

        # Test default route
        # Pass packet with no ACL applied, ensure PHB remains default (0).
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0}}
        run_and_compare_inner_fields(self, self.device,
                                     INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                     control_expected)

        # Attach a Q counter
        q_counter = self.device.create_counter(8)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, q_counter)

        # Attach a P counter
        p_counter = self.device.create_counter(1)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, p_counter)

        # Attach the Unified ACL
        ipv4_acls = []
        ipv4_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # Pass packet with ACL applied, ensure DSCP and PHB changes to non-default.
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1F}}
        expected_output_packet = EXPECTED_EXTRA_OUTPUT_PACKET.copy()
        expected_output_packet[IP].tos = QOS_MARK_DSCP << 2
        run_and_compare_inner_fields(self, self.device,
                                     INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     expected_output_packet, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT,
                                     control_expected)

        # Verify Q counter
        packet_count, byte_count = q_counter.read(SIMPLE_QOS_COUNTER_OFFSET, True, True)
        self.assertEqual(packet_count, 1)
        assertPacketLengthIngress(self, INPUT_PACKET, T.RX_SLICE, byte_count)

        # Verify P counter
        packet_count, byte_count = p_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        assertPacketLengthIngress(self, INPUT_PACKET, T.RX_SLICE, byte_count)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Pass packet with no ACL applied, ensure PHB remains default (0).
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0}}
        run_and_compare_inner_fields(self, self.device,
                                     INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                     control_expected)

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_punt_acl(self):
        ssch.rechoose_odd_inject_slice(self, self.device)
        acl1 = self.create_simple_sec_acl()

        # Test default route
        self.do_test_route_default()

        ipv4_acls = []
        ipv4_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()

        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        punt_dest = T.create_l2_punt_destination(self, self.device, T.L2_PUNT_DESTINATION2_GID, pi_port, HOST_MAC_ADDR, PUNT_VLAN)

        # Change drop to punt
        self.device.set_trap_configuration(
            sdk.LA_EVENT_L3_ACL_FORCE_PUNT,
            0,
            None,
            punt_dest,
            False,
            False,
            True, 0)

        # Add punt ACE
        self.insert_punt_ace(acl1)

        # Test punted packet
        punt_packet = Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
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

        run_and_compare(self, self.device,
                        INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        punt_packet, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)

        # Check counter
        packet_count, byte_count = self.punt_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Test default route
        self.do_test_route_default()

    def get_slice_ifg_serdes(self, index):
        return (self.slice_ifg_serdes[index % 3])

    def packet_test(self, phb):
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': phb}}
        for current_qos_index in range(0, self.RX_L3_AC_QOS_ID):
            slice, ifg, serdes = self.get_slice_ifg_serdes(current_qos_index)
            run_and_compare_inner_fields(self, self.device,
                                         self.qos_input_packets[current_qos_index], slice, ifg, serdes,
                                         EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                         control_expected)

    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Mathilda models.")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_qos_acl_scale(self):

        # 16 QoS profiles supported but, there is a default profile
        # allocated already in topology.py
        RX_L3_AC_QOS_GID_START = 0x860
        RX_L3_AC_QOS_VID1_START = 0x100
        RX_L3_AC_QOS_VID2_START = 0x200

        qos_profiles = []
        rx_l3_qos_acs = []
        qos_acls = []
        q_counters = []
        p_counters = []
        rx_slice1_serdes = T.get_device_out_first_serdes(FIRST_SERDES)
        rx_slice2_serdes = T.get_device_out_next_first_serdes(FIRST_SERDES)
        rx_slice1_last_serdes = T.get_device_out_last_serdes(LAST_SERDES)
        rx_slice2_last_serdes = T.get_device_out_next_last_serdes(LAST_SERDES)
        self.rx_eth_port1 = T.ethernet_port(
            self,
            self.device,
            RX_SLICE_1,
            RX_IFG,
            RX_SYS_PORT_GID,
            rx_slice1_serdes,
            rx_slice1_last_serdes)
        self.rx_eth_port2 = T.ethernet_port(
            self,
            self.device,
            RX_SLICE_2,
            RX_IFG,
            RX_SYS_PORT_GID + 1,
            rx_slice2_serdes,
            rx_slice2_last_serdes)
        for current_qos_index in range(0, self.RX_L3_AC_QOS_ID):
            qos_profiles.append(T.ingress_qos_profile(self, self.device))
            qos_profiles[current_qos_index].set_default_values()

            if ((current_qos_index % 3) == 0):
                ethport = self.topology.rx_eth_port
            if ((current_qos_index % 3) == 1):
                ethport = self.rx_eth_port1
            if ((current_qos_index % 3) == 2):
                ethport = self.rx_eth_port2
            # Create new L3 AC ports
            temp_ac = T.l3_ac_port(self, self.device,
                                   (RX_L3_AC_QOS_GID_START + current_qos_index),
                                   ethport,
                                   self.topology.vrf,
                                   T.RX_L3_AC_MAC,
                                   (RX_L3_AC_QOS_VID1_START + current_qos_index),
                                   (RX_L3_AC_QOS_VID2_START + current_qos_index),
                                   qos_profiles[current_qos_index])

            rx_l3_qos_acs.append(temp_ac)
            rx_l3_qos_acs[current_qos_index].hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
            rx_l3_qos_acs[current_qos_index].hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

            # Set up input packets
            input_packet_base = Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
                Dot1Q(vlan=RX_L3_AC_QOS_VID1_START + current_qos_index, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=RX_L3_AC_QOS_VID2_START + current_qos_index) / \
                IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
                ICMP()
            self.qos_input_packets.append(add_payload(input_packet_base, INPUT_PACKET_PAYLOAD_SIZE))
            # Create 15 ACLs,there is a default profile created in l3_ac_port already
            # add NOP to the first and DROP to the second. Attach the second to the port.
            qos_acls.append(self.create_simple_qos_acl())

        # Check L3 AC ports with traffic without QoS attached
        self.packet_test(0)
        logging.debug("Initial packet tests on {num} ACs passed".format(num=self.RX_L3_AC_QOS_ID))

        # Attach QoS ACL and verify rewrite and counters
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1F}}
        expected_output_packet = EXPECTED_DEFAULT_OUTPUT_PACKET.copy()
        expected_output_packet[IP].tos = QOS_MARK_DSCP << 2
        for current_qos_index in range(0, self.RX_L3_AC_QOS_ID):
            logging.debug("Verifying packet on AC {num} after QoS ACL attached".format(num=current_qos_index))
            # Attach a Q counter
            q_counter = self.device.create_counter(8)
            rx_l3_qos_acs[current_qos_index].hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, q_counter)
            q_counters.append(q_counter)
            # Attach a P counter
            p_counter = self.device.create_counter(1)
            rx_l3_qos_acs[current_qos_index].hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, p_counter)
            p_counters.append(p_counter)

            # Attach the QoS ACL
            ipv4_acls = []
            ipv4_acls.append(qos_acls[current_qos_index])
            acl_group = []
            acl_group = self.device.create_acl_group()
            acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
            rx_l3_qos_acs[current_qos_index].hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

            slice, ifg, serdes = self.get_slice_ifg_serdes(current_qos_index)
            run_and_compare_inner_fields(self, self.device,
                                         self.qos_input_packets[current_qos_index], slice, ifg, serdes,
                                         expected_output_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                         control_expected)
            # Verify Q counter
            packet_count, byte_count = q_counters[current_qos_index].read(SIMPLE_QOS_COUNTER_OFFSET, True, True)
            logging.debug("Q {num}: packet: {pkt}, byte: {byte}".format(num=current_qos_index, pkt=packet_count, byte=byte_count))
            self.assertEqual(packet_count, 1)
            self.assertEqual(
                byte_count,
                get_injected_packet_len(
                    self.device,
                    self.qos_input_packets[current_qos_index], slice))

            # Verify P counter
            packet_count, byte_count = p_counters[current_qos_index].read(0, True, True)
            logging.debug("P {num}: packet: {pkt}, byte: {byte}".format(num=current_qos_index, pkt=packet_count, byte=byte_count))
            self.assertEqual(packet_count, 1)

        # Pass packet with no ACL applied, ensure PHB remains default (0).
        logging.debug("Verifying packet on AC after QoS ACL detached")
        for current_qos_index in range(0, self.RX_L3_AC_QOS_ID):
            # Detach ACL
            rx_l3_qos_acs[current_qos_index].hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        self.packet_test(0)
        print("----------------------------------------------- test_qos_acl_scale === ended")

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_fifteen_qos_acls(self):
        # 15 QoS profiles supported but, there is a default profile
        # allocated already in topology.py
        RX_L3_AC_QOS_NUM_GIDS = 14
        RX_L3_AC_QOS_GID_START = 0x860
        RX_L3_AC_QOS_VID1_START = 0x100
        RX_L3_AC_QOS_VID2_START = 0x200

        qos_profiles = []
        rx_l3_qos_acs = []
        qos_input_packets = []
        qos_acls = []
        for current_qos_index in range(0, RX_L3_AC_QOS_NUM_GIDS):
            # Set up QoS profiles
            qos_profiles.append(T.ingress_qos_profile(self, self.device))
            qos_profiles[current_qos_index].set_default_values()

            # Create new L3 AC ports
            temp_ac = T.l3_ac_port(self, self.device,
                                   (RX_L3_AC_QOS_GID_START + current_qos_index),
                                   self.topology.rx_eth_port,
                                   self.topology.vrf,
                                   T.RX_L3_AC_MAC,
                                   (RX_L3_AC_QOS_VID1_START + current_qos_index),
                                   (RX_L3_AC_QOS_VID2_START + current_qos_index),
                                   qos_profiles[current_qos_index])

            rx_l3_qos_acs.append(temp_ac)
            rx_l3_qos_acs[current_qos_index].hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
            rx_l3_qos_acs[current_qos_index].hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

            # Set up input packets
            input_packet_base = Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
                Dot1Q(vlan=RX_L3_AC_QOS_VID1_START + current_qos_index, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=RX_L3_AC_QOS_VID2_START + current_qos_index) / \
                IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
                ICMP()
            # add
            qos_input_packets.append(add_payload(input_packet_base, INPUT_PACKET_PAYLOAD_SIZE))

            # Create 14 ACLs,there is a default profile created in l3_ac_port already
            # add NOP to the first and DROP to the second. Attach the second to the port.
            qos_acls.append(self.create_simple_qos_acl())

        # Check L3 AC ports with traffic without QoS attached
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0}}
        for current_qos_index in range(0, RX_L3_AC_QOS_NUM_GIDS):
            run_and_compare_inner_fields(self, self.device,
                                         qos_input_packets[current_qos_index], T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                         EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                         control_expected)

        logging.debug("Initial packet tests on {num} ACs passed".format(num=RX_L3_AC_QOS_NUM_GIDS))

        # Attach a Q counter
        q_counters = []
        p_counters = []
        for current_qos_index in range(0, RX_L3_AC_QOS_NUM_GIDS):
            # Attach a Q counter
            q_counter = self.device.create_counter(8)
            rx_l3_qos_acs[current_qos_index].hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, q_counter)
            q_counters.append(q_counter)
            # Attach a P counter
            p_counter = self.device.create_counter(1)
            rx_l3_qos_acs[current_qos_index].hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, p_counter)
            p_counters.append(p_counter)

            # Attach the QoS ACL
            ipv4_acls = []
            ipv4_acls.append(qos_acls[current_qos_index])
            acl_group = []
            acl_group = self.device.create_acl_group()
            acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
            rx_l3_qos_acs[current_qos_index].hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1F}}
        expected_output_packet = EXPECTED_DEFAULT_OUTPUT_PACKET.copy()
        expected_output_packet[IP].tos = QOS_MARK_DSCP << 2
        for current_qos_index in range(0, RX_L3_AC_QOS_NUM_GIDS):
            logging.debug("Verifying packet on AC {num} after QoS ACL attached".format(num=current_qos_index))
            run_and_compare_inner_fields(self, self.device,
                                         qos_input_packets[current_qos_index], T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                         expected_output_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                         control_expected)
            # Verify Q counter
            packet_count, byte_count = q_counters[current_qos_index].read(SIMPLE_QOS_COUNTER_OFFSET, True, True)
            logging.debug("Q {num}: packet: {pkt}, byte: {byte}".format(num=current_qos_index, pkt=packet_count, byte=byte_count))
            self.assertEqual(packet_count, 1)
            self.assertEqual(
                byte_count,
                get_injected_packet_len(
                    self.device,
                    qos_input_packets[current_qos_index], T.RX_SLICE))

            # Verify P counter
            packet_count, byte_count = p_counters[current_qos_index].read(0, True, True)
            logging.debug("P {num}: packet: {pkt}, byte: {byte}".format(num=current_qos_index, pkt=packet_count, byte=byte_count))
            self.assertEqual(packet_count, 1)

        # Pass packet with no ACL applied, ensure PHB remains default (0).
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0}}
        for current_qos_index in range(0, RX_L3_AC_QOS_NUM_GIDS):
            # Detach ACL
            rx_l3_qos_acs[current_qos_index].hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
            logging.debug("Verifying packet on AC {num} after QoS ACL detached".format(num=current_qos_index))

            run_and_compare_inner_fields(self, self.device,
                                         qos_input_packets[current_qos_index], T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                         EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                         control_expected)

    def skip_test_qos_acl_with_lpts(self):
        ssch.rechoose_odd_inject_slice(self, self.device)
        acl = self.create_simple_qos_acl()

        # Attach a Q counter
        q_counter = self.device.create_counter(8)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, q_counter)

        # Attach the QoS ACL
        ipv4_acls = []
        ipv4_acls.append(acl)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        self.create_lpts_instance()
        self.ip_impl = ip_test_base.ipv4_test_base()
        prefix = self.ip_impl.build_prefix(DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.topology.forus_dest, PRIVATE_DATA_DEFAULT)
        run_and_compare(self, self.device,
                        INPUT_PACKET_UC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        PUNT_PACKET_UC, self.INJECT_SLICE, self.INJECT_IFG, PUNT_PIF_FIRST)

        # Verify Q counter
        packet_count, byte_count = q_counter.read(SIMPLE_QOS_COUNTER_OFFSET, True, True)
        self.assertEqual(packet_count, 0)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Delete the route added for this test.
        self.ip_impl.delete_route(self.topology.vrf, prefix)

        self.lpts.clear()

        count = self.lpts.get_count()
        self.assertEqual(count, 0)

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_qos_acl_meter_action_without_remark(self):
        acl3 = self.create_simple_qos_acl3()

        METER_SET_SIE = 8
        meter_set = T.create_meter_set(self, self.device, is_aggregate=False, set_size=METER_SET_SIE)

        egress_counter = self.device.create_counter(sdk.LA_NUM_EGRESS_TRAFFIC_CLASSES)

        ingress_qos_profile_new = T.ingress_qos_profile(self, self.device)
        ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_enabled(True)
        ingress_qos_profile_new.set_default_values()
        for i in range(sdk.LA_MAX_DSCP):
            IN_DSCP = sdk.la_ip_dscp()
            IN_DSCP.value = i
            TAG_IP_DSCP = sdk.la_ip_dscp()
            TAG_IP_DSCP.value = 32
            ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV4, IN_DSCP, TAG_IP_DSCP)

        IN_DSCP = sdk.la_ip_dscp()
        IN_DSCP.value = 8
        TAG_IP_DSCP = sdk.la_ip_dscp()
        TAG_IP_DSCP.value = 8
        ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV4, IN_DSCP, TAG_IP_DSCP)

        egress_qos_profile_new = T.egress_qos_profile(self, self.device)
        egress_qos_profile_new.set_default_values()
        egress_qos_profile_new.hld_obj.set_counter_offset_mapping(TAG_IP_DSCP, 1)

        self.topology.rx_l3_ac.hld_obj.set_meter(meter_set)
        self.topology.rx_l3_ac.hld_obj.set_ingress_qos_profile(ingress_qos_profile_new.hld_obj)
        self.topology.tx_l3_ac_def.hld_obj.set_egress_qos_profile(egress_qos_profile_new.hld_obj)
        self.topology.tx_l3_ac_def.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_QOS, egress_counter)

        ipv4_acls = []
        ipv4_acls.append(acl3)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # Set up input packet
        input_packet = INPUT_PACKET.copy()
        input_packet[IP].tos = IN_DSCP.value << 2

        output_packet = EXPECTED_DEFAULT_OUTPUT_PACKET.copy()
        output_packet[IP].tos = IN_DSCP.value << 2

        run_and_compare(self, self.device,
                        input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        output_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        packet_count, byte_count = egress_counter.read(1, True, True)
        self.assertEqual(packet_count, 1)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_qos_acl_tc_marking_with_counter(self):
        acl4 = self.create_simple_qos_acl4()

        COUNTER_SET_SIZE = 8
        ingress_counter = self.device.create_counter(COUNTER_SET_SIZE)

        ingress_qos_profile_new = T.ingress_qos_profile(self, self.device)
        ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_enabled(True)
        ingress_qos_profile_new.set_default_values()
        for i in range(sdk.LA_MAX_DSCP):
            IN_DSCP = sdk.la_ip_dscp()
            IN_DSCP.value = i
            TAG_IP_DSCP = sdk.la_ip_dscp()
            TAG_IP_DSCP.value = 32
            ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV4, IN_DSCP, TAG_IP_DSCP)

        IN_DSCP = sdk.la_ip_dscp()
        IN_DSCP.value = 16
        TAG_IP_DSCP = sdk.la_ip_dscp()
        TAG_IP_DSCP.value = 16
        ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV4, IN_DSCP, TAG_IP_DSCP)

        egress_counter = self.device.create_counter(COUNTER_SET_SIZE)

        egress_qos_profile_new = T.egress_qos_profile(self, self.device)
        egress_qos_profile_new.set_default_values()
        egress_qos_profile_new.hld_obj.set_counter_offset_mapping(TAG_IP_DSCP, 2)

        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, ingress_counter)
        self.topology.rx_l3_ac.hld_obj.set_ingress_qos_profile(ingress_qos_profile_new.hld_obj)
        self.topology.tx_l3_ac_def.hld_obj.set_egress_qos_profile(egress_qos_profile_new.hld_obj)
        self.topology.tx_l3_ac_def.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_QOS, egress_counter)

        ipv4_acls = []
        ipv4_acls.append(acl4)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # Set up input packet
        input_packet = INPUT_PACKET.copy()
        input_packet[IP].tos = IN_DSCP.value << 2

        output_packet = EXPECTED_DEFAULT_OUTPUT_PACKET.copy()
        output_packet[IP].tos = IN_DSCP.value << 2

        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1f}}
        run_and_compare(self, self.device,
                        input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        output_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                        control_expected)

        packet_count, byte_count = ingress_counter.read(2, True, True)
        self.assertEqual(packet_count, 1)

        packet_count, byte_count = egress_counter.read(2, True, True)
        self.assertEqual(packet_count, 1)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_qos_acl_counter_and_qos_mapping(self):
        acl5 = self.create_simple_qos_acl5()

        COUNTER_SET_SIZE = 2
        ingress_counter = self.device.create_counter(COUNTER_SET_SIZE)

        ingress_qos_profile_new = T.ingress_qos_profile(self, self.device)
        ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_enabled(True)
        ingress_qos_profile_new.set_default_values()
        for i in range(sdk.LA_MAX_DSCP):
            IN_DSCP = sdk.la_ip_dscp()
            IN_DSCP.value = i
            ingress_qos_profile_new.hld_obj.set_meter_or_counter_offset_mapping(sdk.la_ip_version_e_IPV4, IN_DSCP, 1)

        egress_qos_profile_new = T.egress_qos_profile(self, self.device)
        egress_qos_profile_new.set_default_values()

        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, ingress_counter)
        self.topology.rx_l3_ac.hld_obj.set_ingress_qos_profile(ingress_qos_profile_new.hld_obj)
        self.topology.tx_l3_ac_def.hld_obj.set_egress_qos_profile(egress_qos_profile_new.hld_obj)

        ipv4_acls = []
        ipv4_acls.append(acl5)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # Test ingress QoS ACL result.
        IN_DSCP = sdk.la_ip_dscp()
        IN_DSCP.value = 16

        # Set up input packet
        input_packet = INPUT_PACKET.copy()
        input_packet[IP].tos = IN_DSCP.value << 2

        output_packet = EXPECTED_DEFAULT_OUTPUT_PACKET.copy()
        output_packet[IP].tos = 0xE0

        run_and_compare(self, self.device,
                        input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        output_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        packet_count, byte_count = ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        packet_count, byte_count = ingress_counter.read(1, True, True)
        self.assertEqual(packet_count, 0)

        # Test QoS mapping result.
        IN_DSCP = sdk.la_ip_dscp()
        IN_DSCP.value = 32

        # Set up input packet
        input_packet = INPUT_PACKET.copy()
        input_packet[IP].tos = IN_DSCP.value << 2

        output_packet = EXPECTED_DEFAULT_OUTPUT_PACKET.copy()
        output_packet[IP].tos = IN_DSCP.value << 2

        run_and_compare(self, self.device,
                        input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        output_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        packet_count, byte_count = ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 0)

        packet_count, byte_count = ingress_counter.read(1, True, True)
        self.assertEqual(packet_count, 1)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)


if __name__ == '__main__':
    unittest.main()
