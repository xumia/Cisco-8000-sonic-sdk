#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import ip_test_base
from packet_test_utils import *
from scapy.all import *
from ipv6_ingress_acl_base import *
import sim_utils
import topology as T
import smart_slices_choise as ssch

HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
PUNT_VLAN = 0xB13
PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"


RX_SLICE_1 = T.get_device_slice(1)
RX_SLICE_2 = T.get_device_slice(2)
RX_IFG = 0
FIRST_SERDES = T.get_device_first_serdes(10)
LAST_SERDES = T.get_device_last_serdes(11)
RX_SYS_PORT_GID = 1000

PACIFIC_MAX_ACL_ENTRIES = 1024
GB_NUM_DEFAULT_ENTRIES = 9
GB_MAX_ACL_ENTRIES = 3 * 1024 - GB_NUM_DEFAULT_ENTRIES


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
class test_ipv6_ingress_acl(ipv6_ingress_acl_base):
    INJECT_SLICE = T.get_device_slice(3)
    INJECT_IFG = 0
    INJECT_PIF_FIRST = T.get_device_first_serdes(8)
    INJECT_SP_GID = 20

    qos_input_packets = []
    RX_L3_AC_QOS_ID = 15 if decor.is_asic5() else 42
    rx_slice1_serdes = T.get_device_out_first_serdes(FIRST_SERDES)
    rx_slice2_serdes = T.get_device_out_next_first_serdes(FIRST_SERDES)
    rx_slice = T.get_device_slice(T.RX_SLICE)
    slice_ifg_serdes = [(rx_slice, T.RX_IFG, T.FIRST_SERDES),
                        (RX_SLICE_1, RX_IFG, rx_slice1_serdes),
                        (RX_SLICE_2, RX_IFG, rx_slice2_serdes)]

    def setUp(self):
        super().setUp()
        ssch.rechoose_odd_inject_slice(self, self.device)

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_drop_acl_svi(self):
        acl1 = self.create_simple_sec_acl()

        ipv6_acls = []
        ipv6_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)
        self.topology.rx_svi.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # Add drop ACE
        self.insert_drop_ace(acl1)
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
    def test_drop_acl(self):
        acl1 = self.create_simple_sec_acl()

        # Test default route
        self.do_test_route_default()

        ipv6_acls = []
        ipv6_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()

        # Add drop ACE
        self.insert_drop_ace(acl1)
        port_counter = self.device.create_counter(8)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, port_counter)
        self.topology.rx_l3_ac.hld_obj.set_drop_counter_offset(sdk.la_stage_e_INGRESS, 1)

        # Test dropped packet
        self.do_test_route_default_with_drop()

        # Check counter
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

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_ipv6_fields_acl(self):
        acl1 = self.create_simple_sec_acl()

        # Test default route
        self.do_test_route_default()

        ipv6_acls = []
        ipv6_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()

        key_list = []

        # Create a list with special ACL key and modified packet that will be caught by the key

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_LAST_NEXT_HEADER
        f1.val.last_next_header = 6
        f1.mask.last_next_header = 0xff
        k1.append(f1)
        in_packet = self.INPUT_PACKET.copy()
        key_list.append((k1, in_packet))

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_SPORT
        in_packet = self.INPUT_PACKET.copy()
        in_packet[TCP].sport = 0xab12
        f2.val.sport = in_packet[TCP].sport
        f2.mask.sport = 0xffff
        k2.append(f2)
        key_list.append((k2, in_packet))

        k3 = []
        f3 = sdk.la_acl_field()
        f3.type = sdk.la_acl_field_type_e_DPORT
        in_packet = self.INPUT_PACKET.copy()
        in_packet[TCP].dport = 0xfa34
        f3.val.dport = in_packet[TCP].dport
        f3.mask.dport = 0xffff
        k3.append(f3)
        key_list.append((k3, in_packet))

        k4 = []
        f4 = sdk.la_acl_field()
        f4.type = sdk.la_acl_field_type_e_MSG_TYPE
        in_packet = self.INPUT_PACKET_WITH_ICMP.copy()
        in_packet[ICMP].type = 8
        in_packet[ICMP].code = 23
        f4.val.mtype = in_packet[ICMP].type
        f4.mask.mtype = 0xff
        k4.append(f4)

        f5 = sdk.la_acl_field()
        f5.type = sdk.la_acl_field_type_e_MSG_CODE
        f5.val.mcode = in_packet[ICMP].code
        f5.mask.mcode = 0xff
        k4.append(f5)
        key_list.append((k4, in_packet))

        k6 = []
        f6 = sdk.la_acl_field()
        f6.type = sdk.la_acl_field_type_e_MSG_TYPE
        in_packet = self.INPUT_PACKET_WITH_EH_AND_ICMP.copy()
        in_packet[ICMP].type = 8
        in_packet[ICMP].code = 23
        f6.val.mtype = in_packet[ICMP].type
        f6.mask.mtype = 0xff
        k6.append(f6)

        f7 = sdk.la_acl_field()
        f7.type = sdk.la_acl_field_type_e_MSG_CODE
        f7.val.mcode = in_packet[ICMP].code
        f7.mask.mcode = 0xff
        k6.append(f7)
        key_list.append((k6, in_packet))

        k8 = []
        f8 = sdk.la_acl_field()
        f8.type = sdk.la_acl_field_type_e_LAST_NEXT_HEADER
        f8.val.last_next_header = 17
        f8.mask.last_next_header = 0xff
        k8.append(f8)
        in_packet = self.INPUT_PACKET_WITH_EH.copy()
        key_list.append((k8, in_packet))

        k9 = []
        f9 = sdk.la_acl_field()
        f9.type = sdk.la_acl_field_type_e_DPORT
        in_packet = self.INPUT_PACKET_WITH_EH.copy()
        in_packet[UDP].dport = 22
        f9.val.dport = in_packet[UDP].dport
        f9.mask.dport = 0xffff
        k9.append(f9)
        key_list.append((k9, in_packet))

        k10 = []
        f10 = sdk.la_acl_field()
        f10.type = sdk.la_acl_field_type_e_DPORT
        in_packet = self.INPUT_PACKET_W_MULTIPLE_EH.copy()
        in_packet[TCP].dport = 22
        f10.val.dport = in_packet[TCP].dport
        f10.mask.dport = 0xffff
        k10.append(f10)
        key_list.append((k10, in_packet))

        k11 = []
        f11 = sdk.la_acl_field()
        f11.type = sdk.la_acl_field_type_e_DPORT
        in_packet = self.INPUT_PACKET_W_TCP_EH.copy()
        in_packet[TCP].dport = 87
        f11.val.dport = in_packet[TCP].dport
        f11.mask.dport = 0xffff
        k11.append(f11)
        key_list.append((k11, in_packet))

        # Not-first fragment
        k12 = []
        f12 = sdk.la_acl_field()
        f12.type = sdk.la_acl_field_type_e_IPV6_FRAGMENT
        f12.val.ipv6_fragment.fragment = 0x1
        f12.mask.ipv6_fragment.fragment = 0x1
        k12.append(f12)
        in_packet = self.INPUT_PACKET_W_FRAG_EH.copy()
        in_packet[4].offset = 4
        key_list.append((k12, in_packet))

        # First fragment
        k13 = []
        f13 = sdk.la_acl_field()
        f13.type = sdk.la_acl_field_type_e_IPV6_FRAGMENT
        f13.val.ipv6_fragment.fragment = 0x0
        f13.mask.ipv6_fragment.fragment = 0x1
        k13.append(f13)
        in_packet = self.INPUT_PACKET_W_FRAG_EH.copy()
        in_packet[4].m = 0x1
        key_list.append((k13, in_packet))

        k14 = []
        f14 = sdk.la_acl_field()
        f14.type = sdk.la_acl_field_type_e_TCP_FLAGS
        in_packet = self.INPUT_PACKET_W_TCP_EH.copy()
        in_packet[TCP].flags = "SA"
        f14.val.tcp_flags.fields.syn = 1
        f14.val.tcp_flags.fields.ack = 1
        f14.mask.tcp_flags.flat = 0x3f
        k14.append(f14)
        key_list.append((k14, in_packet))

        k15 = []
        f15 = sdk.la_acl_field()
        f15.type = sdk.la_acl_field_type_e_LAST_NEXT_HEADER
        in_packet = self.INPUT_PACKET_RAW.copy()
        f15.val.last_next_header = 0x2f
        f15.mask.last_next_header = 0xff
        k15.append(f15)
        key_list.append((k15, in_packet))

        k16 = []
        f16 = sdk.la_acl_field()
        f16.type = sdk.la_acl_field_type_e_LAST_NEXT_HEADER
        in_packet = self.INPUT_PACKET_WITH_ICMP.copy()
        f16.val.last_next_header = 0x3a
        f16.mask.last_next_header = 0xff
        k16.append(f16)
        key_list.append((k16, in_packet))

        # For every tuple of key-packet in the list
        for key_packet in key_list:
            self.verify_key_packet_acl(acl1, key_packet[0], key_packet[1])

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Test default route
        self.do_test_route_default()

    @unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_multislice_acl(self):
        acl1 = self.create_simple_sec_acl()

        ipv6_acls = []
        ipv6_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.insert_nop_ace(acl1)

        # Apply on another slice
        self.topology.tx_l3_ac_reg.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default()
        self.insert_drop_ace(acl1)
        self.do_test_route_default_with_drop()

        # Check counter (not clearing)
        packet_count, byte_count = self.drop_counter.read(0, True, False)
        self.assertEqual(packet_count, 1)

        # Remove and reapply on slice, while still applied to other
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        self.do_test_route_default()
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
        acl1 = self.create_simple_sec_acl()

        # Test default route
        self.do_test_route_default()

        ipv6_acls = []
        ipv6_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()

        # Add drop ACE
        self.insert_drop_ace(acl1)
        self.do_test_route_default_with_drop()

        # Check counter
        packet_count, byte_count = self.drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        port_counter = self.device.create_counter(8)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, port_counter)
        self.topology.rx_l3_ac.hld_obj.set_drop_counter_offset(sdk.la_stage_e_INGRESS, 1)

        # Add NOP ACE
        self.insert_nop_ace(acl1)
        self.do_test_route_default()

        # Check counter
        packet_count, byte_count = self.nop_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        # Check port counter
        packet_count, bytes = port_counter.read(1, True, True)  # Port counter should be incremented
        self.assertEqual(packet_count, 1)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Test default route
        self.do_test_route_default()

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_punt_acl(self):
        acl1 = self.create_simple_sec_acl()

        # Test default route
        self.do_test_route_default()

        ipv6_acls = []
        ipv6_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)
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
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6,
                 next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                 code=nplapi.NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT,
                 source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 source_lp=T.RX_L3_AC_GID, destination_lp=nplapi.NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT,
                 relay_id=T.VRF_GID, lpts_flow_type=0
                 ) / \
            self.INPUT_PACKET_WITH_EH

        run_and_compare(self, self.device,
                        self.INPUT_PACKET_WITH_EH, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        punt_packet, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)

        # Check counter
        packet_count, byte_count = self.punt_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Test default route
        self.do_test_route_default()

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_qos_acl(self):
        acl1 = self.create_simple_qos_acl()

        ipv6_acls = []
        ipv6_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)

        # Test default route
        # Pass packet with no ACL applied, ensure PHB remains default (0).
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0}}
        run_and_compare_inner_fields(self, self.device,
                                     self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                     control_expected)

        # Attach a counter
        counter = self.device.create_counter(8)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, counter)

        # Attach the QoS ACL
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # Pass packet with ACL applied, ensure DSCP and PHB changes to non-default.
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1F}}
        expected_output_packet = self.EXPECTED_DEFAULT_OUTPUT_PACKET.copy()
        expected_output_packet[IPv6].tc = (QOS_MARK_DSCP << 2)
        run_and_compare_inner_fields(self, self.device,
                                     self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     expected_output_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                     control_expected)

        # Verify counter
        packet_count, byte_count = counter.read(SIMPLE_QOS_COUNTER_OFFSET, True, True)
        self.assertEqual(packet_count, 1)
        assertPacketLengthIngress(self, self.INPUT_PACKET, T.RX_SLICE, byte_count)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Pass packet with no ACL applied, ensure PHB remains default (0).
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0}}
        run_and_compare_inner_fields(self, self.device,
                                     self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                     control_expected)

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_route_default_and_acl(self):
        acl1 = self.create_simple_sec_acl()

        # Test default route
        self.do_test_route_default()

        ipv6_acls = []
        ipv6_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Test default route
        self.do_test_route_default()

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_route_default_delete_acl(self):
        acl1 = self.create_simple_sec_acl()

        # Test default route
        self.do_test_route_default()

        ipv6_acls = []
        ipv6_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()

        # Delete ACE
        self.trim_acl_invalid(acl1)
        self.trim_acl(acl1)

        # Test default route
        self.do_test_route_default_with_acl()
        self.trim_acl(acl1)

        # Test default route
        self.do_test_route_default()

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_route_default_delete_all_acl(self):
        ''' Test default route after ACL delete. '''

        self.do_test_route_default()

        acl1 = self.create_simple_sec_acl()
        ipv6_acls = []
        ipv6_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()

        # Delete ALL ACEs
        acl1.clear()
        count = acl1.get_count()
        self.assertEqual(count, 0)

        # Test default route
        self.do_test_route_default()

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_route_default_update_acl(self):
        ''' Test default route after ACL update. '''

        self.do_test_route_default()
        acl1 = self.create_simple_sec_acl()

        ipv6_acls = []
        ipv6_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()
        self.update_simple_acl_to_default(acl1)

        # Test default route
        self.do_test_route_default()

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    def get_slice_ifg_serdes(self, index):
        return (self.slice_ifg_serdes[index % 3])

    def packet_test(self, phb):
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': phb}}
        for current_qos_index in range(0, self.RX_L3_AC_QOS_ID):
            slice, ifg, serdes = self.get_slice_ifg_serdes(current_qos_index)
            run_and_compare_inner_fields(self, self.device,
                                         self.qos_input_packets[current_qos_index], slice, ifg, serdes,
                                         self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                         control_expected)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
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
                IPv6(src=self.SIP.addr_str, dst=self.DIP.addr_str, hlim=self.TTL) / TCP()
            self.qos_input_packets.append(add_payload(input_packet_base, self.INPUT_PACKET_PAYLOAD_SIZE))
            # Create 15 ACLs,there is a default profile created in l3_ac_port already
            # add NOP to the first and DROP to the second. Attach the second to the port.
            qos_acls.append(self.create_simple_qos_acl())

        # Check L3 AC ports with traffic without QoS attached
        self.packet_test(0)
        logging.debug("Initial packet tests on {num} ACs passed".format(num=self.RX_L3_AC_QOS_ID))

        # Attach a Q counter
        q_counters = []
        p_counters = []
        for current_qos_index in range(0, self.RX_L3_AC_QOS_ID):
            # Attach a Q counter
            q_counter = self.device.create_counter(8)
            rx_l3_qos_acs[current_qos_index].hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, q_counter)
            q_counters.append(q_counter)

            # Attach a P counter
            p_counter = self.device.create_counter(1)
            rx_l3_qos_acs[current_qos_index].hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, p_counter)
            p_counters.append(p_counter)

            # Attach the QoS ACL
            ipv6_acls = []
            ipv6_acls.append(qos_acls[current_qos_index])
            acl_group = []
            acl_group = self.device.create_acl_group()
            acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)
            rx_l3_qos_acs[current_qos_index].hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1F}}
        expected_output_packet = self.EXPECTED_DEFAULT_OUTPUT_PACKET.copy()
        expected_output_packet[IPv6].tc = (QOS_MARK_DSCP << 2)
        for current_qos_index in range(0, self.RX_L3_AC_QOS_ID):
            slice, ifg, serdes = self.get_slice_ifg_serdes(current_qos_index)
            logging.debug("Verifying packet on AC {num} after QoS ACL attached".format(num=current_qos_index))
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
            rx_l3_qos_acs[current_qos_index].hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.packet_test(0)

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_two_acls(self):

        # Create two ACLs, add NOP to the first and DROP to the second. Attach the second to the port.
        acl1 = self.create_simple_sec_acl()
        acl2 = self.create_simple_sec_acl()

        # Test default route
        self.do_test_route_default()

        ipv6_acls1 = []
        ipv6_acls1.append(acl1)
        acl_group1 = []
        acl_group1 = self.device.create_acl_group()
        acl_group1.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls1)

        ipv6_acls2 = []
        ipv6_acls2.append(acl2)
        acl_group2 = []
        acl_group2 = self.device.create_acl_group()
        acl_group2.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls2)

        # Attach the second ACL
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group2)

        # Execute a get on the acl
        acl_group = self.topology.rx_l3_ac.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, acl_group2.this)

        self.do_test_route_default_with_acl()

        # Add NOP ACE to the first ACL - should have no affect
        self.insert_nop_ace(acl1)
        self.do_test_route_default_with_acl()

        # Add drop ACE to the second ACL
        self.insert_drop_ace(acl2)
        self.do_test_route_default_with_drop()

        # Check counter
        packet_count, byte_count = self.drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        # Switch to use first ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
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

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_unified_acl(self):
        acl1 = self.create_simple_unified_acl()

        # Test default route
        # Pass packet with no ACL applied, ensure PHB remains default (0).
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0}}
        run_and_compare_inner_fields(self, self.device,
                                     self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                     control_expected)

        # Attach a counter
        counter = self.device.create_counter(8)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, counter)

        # Attach the Unified ACL
        ipv6_acls = []
        ipv6_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # Pass packet with ACL applied, ensure DSCP and PHB changes to non-default.
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1F}}
        expected_output_packet = self.EXPECTED_EXTRA_OUTPUT_PACKET.copy()
        expected_output_packet[IPv6].tc = (QOS_MARK_DSCP << 2)
        run_and_compare_inner_fields(self, self.device,
                                     self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     expected_output_packet, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT,
                                     control_expected)

        # Verify counter
        packet_count, byte_count = counter.read(SIMPLE_QOS_COUNTER_OFFSET, True, True)
        self.assertEqual(packet_count, 1)
        assertPacketLengthIngress(self, self.INPUT_PACKET, T.RX_SLICE, byte_count)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Pass packet with no ACL applied, ensure PHB remains default (0).
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0}}
        run_and_compare_inner_fields(self, self.device,
                                     self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                     control_expected)

    ''' Disabling the test as it takes longer time of execution on both NSIM and HW
    @unittest.skipIf(decor.is_asic5(), "RTF is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "RTF is not yet enabled on PL")
    def test_acl_sa_scale(self):
        acl = self.create_simple_sec_acl()
        count = acl.get_count()

        ipv6_acls = []
        ipv6_acls.append(acl)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        rev = self.device.ll_device.get_device_revision()
        asic_is_pacific = rev >= sdk.la_device_revision_e_PACIFIC_A0 and rev <= sdk.la_device_revision_e_PACIFIC_B1
        if asic_is_pacific:
            max_acl = PACIFIC_MAX_ACL_ENTRIES
        else:
            max_acl = GB_MAX_ACL_ENTRIES

        for i in range(count, max_acl):
            # Inserting in high position causes the ACL to be inserted at the highest line+1
            # This avoids the need to push all existing entries up, and makes the test run much faster
            self.insert_ace(acl, False, False, None, position=1000000)

        count = acl.get_count()
        self.assertEqual(count, max_acl)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
    '''


if __name__ == '__main__':
    unittest.main()
