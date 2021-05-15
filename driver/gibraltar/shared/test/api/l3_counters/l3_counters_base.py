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

import sys
import unittest
from leaba import sdk
import ip_test_base
import packet_test_utils as U
import scapy.all as S
import sim_utils
import topology as T


class l3_counters_base:
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    TTL = 128
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    OUTPUT_VID = 0xac

    ECN_ECT = 0x2  # ECN Capable Transport
    ECN_CE = 0x3  # Congestion Encountered

    def setUp(self):

        self.maxDiff = None  # Show whole strings on failures (unittest variable)

        self.device = U.sim_utils.create_device(1)

        self.topology = T.topology(self, self.device)

        self.ip_impl = self.ip_impl_class()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)

        self.add_default_route()

    def tearDown(self):
        self.device.tearDown()

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh, l3_counters_base.PRIVATE_DATA_DEFAULT)

    def do_test_counter_route_single_fec(self, single_counter, disable_rx=False, disable_tx=False):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, l3_counters_base.PRIVATE_DATA)

        # Create and set ingress counter
        counter_set_size = 1 if single_counter else sdk.la_l3_protocol_e_LAST
        ingress_counter = self.device.create_counter(counter_set_size)
        self.l3_port_impl.rx_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, ingress_counter)

        # Create and set egress counter
        egress_counter = self.device.create_counter(counter_set_size)
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, egress_counter)

        l2_egress_counter = self.device.create_counter(counter_set_size)
        self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, l2_egress_counter)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        # Check ingress counter
        if single_counter:
            packet_count, byte_count = ingress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthIngress(self, self.INPUT_PACKET, T.RX_SLICE, byte_count)
        else:
            packet_count, byte_count = ingress_counter.read(self.protocol, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthIngress(self, self.INPUT_PACKET, T.RX_SLICE, byte_count)

        # Check egress counter
        if single_counter:
            if(self.l3_port_impl.is_svi):
                packet_count, byte_count = l2_egress_counter.read(0, True, True)
                self.assertEqual(packet_count, 1)

            packet_count, byte_count = egress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)
        else:
            if(self.l3_port_impl.is_svi):
                packet_count, byte_count = l2_egress_counter.read(self.protocol, True, True)
                self.assertEqual(packet_count, 1)

            packet_count, byte_count = egress_counter.read(self.protocol, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)

        if(not self.l3_port_impl.is_svi):
            if(disable_rx):
                self.l3_port_impl.rx_port.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
                packet_count, byte_count = ingress_counter.read(0, True, True)
                self.assertEqual(packet_count, 0)
                packet_count, byte_count = egress_counter.read(0, True, True)
                self.assertEqual(packet_count, 0)

            if(disable_tx):
                self.l3_port_impl.tx_port.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def do_test_ecn_counter_route_single_fec(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, l3_counters_base.PRIVATE_DATA)

        counter_set_size = 8

        # L3 counters
        egress_counter = self.device.create_counter(counter_set_size)
        self.l3_port_impl.tx_port.hld_obj.set_ecn_counting_enabled(True)
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_QOS, egress_counter)
        self.assertEqual(self.l3_port_impl.tx_port.hld_obj.get_ecn_counting_enabled(), True)
        self.l3_port_impl.tx_port.hld_obj.set_ecn_remark_enabled(True)

        # L2 counters
        l2_egress_counter = self.device.create_counter(counter_set_size)
        self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_QOS, l2_egress_counter)

        if self.INPUT_PACKET.version == 6:
            self.INPUT_PACKET.tc |= self.ECN_ECT
            self.EXPECTED_OUTPUT_PACKET.tc |= self.ECN_CE
        else:
            self.INPUT_PACKET.tos |= self.ECN_ECT
            self.EXPECTED_OUTPUT_PACKET.tos |= self.ECN_CE

        if (self.device.ll_device.is_asic5() or
            self.device.ll_device.is_asic4() or
                self.device.ll_device.is_asic3()):
            congestion_input = "txpp_npu_input.sms_rd_pd.congested"
        else:
            congestion_input = "txpp_npu_input.sms_rd_pd.cong_on"

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg,
                          initial_metadata_values_dict={congestion_input: 0x1})

        if (self.l3_port_impl.is_svi):
            packet_count, byte_count = l2_egress_counter.read(0, True, True)
        else:
            packet_count, byte_count = egress_counter.read(0, True, True)

        self.assertEqual(packet_count, 1)

        # Zero ECN field bits
        if self.INPUT_PACKET.version == 6:
            self.INPUT_PACKET.tc &= (0xFF << 2)
            self.EXPECTED_OUTPUT_PACKET.tc &= (0xFF << 2)
        else:
            self.INPUT_PACKET.tos &= (0xFF << 2)
            self.EXPECTED_OUTPUT_PACKET.tos &= (0xFF << 2)


class ipv4_svi_counters_test(l3_counters_base, unittest.TestCase):
    protocol = sdk.la_l3_protocol_e_IPV4_UC
    l3_port_impl_class = T.ip_svi_base
    ip_impl_class = ip_test_base.ipv4_test_base
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')

    INPUT_PACKET_BASE = \
        S.Ether(dst=T.RX_SVI_MAC.addr_str, src=l3_counters_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=l3_counters_base.TTL)

    EXPECTED_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=l3_counters_base.TTL - 1)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = U.pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)


class ipv6_svi_counters_test(l3_counters_base, unittest.TestCase):
    protocol = sdk.la_l3_protocol_e_IPV6_UC
    l3_port_impl_class = T.ip_svi_base
    ip_impl_class = ip_test_base.ipv6_test_base
    SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

    INPUT_PACKET_BASE = \
        S.Ether(dst=T.RX_SVI_MAC.addr_str, src=l3_counters_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=l3_counters_base.TTL, plen=40)

    EXPECTED_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=l3_counters_base.TTL - 1, plen=40)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = U.pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)


class ipv4_l3_ac_counters_test(l3_counters_base, unittest.TestCase):
    protocol = sdk.la_l3_protocol_e_IPV4_UC
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl_class = ip_test_base.ipv4_test_base
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')

    INPUT_PACKET_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=l3_counters_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=l3_counters_base.TTL)

    EXPECTED_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=l3_counters_base.TTL - 1)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = U.pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)


class ipv6_l3_ac_counters_test(l3_counters_base, unittest.TestCase):
    protocol = sdk.la_l3_protocol_e_IPV6_UC
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl_class = ip_test_base.ipv6_test_base
    SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

    INPUT_PACKET_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=l3_counters_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=l3_counters_base.TTL, plen=40)

    EXPECTED_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=l3_counters_base.TTL - 1, plen=40)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = U.pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
