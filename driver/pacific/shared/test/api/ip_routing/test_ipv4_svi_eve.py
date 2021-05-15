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

from packet_test_utils import *
from scapy.all import *
from ip_routing_svi_eve_base import *
import unittest
from leaba import sdk
import topology as T
import scapy.all as S
import packet_test_utils as U
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_ipv4_svi_eve(ip_routing_svi_eve_base):
    ip_impl = ip_test_base.ipv4_test_base
    SVI_HOST_IP_ADDR = T.ipv4_addr('10.0.0.2')
    SVI_TRUNK_HOST_IP_ADDR = T.ipv4_addr('10.0.0.5')
    SVI1_HOST_IP_ADDR = T.ipv4_addr('11.0.0.3')
    SVI1_TRUNK_HOST_IP_ADDR = T.ipv4_addr('11.0.0.4')
    SVI2_TRUNK_HOST_IP_ADDR = T.ipv4_addr('12.0.0.5')
    base = ip_routing_svi_eve_base

    rx_svi_access_in_packet = \
        S.Ether(dst=T.RX_SVI_MAC.addr_str, src=base.SVI_HOST_MAC.addr_str) / \
        S.IP(dst=SVI1_HOST_IP_ADDR.addr_str, src=SVI_HOST_IP_ADDR.addr_str) / \
        S.TCP()

    rx_svi_access_in_packet2 = \
        S.Ether(dst=T.RX_SVI_MAC.addr_str, src=base.SVI_HOST_MAC.addr_str) / \
        S.IP(dst=SVI1_TRUNK_HOST_IP_ADDR.addr_str, src=SVI_HOST_IP_ADDR.addr_str) / \
        S.TCP()

    rx_svi1_trunk_in_packet = \
        S.Ether(dst=T.RX_SVI_MAC1.addr_str, src=base.SVI1_TRUNK_HOST_MAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=30) / \
        S.IP(dst=SVI_HOST_IP_ADDR.addr_str, src=SVI1_TRUNK_HOST_IP_ADDR.addr_str) / \
        S.TCP()

    rx_svi1_trunk_in_packet2 = \
        S.Ether(dst=T.RX_SVI_MAC1.addr_str, src=base.SVI1_TRUNK_HOST_MAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=base.SVI1_VLAN) / \
        S.IP(dst=SVI_TRUNK_HOST_IP_ADDR.addr_str, src=SVI1_TRUNK_HOST_IP_ADDR.addr_str) / \
        S.TCP()

    rx_svi1_trunk_in_packet3 = \
        S.Ether(dst=T.RX_SVI_MAC1.addr_str, src=base.SVI1_TRUNK_HOST_MAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=base.SVI1_VLAN) / \
        S.IP(dst=SVI2_TRUNK_HOST_IP_ADDR.addr_str, src=SVI1_TRUNK_HOST_IP_ADDR.addr_str) / \
        S.TCP()

    rx_svi1_access_out_packet = \
        S.Ether(dst=base.SVI1_HOST_MAC.addr_str, src=T.RX_SVI_MAC1.addr_str) / \
        S.IP(dst=SVI1_HOST_IP_ADDR.addr_str, src=SVI_HOST_IP_ADDR.addr_str, ttl=63) / \
        S.TCP()

    rx_svi1_trunk_out_packet = \
        S.Ether(dst=base.SVI1_TRUNK_HOST_MAC.addr_str, src=T.RX_SVI_MAC1.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=base.SVI1_VLAN) / \
        S.IP(dst=SVI1_TRUNK_HOST_IP_ADDR.addr_str, src=SVI_HOST_IP_ADDR.addr_str, ttl=63) / \
        S.TCP()

    rx_svi1_trunk_out_packet2 = \
        S.Ether(dst=base.SVI1_HOST_MAC.addr_str, src=T.RX_SVI_MAC1.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=base.SVI1_VLAN + 1) / \
        S.IP(dst=SVI1_TRUNK_HOST_IP_ADDR.addr_str, src=SVI_HOST_IP_ADDR.addr_str, ttl=63) / \
        S.TCP()

    rx_svi_access_out_packet = \
        S.Ether(dst=base.SVI_HOST_MAC.addr_str, src=T.RX_SVI_MAC.addr_str) / \
        S.IP(dst=SVI_HOST_IP_ADDR.addr_str, src=SVI1_TRUNK_HOST_IP_ADDR.addr_str, ttl=63) / \
        S.TCP()

    rx_svi_trunk_out_packet = \
        S.Ether(dst=base.SVI_TRUNK_HOST_MAC.addr_str, src=T.RX_SVI_MAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=base.SVI_VLAN) / \
        S.IP(dst=SVI_TRUNK_HOST_IP_ADDR.addr_str, src=SVI1_TRUNK_HOST_IP_ADDR.addr_str, ttl=63) / \
        S.TCP()

    rx_svi_trunk_out_packet2 = \
        S.Ether(dst=base.SVI_HOST_MAC.addr_str, src=T.RX_SVI_MAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=base.SVI_VLAN) / \
        S.IP(dst=SVI_TRUNK_HOST_IP_ADDR.addr_str, src=SVI1_TRUNK_HOST_IP_ADDR.addr_str, ttl=63) / \
        S.TCP()

    rx_svi2_trunk_out_packet = \
        S.Ether(dst=base.SVI2_TRUNK_HOST_MAC.addr_str, src=base.RX_SVI_MAC2.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=base.SVI2_VLAN) / \
        S.IP(dst=SVI2_TRUNK_HOST_IP_ADDR.addr_str, src=SVI1_TRUNK_HOST_IP_ADDR.addr_str, ttl=63) / \
        S.TCP()

    def setUp(self):
        super().setUp()
        ip_routing_svi_eve_base.setup_ip_routing_svi_eve(self)

    def do_test_access_to_access(self, in_packet, out_packet):
        out_port = self.rx_switch1_access_port.hld_obj
        svi_input_packet, svi_output_packet = pad_input_and_output_packets(in_packet, out_packet)
        run_and_compare(self, self.device,
                        svi_input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        svi_output_packet, T.RX_SLICE, T.RX_IFG1, T.FIRST_SERDES1)

        packet_count, byte_count = self.inc1.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.rx_svi1_ec.read(0, True, True)
        self.assertEqual(packet_count, 1)

        if (out_port.get_egress_feature_mode() == sdk.la_l2_service_port.egress_feature_mode_e_L2):
            packet_count, byte_count = self.l2_ec2.read(0, True, True)
            self.assertEqual(packet_count, 1)

    def do_test_access_to_trunk(self, in_packet, out_packet):
        out_port = self.rx_switch1_trunk_port.hld_obj
        svi_input_packet, svi_output_packet = pad_input_and_output_packets(in_packet, out_packet)
        run_and_compare(self, self.device,
                        svi_input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        svi_output_packet, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_SVI_REG)

        packet_count, byte_count = self.inc1.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.rx_svi1_ec.read(0, True, True)
        self.assertEqual(packet_count, 1)

        if (out_port.get_egress_feature_mode() == sdk.la_l2_service_port.egress_feature_mode_e_L2):
            packet_count, byte_count = self.l2_ec4.read(0, True, True)
            self.assertEqual(packet_count, 1)

    def do_test_trunk_to_access(self, in_packet, out_packet):
        out_port = self.rx_switch_access_port.hld_obj
        svi_input_packet, svi_output_packet = pad_input_and_output_packets(in_packet, out_packet)
        run_and_compare(self, self.device,
                        svi_input_packet, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_SVI_REG,
                        svi_output_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        packet_count, byte_count = self.inc4.read(0, True, True)
        packet_count, byte_count = self.rx_svi_ec.read(0, True, True)
        self.assertEqual(packet_count, 1)

        if (out_port.get_egress_feature_mode() == sdk.la_l2_service_port.egress_feature_mode_e_L2):
            packet_count, byte_count = self.l2_ec1.read(0, True, True)
            self.assertEqual(packet_count, 1)

    def do_test_trunk_to_trunk(self, in_packet, out_packet):
        out_port = self.rx_switch_trunk_port.hld_obj
        svi_input_packet, svi_output_packet = pad_input_and_output_packets(in_packet, out_packet)
        run_and_compare(self, self.device,
                        svi_input_packet, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_SVI_REG,
                        svi_output_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_SVI_DEF)

        packet_count, byte_count = self.inc4.read(0, True, True)
        packet_count, byte_count = self.rx_svi_ec.read(0, True, True)
        self.assertEqual(packet_count, 1)

        if (out_port.get_egress_feature_mode() == sdk.la_l2_service_port.egress_feature_mode_e_L2):
            packet_count, byte_count = self.l2_ec3.read(0, True, True)
            self.assertEqual(packet_count, 1)

    def do_test_trunk_to_trunk_non_native(self, in_packet, out_packet):
        out_port = self.rx_switch2_trunk_port.hld_obj
        svi_input_packet, svi_output_packet = pad_input_and_output_packets(in_packet, out_packet)
        run_and_compare(self, self.device,
                        svi_input_packet, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_SVI_REG,
                        svi_output_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_SVI_DEF)

        packet_count, byte_count = self.inc4.read(0, True, True)
        packet_count, byte_count = self.rx_svi2_ec.read(0, True, True)
        self.assertEqual(packet_count, 1)

    def test_access_to_access(self):
        ip_routing_svi_eve_base.add_hosts(self)
        self.do_test_access_to_access(self.rx_svi_access_in_packet, self.rx_svi1_access_out_packet)

    def test_access_to_trunk(self):
        ip_routing_svi_eve_base.add_hosts(self)
        self.do_test_access_to_trunk(self.rx_svi_access_in_packet2, self.rx_svi1_trunk_out_packet)

    def test_trunk_to_access(self):
        ip_routing_svi_eve_base.add_hosts(self)
        self.do_test_trunk_to_access(self.rx_svi1_trunk_in_packet, self.rx_svi_access_out_packet)

    def test_trunk_to_trunk(self):
        ip_routing_svi_eve_base.add_hosts(self)
        self.do_test_trunk_to_trunk(self.rx_svi1_trunk_in_packet2, self.rx_svi_trunk_out_packet)

    def test_trunk_to_trunk_non_native(self):
        ip_routing_svi_eve_base.add_hosts(self)
        self.do_test_trunk_to_trunk_non_native(self.rx_svi1_trunk_in_packet3, self.rx_svi2_trunk_out_packet)

    def test_access_to_access_nh(self):
        ip_routing_svi_eve_base.create_next_hop(self)
        self.do_test_access_to_access(self.rx_svi_access_in_packet, self.rx_svi1_access_out_packet)

    @unittest.skipIf(True, "Test fails on master - enable after merge to master")
    def test_access_to_trunk_nh(self):
        ip_routing_svi_eve_base.create_next_hop(self)
        ip_routing_svi_eve_base.move_nh_mac_from_access_to_trunk(self,
                                                                 self.rx_switch1_access_port.hld_obj,
                                                                 self.rx_switch1_trunk_port.hld_obj)
        self.do_test_access_to_trunk(self.rx_svi_access_in_packet2, self.rx_svi1_trunk_out_packet2)

    def test_trunk_to_access_nh(self):
        ip_routing_svi_eve_base.create_next_hop1(self)
        self.do_test_trunk_to_access(self.rx_svi1_trunk_in_packet, self.rx_svi_access_out_packet)

    def test_trunk_to_trunk_nh(self):
        ip_routing_svi_eve_base.create_next_hop1(self)
        ip_routing_svi_eve_base.move_nh1_mac_from_access_to_trunk(self,
                                                                  self.rx_switch_access_port.hld_obj,
                                                                  self.rx_switch_trunk_port.hld_obj)
        self.do_test_trunk_to_trunk(self.rx_svi1_trunk_in_packet2, self.rx_svi_trunk_out_packet2)

    def test_trunk_to_trunk_non_native_nh(self):
        ip_routing_svi_eve_base.create_next_hop2(self)
        self.do_test_trunk_to_trunk_non_native(self.rx_svi1_trunk_in_packet3, self.rx_svi2_trunk_out_packet)


if __name__ == '__main__':
    unittest.main()
