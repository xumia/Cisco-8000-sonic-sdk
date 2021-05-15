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
from ip_routing_svi_eve_base import *
import unittest
from leaba import sdk
import decor
import topology as T
import scapy.all as S
import packet_test_utils as U


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_ipv4_svi_spa(ip_routing_svi_eve_base):

    ip_impl = ip_test_base.ipv4_test_base
    SVI_HOST_IP_ADDR = T.ipv4_addr('10.0.0.2')
    SVI_TRUNK_HOST_IP_ADDR = T.ipv4_addr('10.0.0.5')
    SVI1_HOST_IP_ADDR = T.ipv4_addr('11.0.0.3')
    SVI1_TRUNK_HOST_IP_ADDR = T.ipv4_addr('11.0.0.4')
    SVI2_TRUNK_HOST_IP_ADDR = T.ipv4_addr('12.0.0.5')
    PAYLOAD_SIZE = 60

    def setUp(self):
        super().setUp()
        ip_routing_svi_eve_base.setup_ip_routing_svi_eve_spa(self)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_access_spa_to_access_spa(self):
        ip_routing_svi_eve_base.add_hosts(self)
        # access to access packet
        svi_input_packet_base = \
            S.Ether(dst=T.RX_SVI_MAC.addr_str, src='00:11:22:33:44:55') / \
            S.IP(dst=self.SVI1_HOST_IP_ADDR.addr_str, src='10.0.0.2') / \
            S.TCP()

        svi_output_packet_base = \
            S.Ether(dst=self.SVI1_HOST_MAC.addr_str, src=T.RX_SVI_MAC1.addr_str) / \
            S.IP(dst=self.SVI1_HOST_IP_ADDR.addr_str, src='10.0.0.2', ttl=63) / \
            S.TCP()

        svi_input_packet, svi_output_packet = pad_input_and_output_packets(svi_input_packet_base, svi_output_packet_base)
        self.run_and_compare_spa(self.svi_spa_port3, svi_input_packet, T.TX_SLICE_REG, T.TX_IFG_REG,
                                 self.FIRST_SERDES_SPA, svi_output_packet, 0)

        # check l2 counters - ingress on rx_switch_access_spa_port and egress on rx_switch1_access_spa_port
        packet_count, byte_count = self.inc1.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.ec3.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.rx_svi1_ec.read(0, True, True)
        self.assertEqual(packet_count, 1)

    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device - inject PIF used on HW.")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_access_spa_drop_receive_disabled(self):
        ip_routing_svi_eve_base.add_hosts(self)
        # access to access packet
        svi_input_packet_base = \
            S.Ether(dst=T.RX_SVI_MAC.addr_str, src='00:11:22:33:44:55') / \
            S.IP(dst=self.SVI1_HOST_IP_ADDR.addr_str, src='10.0.0.2') / \
            S.TCP()

        svi_output_packet_base = \
            S.Ether(dst=self.SVI1_HOST_MAC.addr_str, src=T.RX_SVI_MAC1.addr_str) / \
            S.IP(dst=self.SVI1_HOST_IP_ADDR.addr_str, src='10.0.0.2', ttl=63) / \
            S.TCP()

        svi_input_packet, svi_output_packet = pad_input_and_output_packets(svi_input_packet_base, svi_output_packet_base)

        # Disable Rx
        self.svi_spa_port1.hld_obj.set_member_receive_enabled(self.spa_sys_port1.hld_obj, False)
        is_receive_enabled = self.svi_spa_port1.hld_obj.get_member_receive_enabled(self.spa_sys_port1.hld_obj)
        self.assertEqual(is_receive_enabled, False)
        U.run_and_drop(self, self.device, svi_input_packet, T.TX_SLICE_REG, T.TX_IFG_REG, self.FIRST_SERDES_SPA)

        # Enable Rx
        self.svi_spa_port1.hld_obj.set_member_receive_enabled(self.spa_sys_port1.hld_obj, True)
        is_receive_enabled = self.svi_spa_port1.hld_obj.get_member_receive_enabled(self.spa_sys_port1.hld_obj)
        self.assertEqual(is_receive_enabled, True)
        self.run_and_compare_spa(self.svi_spa_port3, svi_input_packet, T.TX_SLICE_REG, T.TX_IFG_REG,
                                 self.FIRST_SERDES_SPA, svi_output_packet, 0)

        # check l2 counters - ingress on rx_switch_access_spa_port and egress on rx_switch1_access_spa_port
        packet_count, byte_count = self.inc1.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.ec3.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.rx_svi1_ec.read(0, True, True)
        self.assertEqual(packet_count, 1)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_access_spa_to_trunk_spa(self):
        ip_routing_svi_eve_base.add_hosts(self)
        # access to trunk packet
        svi_input_packet_base = \
            S.Ether(dst=T.RX_SVI_MAC.addr_str, src='00:11:22:33:44:55') / \
            S.IP(dst=self.SVI1_TRUNK_HOST_IP_ADDR.addr_str, src='10.0.0.2') / \
            S.TCP()

        svi_output_packet_base = \
            S.Ether(dst=self.SVI1_TRUNK_HOST_MAC.addr_str, src=T.RX_SVI_MAC1.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=self.SVI1_VLAN) / \
            S.IP(dst=self.SVI1_TRUNK_HOST_IP_ADDR.addr_str, src='10.0.0.2', ttl=63) / \
            S.TCP()

        svi_input_packet, svi_output_packet = pad_input_and_output_packets(svi_input_packet_base, svi_output_packet_base)
        self.run_and_compare_spa(self.svi_spa_port4, svi_input_packet, T.TX_SLICE_REG, T.TX_IFG_REG,
                                 self.FIRST_SERDES_SPA, svi_output_packet, 0)

        # check l2 counters - ingress on rx_switch_access_spa_port and egress on rx_switch1_trunk_spa_port
        packet_count, byte_count = self.inc1.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.ec4.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.rx_svi1_ec.read(0, True, True)
        self.assertEqual(packet_count, 1)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_trunk_spa_to_access_spa(self):
        ip_routing_svi_eve_base.add_hosts(self)
        # trunk to access packet
        svi_input_packet_base = \
            S.Ether(dst=T.RX_SVI_MAC1.addr_str, src='00:11:22:33:44:04', type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=30) / \
            S.IP(dst=self.SVI_HOST_IP_ADDR.addr_str, src='11.0.0.4') / \
            S.TCP()

        svi_output_packet_base = \
            S.Ether(dst=self.SVI_HOST_MAC.addr_str, src=T.RX_SVI_MAC.addr_str) / \
            S.IP(dst=self.SVI_HOST_IP_ADDR.addr_str, src='11.0.0.4', ttl=63) / \
            S.TCP()

        svi_input_packet = U.add_payload(svi_input_packet_base, self.PAYLOAD_SIZE)
        svi_output_packet = U.add_payload(svi_output_packet_base, self.PAYLOAD_SIZE)
        self.run_and_compare_spa(self.svi_spa_port1, svi_input_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF,
                                 self.SERDES12, svi_output_packet, 1)

        # check l2 counters - ingress on rx_switch1_trunk_port and egress on rx_switch_access_port
        packet_count, byte_count = self.inc4.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.ec1.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.rx_svi_ec.read(0, True, True)
        self.assertEqual(packet_count, 1)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_trunk_spa_to_trunk_spa(self):
        ip_routing_svi_eve_base.add_hosts(self)
        # trunk to trunk packet
        svi_input_packet_base = \
            S.Ether(dst=T.RX_SVI_MAC1.addr_str, src=self.SVI1_TRUNK_HOST_MAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=self.SVI1_VLAN) / \
            S.IP(dst=self.SVI_TRUNK_HOST_IP_ADDR.addr_str, src='11.0.0.4') / \
            S.TCP()

        svi_output_packet_base = \
            S.Ether(dst=self.SVI_TRUNK_HOST_MAC.addr_str, src='10:12:13:14:15:16', type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=self.SVI_VLAN) / \
            S.IP(dst=self.SVI_TRUNK_HOST_IP_ADDR.addr_str, src='11.0.0.4', ttl=63) / \
            S.TCP()

        svi_input_packet, svi_output_packet = pad_input_and_output_packets(svi_input_packet_base, svi_output_packet_base)
        self.run_and_compare_spa(self.svi_spa_port2, svi_input_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF,
                                 self.SERDES12, svi_output_packet, 2)

        # check l2 counters - ingress on rx_switch1_trunk_port and egress on rx_switch_trunk_port
        packet_count, byte_count = self.inc4.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.ec2.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.rx_svi_ec.read(0, True, True)
        self.assertEqual(packet_count, 1)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_access_spa_to_access_spa_nh(self):
        ip_routing_svi_eve_base.create_next_hop(self)

        svi_input_packet_base = \
            S.Ether(dst=T.RX_SVI_MAC.addr_str, src='00:11:22:33:44:55') / \
            S.IP(dst=self.SVI1_HOST_IP_ADDR.addr_str, src='10.0.0.2') / \
            S.TCP()

        svi_output_packet_base = \
            S.Ether(dst=self.SVI1_HOST_MAC.addr_str, src=T.RX_SVI_MAC1.addr_str) / \
            S.IP(dst=self.SVI1_HOST_IP_ADDR.addr_str, src='10.0.0.2', ttl=63) / \
            S.TCP()

        svi_input_packet, svi_output_packet = pad_input_and_output_packets(svi_input_packet_base, svi_output_packet_base)
        self.run_and_compare_spa(self.svi_spa_port3, svi_input_packet, T.TX_SLICE_REG, T.TX_IFG_REG,
                                 self.FIRST_SERDES_SPA, svi_output_packet, 0)

        # check l2 counters - ingress on rx_switch_access_spa_port and egress on rx_switch1_access_spa_port
        packet_count, byte_count = self.inc1.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.ec3.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.rx_svi1_ec.read(0, True, True)
        self.assertEqual(packet_count, 1)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_access_spa_to_trunk_spa_nh(self):
        ip_routing_svi_eve_base.create_next_hop(self)
        ip_routing_svi_eve_base.move_nh_mac_from_access_to_trunk(self, self.rx_switch1_access_spa_port.hld_obj,
                                                                 self.rx_switch1_trunk_spa_port.hld_obj)

        svi_input_packet_base = \
            S.Ether(dst=T.RX_SVI_MAC.addr_str, src='00:11:22:33:44:55') / \
            S.IP(dst=self.SVI1_HOST_IP_ADDR.addr_str, src='10.0.0.2') / \
            S.TCP()

        svi_output_packet_base = \
            S.Ether(dst=self.SVI1_HOST_MAC.addr_str, src=T.RX_SVI_MAC1.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=self.SVI1_VLAN + 1) / \
            S.IP(dst=self.SVI1_HOST_IP_ADDR.addr_str, src='10.0.0.2', ttl=63) / \
            S.TCP()

        svi_input_packet, svi_output_packet = pad_input_and_output_packets(svi_input_packet_base, svi_output_packet_base)
        self.run_and_compare_spa(self.svi_spa_port4, svi_input_packet, T.TX_SLICE_REG, T.TX_IFG_REG,
                                 self.FIRST_SERDES_SPA, svi_output_packet, 0)

        # check l2 counters - ingress on rx_switch_access_spa_port and egress on rx_switch1_trunk_spa_port
        packet_count, byte_count = self.inc1.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.ec4.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.rx_svi1_ec.read(0, True, True)
        self.assertEqual(packet_count, 1)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_trunk_spa_to_access_spa_nh(self):
        ip_routing_svi_eve_base.create_next_hop1(self)

        # trunk to access packet
        svi_input_packet_base = \
            S.Ether(dst=T.RX_SVI_MAC1.addr_str, src='00:11:22:33:44:04', type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=30) / \
            S.IP(dst=self.SVI_HOST_IP_ADDR.addr_str, src='11.0.0.4') / \
            S.TCP()

        svi_output_packet_base = \
            S.Ether(dst=self.SVI_HOST_MAC.addr_str, src=T.RX_SVI_MAC.addr_str) / \
            S.IP(dst=self.SVI_HOST_IP_ADDR.addr_str, src='11.0.0.4', ttl=63) / \
            S.TCP()

        svi_input_packet = U.add_payload(svi_input_packet_base, self.PAYLOAD_SIZE)
        svi_output_packet = U.add_payload(svi_output_packet_base, self.PAYLOAD_SIZE)
        self.run_and_compare_spa(self.svi_spa_port1, svi_input_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF,
                                 self.SERDES12, svi_output_packet, 1)

        # check l2 counters - ingress on rx_switch1_trunk_port and egress on rx_switch_access_port
        packet_count, byte_count = self.inc4.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.ec1.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.rx_svi_ec.read(0, True, True)
        self.assertEqual(packet_count, 1)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_trunk_spa_to_trunk_spa_nh(self):
        ip_routing_svi_eve_base.create_next_hop1(self)
        ip_routing_svi_eve_base.move_nh1_mac_from_access_to_trunk(self, self.rx_switch_access_spa_port.hld_obj,
                                                                  self.rx_switch_trunk_spa_port.hld_obj)

        svi_input_packet_base = \
            S.Ether(dst=T.RX_SVI_MAC1.addr_str, src=self.SVI1_TRUNK_HOST_MAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=self.SVI1_VLAN) / \
            S.IP(dst=self.SVI_TRUNK_HOST_IP_ADDR.addr_str, src='11.0.0.4') / \
            S.TCP()

        svi_output_packet_base = \
            S.Ether(dst=self.SVI_HOST_MAC.addr_str,
                    src='10:12:13:14:15:16',
                    type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=self.SVI_VLAN) / \
            S.IP(dst=self.SVI_TRUNK_HOST_IP_ADDR.addr_str,
                 src='11.0.0.4',
                 ttl=63) / \
            S.TCP()

        svi_input_packet, svi_output_packet = pad_input_and_output_packets(svi_input_packet_base, svi_output_packet_base)
        self.run_and_compare_spa(self.svi_spa_port2, svi_input_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF,
                                 self.SERDES12, svi_output_packet, 2)

        # check l2 counters - ingress on rx_switch1_trunk_port and egress on rx_switch_trunk_port
        packet_count, byte_count = self.inc4.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.ec2.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.rx_svi_ec.read(0, True, True)
        self.assertEqual(packet_count, 1)

        ip_routing_svi_eve_base.add_delayed_member_for_trunk_spa(self)
        run_and_compare(self, self.device,
                        svi_input_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, self.SERDES12,
                        svi_output_packet, T.RX_SLICE, T.TX_IFG_DEF, self.SERDES8)

        packet_count, byte_count = self.ec2.read(0, True, True)
        self.assertEqual(packet_count, 1)


if __name__ == '__main__':
    unittest.main()
