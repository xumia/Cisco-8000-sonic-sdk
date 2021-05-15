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

# !/usr/bin/env python3

import decor
from packet_test_utils import *
from scapy.all import *
from l2_switch_base import *
import unittest
from leaba import sdk
import sim_utils
import topology as T


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l2_switch_forwarding_and_flooding_disable(l2_switch_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_switch_known_multicast_mac_forwarding_pkt_count_disable_rx(self):
        self.install_mac(self.MCAST_MAC)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.MCAST_MAC, self.VLAN)
        self.run_and_compare_l2_ingress_counter(in_packet, out_packet,
                                                sdk.la_rate_limiters_packet_type_e_MC, disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_switch_known_multicast_mac_forwarding_pkt_count_disable_tx(self):
        self.install_mac(self.MCAST_MAC)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.MCAST_MAC, self.VLAN)
        self.run_and_compare_l2_ingress_counter(in_packet, out_packet,
                                                sdk.la_rate_limiters_packet_type_e_MC, disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_switch_known_unicast_mac_forwarding_pkt_count_disable_rx(self):
        self.install_mac(self.UCAST_MAC)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.UCAST_MAC, self.VLAN)
        self.run_and_compare_l2_ingress_counter(in_packet, out_packet,
                                                sdk.la_rate_limiters_packet_type_e_UC, disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_switch_known_unicast_mac_forwarding_pkt_count_disable_tx(self):
        self.install_mac(self.UCAST_MAC)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.UCAST_MAC, self.VLAN)
        self.run_and_compare_l2_ingress_counter(in_packet, out_packet,
                                                sdk.la_rate_limiters_packet_type_e_UC, disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_switch_forwarding_pkt_count_with_service_mapping_updates_disable_rx(self):
        self.install_mac(self.UCAST_MAC)

        self.ac_port1.hld_obj.set_service_mapping_vids(self.VLAN2, 0)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.UCAST_MAC, self.VLAN2)
        self.run_and_compare_l2_ingress_counter(in_packet, out_packet, sdk.la_rate_limiters_packet_type_e_UC)
        (vlan_id1, vlan_id2) = self.ac_port1.hld_obj.get_service_mapping_vids()
        self.assertEqual(vlan_id1, self.VLAN2)
        self.assertEqual(vlan_id2, 0)

        self.ac_port1.hld_obj.set_service_mapping_vids(self.VLAN3, self.VLAN2)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.UCAST_MAC, self.VLAN3, self.VLAN2)
        self.run_and_compare_l2_ingress_counter(in_packet, out_packet,
                                                sdk.la_rate_limiters_packet_type_e_UC, disable_rx=True)
        # (vlan_id1, vlan_id2) = self.ac_port1.hld_obj.get_service_mapping_vids()
        # self.assertEqual(vlan_id1, self.VLAN3)
        # self.assertEqual(vlan_id2, self.VLAN2)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_switch_forwarding_pkt_count_with_service_mapping_updates_disable_tx(self):
        self.install_mac(self.UCAST_MAC)

        self.ac_port1.hld_obj.set_service_mapping_vids(self.VLAN2, 0)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.UCAST_MAC, self.VLAN2)
        self.run_and_compare_l2_ingress_counter(in_packet, out_packet, sdk.la_rate_limiters_packet_type_e_UC)
        (vlan_id1, vlan_id2) = self.ac_port1.hld_obj.get_service_mapping_vids()
        self.assertEqual(vlan_id1, self.VLAN2)
        self.assertEqual(vlan_id2, 0)

        self.ac_port1.hld_obj.set_service_mapping_vids(self.VLAN3, self.VLAN2)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.UCAST_MAC, self.VLAN3, self.VLAN2)
        self.run_and_compare_l2_ingress_counter(in_packet, out_packet,
                                                sdk.la_rate_limiters_packet_type_e_UC, disable_tx=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_switch_unknown_multicast_flooding_pkt_count_disable_rx(self):
        self.set_flood_destination(is_ucast=False)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.MCAST_MAC, self.VLAN)
        self.run_and_compare_l2_ingress_counter(in_packet, out_packet,
                                                sdk.la_rate_limiters_packet_type_e_UNKNOWN_MC, disable_rx=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_switch_unknown_multicast_flooding_pkt_count_disable_tx(self):
        self.set_flood_destination(is_ucast=False)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.MCAST_MAC, self.VLAN)
        self.run_and_compare_l2_ingress_counter(in_packet, out_packet,
                                                sdk.la_rate_limiters_packet_type_e_UNKNOWN_MC, disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_switch_unknown_unicast_flooding_pkt_count_disable_rx(self):
        self.set_flood_destination(is_ucast=True)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.UCAST_MAC, self.VLAN)
        self.run_and_compare_l2_ingress_counter(in_packet, out_packet,
                                                sdk.la_rate_limiters_packet_type_e_UNKNOWN_UC, disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_switch_unknown_unicast_flooding_pkt_count_disable_tx(self):
        self.set_flood_destination(is_ucast=True)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.UCAST_MAC, self.VLAN)
        self.run_and_compare_l2_ingress_counter(in_packet, out_packet,
                                                sdk.la_rate_limiters_packet_type_e_UNKNOWN_UC, disable_tx=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_switch_broadcast_flooding_pkt_count_disable_rx(self):
        self.set_flood_destination(is_ucast=False)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.BCAST_MAC, self.VLAN)
        self.run_and_compare_l2_ingress_counter(in_packet, out_packet,
                                                sdk.la_rate_limiters_packet_type_e_BC, disable_rx=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_switch_broadcast_flooding_pkt_count_disable_tx(self):
        self.set_flood_destination(is_ucast=False)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.BCAST_MAC, self.VLAN)
        self.run_and_compare_l2_ingress_counter(in_packet, out_packet,
                                                sdk.la_rate_limiters_packet_type_e_BC, disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_switch_mac_forwarding(self):
        dest_mac = T.mac_addr(self.UCAST_MAC)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.UCAST_MAC, self.VLAN)

        run_and_drop(
            self,
            self.device,
            in_packet,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST)

        self.sw1.hld_obj.set_mac_entry(dest_mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

        run_and_compare(
            self,
            self.device,
            in_packet,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            out_packet,
            self.OUT_SLICE,
            self.OUT_IFG,
            self.OUT_SERDES_FIRST)

        self.ac_port2.hld_obj.disable()
        run_and_drop(
            self,
            self.device,
            in_packet,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST)

        # Pass packet from port 1 to itself by overwriting the existing MAC entry
        self.sw1.hld_obj.set_mac_entry(dest_mac.hld_obj, self.ac_port1.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SAME_INTERFACE)

        run_and_compare(
            self,
            self.device,
            in_packet,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            out_packet,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST)

        self.ac_port1.hld_obj.disable()

        run_and_drop(
            self,
            self.device,
            in_packet,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST)


if __name__ == '__main__':
    unittest.main()
