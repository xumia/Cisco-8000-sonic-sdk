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
from l2_switch_base import *
import unittest
from leaba import sdk
import sim_utils
import topology as T


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l2_switch_forwarding_and_flooding(l2_switch_base):

    def test_l2_switch_known_multicast_mac_forwarding_pkt_count(self):
        self.install_mac(self.MCAST_MAC)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.MCAST_MAC, self.VLAN)
        self.run_and_compare_l2_ingress_counter(in_packet, out_packet, sdk.la_rate_limiters_packet_type_e_MC)

    def test_l2_switch_known_unicast_mac_forwarding_pkt_count(self):
        self.install_mac(self.UCAST_MAC)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.UCAST_MAC, self.VLAN)
        self.run_and_compare_l2_ingress_counter(in_packet, out_packet, sdk.la_rate_limiters_packet_type_e_UC)

    def test_l2_switch_forwarding_pkt_count_with_service_mapping_updates(self):
        self.install_mac(self.UCAST_MAC)

        self.ac_port1.hld_obj.set_service_mapping_vids(self.VLAN2, 0)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.UCAST_MAC, self.VLAN2)
        self.run_and_compare_l2_ingress_counter(in_packet, out_packet, sdk.la_rate_limiters_packet_type_e_UC)
        (vlan_id1, vlan_id2) = self.ac_port1.hld_obj.get_service_mapping_vids()
        self.assertEqual(vlan_id1, self.VLAN2)
        self.assertEqual(vlan_id2, 0)

        self.ac_port1.hld_obj.set_service_mapping_vids(self.VLAN3, self.VLAN2)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.UCAST_MAC, self.VLAN3, self.VLAN2)
        self.run_and_compare_l2_ingress_counter(in_packet, out_packet, sdk.la_rate_limiters_packet_type_e_UC)
        (vlan_id1, vlan_id2) = self.ac_port1.hld_obj.get_service_mapping_vids()
        self.assertEqual(vlan_id1, self.VLAN3)
        self.assertEqual(vlan_id2, self.VLAN2)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_l2_switch_unknown_multicast_flooding_pkt_count(self):
        self.set_flood_destination(is_ucast=False)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.MCAST_MAC, self.VLAN)
        self.run_and_compare_l2_ingress_counter(in_packet, out_packet, sdk.la_rate_limiters_packet_type_e_UNKNOWN_MC)

    def test_l2_switch_unknown_unicast_flooding_pkt_count(self):
        self.set_flood_destination(is_ucast=True)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.UCAST_MAC, self.VLAN)
        self.run_and_compare_l2_ingress_counter(in_packet, out_packet, sdk.la_rate_limiters_packet_type_e_UNKNOWN_UC)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_l2_switch_broadcast_flooding_pkt_count(self):
        self.set_flood_destination(is_ucast=False)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.BCAST_MAC, self.VLAN)
        self.run_and_compare_l2_ingress_counter(in_packet, out_packet, sdk.la_rate_limiters_packet_type_e_BC)

    def test_l2_switch_drop_unknown_unicast(self):
        drop_unknown_uc = self.sw1.hld_obj.get_drop_unknown_uc_enabled()
        self.assertEqual(drop_unknown_uc, False)

        self.sw1.hld_obj.set_drop_unknown_uc_enabled(True)
        drop_unknown_uc = self.sw1.hld_obj.get_drop_unknown_uc_enabled()
        self.assertEqual(drop_unknown_uc, True)

        self.set_flood_destination(is_ucast=True)

        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.UCAST_MAC, self.VLAN)
        self.run_and_drop_unknown_bum(in_packet, out_packet, self.UCAST_MAC)

    def test_l2_switch_drop_unknown_multicast(self):
        drop_unknown_mc = self.sw1.hld_obj.get_drop_unknown_mc_enabled()
        self.assertEqual(drop_unknown_mc, False)

        self.sw1.hld_obj.set_drop_unknown_mc_enabled(True)
        drop_unknown_mc = self.sw1.hld_obj.get_drop_unknown_mc_enabled()
        self.assertEqual(drop_unknown_mc, True)

        self.set_flood_destination(is_ucast=False)

        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.MCAST_MAC, self.VLAN)
        self.run_and_drop_unknown_bum(in_packet, out_packet, self.MCAST_MAC)

    def test_l2_switch_drop_unknown_broadcast(self):
        drop_unknown_bc = self.sw1.hld_obj.get_drop_unknown_bc_enabled()
        self.assertEqual(drop_unknown_bc, False)

        self.sw1.hld_obj.set_drop_unknown_bc_enabled(True)
        drop_unknown_bc = self.sw1.hld_obj.get_drop_unknown_bc_enabled()
        self.assertEqual(drop_unknown_bc, True)

        self.set_flood_destination(is_ucast=False)

        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.BCAST_MAC, self.VLAN)
        self.run_and_drop_unknown_bum(in_packet, out_packet, self.BCAST_MAC)

    def test_l2_switch_getter(self):
        sw_by_id = self.device.get_switch_by_id(self.SWITCH_GID)
        self.assertEqual(sw_by_id.this, self.sw1.hld_obj.this)

    def test_l2_switch_mac_max(self):
        self.assertNotEqual(self.sw1.hld_obj, None)
        max_addresses = 10000
        self.sw1.hld_obj.set_max_switch_mac_addresses(max_addresses)
        max_switch_addresses = self.sw1.hld_obj.get_max_switch_mac_addresses()
        self.assertEqual(max_switch_addresses, max_addresses)

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

        self.device.set_mac_aging_interval(self.AGE_INTERVAL)
        # Check MAC entry on HW
        age_info = self.sw1.hld_obj.get_mac_entry(dest_mac.hld_obj)
        # Delete MAC entry on HW
        self.sw1.hld_obj.remove_mac_entry(dest_mac.hld_obj)
        # Check MAC entry on HW, it should not be there
        with self.assertRaises(sdk.NotFoundException):
            age_info = self.sw1.hld_obj.get_mac_entry(dest_mac.hld_obj)
        self.device.set_mac_aging_interval(sdk.LA_MAC_AGING_TIME_NEVER)

    def test_l2_switch_mac_table_scaling(self):
        self.dest_mac = T.mac_addr(self.UCAST_MAC)

        self.sw1.hld_obj.set_max_switch_mac_addresses(260000)
        max_switch_addresses = self.sw1.hld_obj.get_max_switch_mac_addresses()
        self.assertEqual(max_switch_addresses, 260000)

        self.sw1.hld_obj.set_mac_entry(self.dest_mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        self.sw1.hld_obj.remove_mac_entry(self.dest_mac.hld_obj)

        # Test set_stp_state and set_mac_learning_mode
        self.ac_port1.hld_obj.set_stp_state(sdk.la_port_stp_state_e_FORWARDING)
        self.ac_port1.hld_obj.set_mac_learning_mode(sdk.la_lp_mac_learning_mode_e_STANDALONE)

        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.UCAST_MAC, self.VLAN)

        run_and_drop(
            self,
            self.device,
            in_packet,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST)

        self.sw1.hld_obj.set_mac_entry(self.dest_mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
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

        # Pass packet from port 1 to itself by overwriting the existing MAC entry
        self.sw1.hld_obj.set_mac_entry(self.dest_mac.hld_obj, self.ac_port1.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
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

        # NOTE:
        # PSV tests will cover MAC entry scaling
        # NSIM-specific test will exercise SDK functions not CEM ARC functions
        # This test can be augmented to be executed on HW by changing the number
        # of MAC entries below and import debug_utils for white-box debugging
        entries = self.install_mac_entries(64000, False)
        print("{num_entries} MAC entries installed".format(num_entries=len(entries)))
        self.delete_mac_entries(entries)
        print("{num_entries} MAC entries deleted".format(num_entries=len(entries)))
        self.install_mac_entries(64000, True)
        print("{num_entries} MAC entries installed and deleted".format(num_entries=len(entries)))

    def test_l2_switch_flooding(self):
        self.set_flood_destination(is_ucast=True)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.UCAST_MAC, self.VLAN)
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

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_l2_switch_broadcast_flooding(self):
        self.set_flood_destination(is_ucast=False)
        in_packet, out_packet = self.create_packets(self.SRC_MAC, self.BCAST_MAC, self.VLAN)
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


if __name__ == '__main__':
    unittest.main()
