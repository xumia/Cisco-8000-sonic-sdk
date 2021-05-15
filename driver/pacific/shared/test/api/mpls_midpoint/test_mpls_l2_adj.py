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

import sys
import unittest
from leaba import sdk
from scapy.all import *
import sim_utils
import topology as T
import packet_test_utils as U
from sdk_test_case_base import *
import decor

U.parse_ip_after_mpls()
load_contrib('mpls')

INPUT_LABEL_OUTER = sdk.la_mpls_label()
INPUT_LABEL_OUTER.label = 0x128
INPUT_LABEL_INNER = sdk.la_mpls_label()
INPUT_LABEL_INNER.label = 0x126

SLICE1 = T.get_device_slice(1)
IFG1 = T.get_device_ifg(1)

PORT_SLICES = [SLICE1, SLICE1, SLICE1]
PORT_IFGS = [IFG1, IFG1, IFG1]
PORT_FIRST_SERDES = [T.get_device_first_serdes(4), T.get_device_next_first_serdes(6),
                     T.get_device_out_first_serdes(8)]

NUM_SYS_PORTS = 3
SYS_PORT_GIDS = [12, 13, 14]
SPA_PORT_GID = 0
L3_AC_GID = 0
NH_L3_AC_GID = 1
NH_DROP_GID = 2
NH_GLEAN_GID = 3
PFX_OBJ_1_GID = 0
PFX_OBJ_2_GID = 1

SA = T.mac_addr('be:ef:5d:35:7a:35')
L3_AC_MAC = T.mac_addr('72:74:76:78:80:82')
NH_L3_AC_MAC = T.mac_addr('11:22:33:44:55:66')

MPLS_TTL = 0x88
IP_TTL = 0x90
DIP = T.ipv4_addr('82.81.95.250')
SIP = T.ipv4_addr('12.10.12.10')
PRIVATE_DATA = 0x1234567890abcdef


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class mpls_l2_adj(sdk_test_case_base):

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=INPUT_LABEL_OUTER.label, ttl=MPLS_TTL) / \
        MPLS(label=INPUT_LABEL_INNER.label, ttl=MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=IP_TTL)

    INPUT_PACKET_SINGLE_LABEL_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=INPUT_LABEL_OUTER.label, ttl=MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=IP_TTL)

    EXPECTED_OUTPUT_PACKET_BASE = \
        Ether(dst=NH_L3_AC_MAC.addr_str, src=L3_AC_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=INPUT_LABEL_INNER.label, ttl=MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=IP_TTL)

    EXPECTED_OUTPUT_PACKET_SINGLE_LABEL_BASE = \
        Ether(dst=NH_L3_AC_MAC.addr_str, src=L3_AC_MAC.addr_str) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=IP_TTL)

    INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_SINGLE_LABEL, BASE_INPUT_PACKET_SINGLE_LABEL_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(
        INPUT_PACKET_SINGLE_LABEL_BASE)
    EXPECTED_OUTPUT_PACKET_SINGLE_LABEL = U.add_payload(
        EXPECTED_OUTPUT_PACKET_SINGLE_LABEL_BASE,
        BASE_INPUT_PACKET_SINGLE_LABEL_PAYLOAD_SIZE)

    def setUp(self):
        super().setUp()
        self.lsr = self.device.get_lsr()

        self.create_ports()

    def create_ports(self):
        self.system_ports = []
        self.spa_port = T.spa_port(self, self.device, SPA_PORT_GID)
        for x in range(NUM_SYS_PORTS):
            mac_port = T.mac_port(self, self.device, PORT_SLICES[x], PORT_IFGS[x], PORT_FIRST_SERDES[x], PORT_FIRST_SERDES[x] + 1)
            mac_port.activate()
            self.system_ports.append(T.system_port(self, self.device, SYS_PORT_GIDS[x], mac_port))
            self.spa_port.add(self.system_ports[x])

        self.eth_port = T.sa_ethernet_port(self, self.device, self.spa_port)
        self.l3_ac_port = T.l3_ac_port(self, self.device, L3_AC_GID, self.eth_port, self.topology.vrf, L3_AC_MAC)
        self.next_hop = T.next_hop(self, self.device, NH_L3_AC_GID, NH_L3_AC_MAC, self.l3_ac_port)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_adj(self):
        pfx_obj1 = T.global_prefix_object(self, self.device, PFX_OBJ_1_GID, self.next_hop.hld_obj)
        pfx_obj2 = T.global_prefix_object(self, self.device, PFX_OBJ_2_GID, self.next_hop.hld_obj)
        l2_adj_counter1 = self.device.create_counter(1)
        l2_adj_counter2 = self.device.create_counter(1)
        pfx_obj1.hld_obj.set_global_lsp_properties([], l2_adj_counter1, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        pfx_obj2.hld_obj.set_global_lsp_properties([], l2_adj_counter2, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        nhlfe1 = self.device.create_mpls_l2_adjacency_nhlfe(pfx_obj1.hld_obj, self.system_ports[0].hld_obj)
        nhlfe2 = self.device.create_mpls_l2_adjacency_nhlfe(pfx_obj2.hld_obj, self.system_ports[1].hld_obj)

        self.lsr.add_route(INPUT_LABEL_OUTER, nhlfe1, PRIVATE_DATA)

        U.run_and_compare(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, PORT_SLICES[0], PORT_IFGS[0], PORT_FIRST_SERDES[0])

        packet_count, byte_count = l2_adj_counter1.read(0, True, False)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)

        self.lsr.modify_route(INPUT_LABEL_OUTER, nhlfe2)

        U.run_and_compare(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, PORT_SLICES[1], PORT_IFGS[1], PORT_FIRST_SERDES[1])

        packet_count, byte_count = l2_adj_counter2.read(0, True, False)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)

        self.lsr.delete_route(INPUT_LABEL_OUTER)
        self.device.destroy(nhlfe1)
        self.device.destroy(nhlfe2)
        self.device.destroy(pfx_obj1.hld_obj)
        self.device.destroy(pfx_obj2.hld_obj)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_adj_single_label(self):
        pfx_obj1 = T.global_prefix_object(self, self.device, PFX_OBJ_1_GID, self.next_hop.hld_obj)
        pfx_obj2 = T.global_prefix_object(self, self.device, PFX_OBJ_2_GID, self.next_hop.hld_obj)
        l2_adj_counter1 = self.device.create_counter(1)
        l2_adj_counter2 = self.device.create_counter(1)
        pfx_obj1.hld_obj.set_global_lsp_properties([], l2_adj_counter1, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        pfx_obj2.hld_obj.set_global_lsp_properties([], l2_adj_counter2, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        nhlfe1 = self.device.create_mpls_l2_adjacency_nhlfe(pfx_obj1.hld_obj, self.system_ports[0].hld_obj)
        nhlfe2 = self.device.create_mpls_l2_adjacency_nhlfe(pfx_obj2.hld_obj, self.system_ports[1].hld_obj)

        self.lsr.add_route(INPUT_LABEL_OUTER, nhlfe1, PRIVATE_DATA)
        U.run_and_compare(self, self.device, self.INPUT_PACKET_SINGLE_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SINGLE_LABEL, PORT_SLICES[0], PORT_IFGS[0], PORT_FIRST_SERDES[0])

        packet_count, byte_count = l2_adj_counter1.read(0, True, False)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SINGLE_LABEL, byte_count)

        self.lsr.modify_route(INPUT_LABEL_OUTER, nhlfe2)

        U.run_and_compare(self, self.device, self.INPUT_PACKET_SINGLE_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SINGLE_LABEL, PORT_SLICES[1], PORT_IFGS[1], PORT_FIRST_SERDES[1])

        packet_count, byte_count = l2_adj_counter2.read(0, True, False)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SINGLE_LABEL, byte_count)

        self.lsr.delete_route(INPUT_LABEL_OUTER)
        self.device.destroy(nhlfe1)
        self.device.destroy(nhlfe2)
        self.device.destroy(pfx_obj1.hld_obj)
        self.device.destroy(pfx_obj2.hld_obj)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_adj_invalid_param(self):
        pfx_obj = T.global_prefix_object(self, self.device, PFX_OBJ_1_GID, self.topology.nh_l3_ac_reg.hld_obj)

        with self.assertRaises(sdk.InvalException):
            nhlfe = self.device.create_mpls_l2_adjacency_nhlfe(pfx_obj.hld_obj, self.system_ports[0].hld_obj)

        pfx_obj.hld_obj.set_destination(self.next_hop.hld_obj)
        nhlfe = self.device.create_mpls_l2_adjacency_nhlfe(pfx_obj.hld_obj, self.system_ports[0].hld_obj)

        self.device.destroy(nhlfe)
        self.spa_port.remove(self.system_ports[0])

        with self.assertRaises(sdk.InvalException):
            self.device.create_mpls_l2_adjacency_nhlfe(pfx_obj.hld_obj, self.system_ports[0].hld_obj)

        self.spa_port.add(self.system_ports[0])

        self.device.destroy(pfx_obj.hld_obj)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_adj_spa_member_remove(self):
        pfx_obj = T.global_prefix_object(self, self.device, PFX_OBJ_1_GID, self.next_hop.hld_obj)

        nhlfe = self.device.create_mpls_l2_adjacency_nhlfe(pfx_obj.hld_obj, self.system_ports[0].hld_obj)

        with self.assertRaises(sdk.BusyException):
            self.spa_port.remove(self.system_ports[0])

        self.device.destroy(nhlfe)
        self.device.destroy(pfx_obj.hld_obj)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_adj_glean_drop_adj(self):
        glean_nh = T.next_hop(self, self.device, NH_GLEAN_GID, NH_L3_AC_MAC, None, sdk.la_next_hop.nh_type_e_GLEAN)
        drop_nh = T.next_hop(self, self.device, NH_DROP_GID, NH_L3_AC_MAC, None, sdk.la_next_hop.nh_type_e_DROP)

        glean_ctr = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_GLEAN_ADJ, 0, glean_ctr, None, False, False, True, 0)
        drop_ctr = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_DROP_ADJ, 0, drop_ctr, None, False, False, True, 0)

        glean_pfx_obj = T.global_prefix_object(self, self.device, PFX_OBJ_1_GID, glean_nh.hld_obj)
        drop_pfx_obj = T.global_prefix_object(self, self.device, PFX_OBJ_2_GID, drop_nh.hld_obj)

        glean_nhlfe = self.device.create_mpls_l2_adjacency_nhlfe(glean_pfx_obj.hld_obj, None)
        drop_nhlfe = self.device.create_mpls_l2_adjacency_nhlfe(drop_pfx_obj.hld_obj, None)

        self.lsr.add_route(INPUT_LABEL_OUTER, glean_nhlfe, PRIVATE_DATA)
        U.run_and_drop(self, self.device, self.INPUT_PACKET_SINGLE_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        packet_count, byte_count = glean_ctr.read(0, True, False)
        self.assertEqual(packet_count, 1)

        self.lsr.modify_route(INPUT_LABEL_OUTER, drop_nhlfe)
        U.run_and_drop(self, self.device, self.INPUT_PACKET_SINGLE_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        packet_count, byte_count = drop_ctr.read(0, True, False)
        self.assertEqual(packet_count, 1)

        self.lsr.delete_route(INPUT_LABEL_OUTER)

        self.device.destroy(glean_nhlfe)
        self.device.destroy(glean_pfx_obj.hld_obj)
        self.device.destroy(glean_nh.hld_obj)

        self.device.destroy(drop_nhlfe)
        self.device.destroy(drop_pfx_obj.hld_obj)
        self.device.destroy(drop_nh.hld_obj)


if __name__ == '__main__':
    unittest.main()
