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

import decor
import sys
import unittest
from leaba import sdk
from scapy.all import *
import decor
import topology as T
import packet_test_utils as U
from sdk_test_case_base import *
import smart_slices_choise as ssch


U.parse_ip_after_mpls()
load_contrib('mpls')

INPUT_LABEL_OUTER = sdk.la_mpls_label()
INPUT_LABEL_OUTER.label = 0x128
INPUT_LABEL_INNER = sdk.la_mpls_label()
INPUT_LABEL_INNER.label = 0x126

PORT_SLICES = [1, 1, 1]
PORT_IFGS = [1, 1, 1]
PORT_FIRST_SERDES = [4, 6, 8]

NUM_SYS_PORTS = 3
SYS_PORT_GIDS = [12, 13, 14]
SPA_PORT_GID = 0
L3_AC_GID = 2
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

PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
HOST_MAC_ADDR = "fe:dc:ba:98:76:54"

PUNT_VLAN = 0xA13
MIRROR_CMD_GID = 9

MIRROR_GID_INGRESS_OFFSET = 32
MIRROR_GID_EGRESS_OFFSET = 0
MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET

MIRROR_VLAN = 0xA12


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class mpls_l2_adj(sdk_test_case_base):
    INJECT_SLICE = T.get_device_slice(2)  # must be an even number
    INJECT_IFG = T.get_device_ifg(0)
    INJECT_PIF_FIRST = T.get_device_first_serdes(8)
    INJECT_PIF_LAST = INJECT_PIF_FIRST + 1
    INJECT_SP_GID = 25

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

    SNOOP_PACKET_BASE = Ether(dst=HOST_MAC_ADDR,
                              src=PUNT_INJECT_PORT_MAC_ADDR,
                              type=U.Ethertype.Dot1Q.value) / Dot1Q(prio=0,
                                                                    id=0,
                                                                    vlan=MIRROR_VLAN,
                                                                    type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4,
                                                                                                          fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_MPLS_BOS_IPV4,
                                                                                                          next_header_offset=0,
                                                                                                          source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                          code=MIRROR_CMD_INGRESS_GID,
                                                                                                          source_sp=T.RX_SYS_PORT_GID,
                                                                                                          destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                          source_lp=T.RX_L3_AC_GID,
                                                                                                          destination_lp=L3_AC_GID,
                                                                                                          reserved2=2,
                                                                                                          relay_id=T.VRF_GID,
                                                                                                          lpts_flow_type=0) / Ether(dst=T.RX_L3_AC_MAC.addr_str,
                                                                                                                                    src=SA.addr_str,
                                                                                                                                    type=U.Ethertype.QinQ.value) / Dot1Q(vlan=T.RX_L3_AC_PORT_VID1,
                                                                                                                                                                         type=U.Ethertype.Dot1Q.value) / Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / MPLS(label=INPUT_LABEL_OUTER.label,
                                                                                                                                                                                                                                                 ttl=MPLS_TTL) / IP(src=SIP.addr_str,
                                                                                                                                                                                                                                                                    dst=DIP.addr_str,
                                                                                                                                                                                                                                                                    ttl=IP_TTL)
    SNOOP_PACKET = U.add_payload(SNOOP_PACKET_BASE, BASE_INPUT_PACKET_SINGLE_LABEL_PAYLOAD_SIZE)

    def setUp(self):
        super().setUp()
        ssch.rechoose_even_inject_slice(self, self.device)

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

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_adj_single_label(self):
        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        self.mirror_cmd = T.create_l2_mirror_command(
            self.device,
            MIRROR_CMD_INGRESS_GID,
            pi_port,
            HOST_MAC_ADDR,
            MIRROR_VLAN,
            1.0)

        self.topology.rx_l3_ac.hld_obj.set_ingress_sflow_enabled(True)
        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_INGRESS_MONITOR)
        self.device.set_snoop_configuration(sdk.LA_EVENT_L3_INGRESS_MONITOR, 0, False, False, self.mirror_cmd)

        pfx_obj1 = T.global_prefix_object(self, self.device, PFX_OBJ_1_GID, self.next_hop.hld_obj)
        pfx_obj2 = T.global_prefix_object(self, self.device, PFX_OBJ_2_GID, self.next_hop.hld_obj)
        l2_adj_counter1 = self.device.create_counter(1)
        l2_adj_counter2 = self.device.create_counter(1)
        pfx_obj1.hld_obj.set_global_lsp_properties([], l2_adj_counter1, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        pfx_obj2.hld_obj.set_global_lsp_properties([], l2_adj_counter2, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        nhlfe1 = self.device.create_mpls_l2_adjacency_nhlfe(pfx_obj1.hld_obj, self.system_ports[0].hld_obj)
        nhlfe2 = self.device.create_mpls_l2_adjacency_nhlfe(pfx_obj2.hld_obj, self.system_ports[1].hld_obj)

        ingress_packet = {'data': self.INPUT_PACKET_SINGLE_LABEL, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_SINGLE_LABEL, 'slice': PORT_SLICES[0],
                                 'ifg': PORT_IFGS[0], 'pif': PORT_FIRST_SERDES[0]})
        expected_packets.append({'data': self.SNOOP_PACKET, 'slice': self.INJECT_SLICE,
                                 'ifg': self.INJECT_IFG, 'pif': self.INJECT_PIF_FIRST})

        self.lsr.add_route(INPUT_LABEL_OUTER, nhlfe1, PRIVATE_DATA)
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        packet_count, byte_count = l2_adj_counter1.read(0, True, False)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SINGLE_LABEL, byte_count)

        self.lsr.delete_route(INPUT_LABEL_OUTER)
        self.device.destroy(nhlfe1)
        self.device.destroy(nhlfe2)
        self.device.destroy(pfx_obj1.hld_obj)
        self.device.destroy(pfx_obj2.hld_obj)


if __name__ == '__main__':
    unittest.main()
