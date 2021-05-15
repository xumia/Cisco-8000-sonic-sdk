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
import sim_utils
import topology as T
import packet_test_utils as U
from sdk_test_case_base import *

DUMMY_LABEL = sdk.la_mpls_label()
DUMMY_LABEL.label = 0x52

PORT_SLICES = [1, 1]
PORT_IFGS = [1, 1]
PORT_FIRST_SERDES = [4, 6]

NUM_SYS_PORTS = 2
SYS_PORT_GIDS = [12, 13]
SPA_PORT_GID = 0
L3_AC_GID = 0
NH_L3_AC_GID = 1
PFX_OBJ_GID = 1

SA = T.mac_addr('be:ef:5d:35:7a:35')
L3_AC_MAC = T.mac_addr('72:74:76:78:80:82')
NH_L3_AC_MAC = T.mac_addr('11:22:33:44:55:66')

IP_TTL = 0x90
DIP = T.ipv4_addr('100.213.95.250')
SIP1 = T.ipv4_addr('20.10.20.10')
SIP2 = T.ipv4_addr('200.1.0.2')
PRIVATE_DATA = 0x1234567890abcdef


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class spa_port_remove_rollback(sdk_test_case_base):

    INPUT_PACKET_1_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=SIP1.addr_str, dst=DIP.addr_str, ttl=IP_TTL)

    INPUT_PACKET_2_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=SIP2.addr_str, dst=DIP.addr_str, ttl=IP_TTL)

    EXPECTED_OUTPUT_PACKET_1_BASE = \
        Ether(dst=NH_L3_AC_MAC.addr_str, src=L3_AC_MAC.addr_str) / \
        IP(src=SIP1.addr_str, dst=DIP.addr_str, ttl=IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_2_BASE = \
        Ether(dst=NH_L3_AC_MAC.addr_str, src=L3_AC_MAC.addr_str) / \
        IP(src=SIP2.addr_str, dst=DIP.addr_str, ttl=IP_TTL - 1)

    PAYLOAD_SIZE = 60
    INPUT_PACKET_1 = U.add_payload(INPUT_PACKET_1_BASE, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_1 = U.add_payload(EXPECTED_OUTPUT_PACKET_1_BASE, PAYLOAD_SIZE)
    INPUT_PACKET_2 = U.add_payload(INPUT_PACKET_2_BASE, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_2 = U.add_payload(EXPECTED_OUTPUT_PACKET_2_BASE, PAYLOAD_SIZE)

    def run_and_compare_spa(self, spa_port, input_packet, input_slice, input_ifg, input_serdes, out_packet):
        dip = T.ipv4_addr(input_packet[IP].dst)
        sip = T.ipv4_addr(input_packet[IP].src)

        lb_vec_entry_list = []
        lb_vec = sdk.la_lb_vector_t()
        lb_vec.type = sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP
        lb_vec.ipv4.sip = sip.hld_obj.s_addr
        lb_vec.ipv4.dip = dip.hld_obj.s_addr
        lb_vec.ipv4.protocol = 0
        lb_vec_entry_list.append(lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(self.spa_port.hld_obj, lb_vec_entry_list)
        # For Debug purpose:
        # U.display_forwarding_load_balance_chain(self.spa_port.hld_obj, out_dest_chain)
        self.assertEqual(out_dest_chain[-1].type(), sdk.la_object.object_type_e_SYSTEM_PORT)

        out_dsp = out_dest_chain[-1].downcast()
        U.run_and_compare(self, self.device,
                          input_packet, input_slice, input_ifg, input_serdes,
                          out_packet, out_dsp.get_slice(), out_dsp.get_ifg(), out_dsp.get_base_serdes())

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

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_spa_port_remove_rollback(self):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr = T.ipv4_addr('100.213.0.0').hld_obj
        prefix.length = 16

        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.next_hop.hld_obj, 0, False)

        self.run_and_compare_spa(
            self.spa_port.hld_obj,
            self.INPUT_PACKET_1,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_1)
        self.run_and_compare_spa(
            self.spa_port.hld_obj,
            self.INPUT_PACKET_2,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_2)

        pfx_obj = T.global_prefix_object(self, self.device, PFX_OBJ_GID, self.next_hop.hld_obj)
        nhlfe = self.device.create_mpls_l2_adjacency_nhlfe(pfx_obj.hld_obj, self.system_ports[0].hld_obj)

        self.lsr.add_route(DUMMY_LABEL, nhlfe, 0)

        with self.assertRaises(sdk.BusyException):
            self.spa_port.remove(self.system_ports[0])

        # Remove call above does implicit disable. Enable member again.
        self.spa_port.hld_obj.set_member_transmit_enabled(self.system_ports[0].hld_obj, True)
        self.run_and_compare_spa(
            self.spa_port.hld_obj,
            self.INPUT_PACKET_1,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_1)
        self.run_and_compare_spa(
            self.spa_port.hld_obj,
            self.INPUT_PACKET_2,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_2)
        self.lsr.delete_route(DUMMY_LABEL)
        self.topology.vrf.hld_obj.delete_ipv4_route(prefix)
        self.device.destroy(nhlfe)
        self.device.destroy(pfx_obj.hld_obj)

        self.spa_port.hld_obj.set_member_transmit_enabled(self.system_ports[0].hld_obj, False)
        self.spa_port.hld_obj.remove(self.system_ports[0].hld_obj)


if __name__ == '__main__':
    unittest.main()
