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

# Test covering CSCvm73033.
#
# Verifies forwarding of UDP packets with destination port 6784 (BFDoLAG) even
# when forwarding is disabled.

import decor
from scapy.all import *
import sys
import unittest
from leaba import sdk
import sim_utils
import topology as T
import packet_test_utils as U
import ip_test_base

SIP = T.ipv4_addr('12.10.12.10')
DIP = T.ipv4_addr('82.81.95.250')
PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
IP_TTL = 0x88
SA = T.mac_addr('be:ef:5d:35:7a:35')
PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
PUNT_VLAN = 0xA13
INJECT_SLICE = 0
PUNT_RELAY_ID = 0 if decor.is_pacific() else T.VRF_GID


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class forwarding_disabled(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(1)

        self.topology = T.topology(self, self.device)

        self.l3_port_impl = T.ip_l3_ac_base(self.topology)
        self.ip_impl = ip_test_base.ipv4_test_base()

        self.add_default_route()

    def tearDown(self):
        self.device.tearDown()

    def add_default_route(self):
        prefix = self.ip_impl.build_prefix(DIP, length=0)
        self.ip_impl.add_route(
            self.topology.vrf,
            prefix,
            self.l3_port_impl.def_nh,
            PRIVATE_DATA_DEFAULT)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_forwarding_disabled(self):
        # Disable IP forwarding on the port
        self.l3_port_impl.rx_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, False)

        prefix = self.ip_impl.build_prefix(DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_nh, PRIVATE_DATA_DEFAULT)
        cpu_punt_port = self.topology.inject_ports[INJECT_SLICE]

        # create punt dest
        punt_dest = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            cpu_punt_port,
            HOST_MAC_ADDR,
            PUNT_VLAN)

        # enable the trap
        counter = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_BFD_MICRO_IP_DISABLED, 0,
                                           counter, punt_dest,
                                           False, False, True, 0)
        INPUT_PACKET_BASE = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=IP_TTL) / \
            UDP(sport=2048, dport=6784, chksum=0)

        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=22,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_L3_BFD_MICRO_IP_DISABLED,
                   source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   #source_lp=T.RX_L3_AC_GID, destination_lp=sdk.la_packet_types.LA_L3_LOGICAL_PORT_GID_INVALID,
                   source_lp=T.RX_L3_AC_GID, destination_lp=sdk.LA_EVENT_L3_BFD_MICRO_IP_DISABLED,
                   relay_id=PUNT_RELAY_ID, lpts_flow_type=0) / \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=IP_TTL) / \
            UDP(sport=2048, dport=6784, chksum=0)

        INPUT_PACKET, EXPECTED_OUTPUT_PACKET = U.pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)

        pi_pif = self.device.get_pci_serdes()

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          EXPECTED_OUTPUT_PACKET, INJECT_SLICE, T.PI_IFG, pi_pif)

        packets, bytes = counter.read(0, True, True)
        self.assertEqual(packets, 1)


if __name__ == '__main__':
    unittest.main()
