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
import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import decor
import topology as T

from sdk_test_case_base import *
from bcast_traps_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class SnoopBroadcastOverL3(bcast_traps_base):

    def setUp(self):
        super().setUp()
        self.mirror_cmd = T.create_l2_mirror_command(self.device, MIRROR_CMD_INGRESS_GID, self.pi_port, HOST_MAC_ADDR, MIRROR_VLAN)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT)
        self.trap_counter = self.device.create_counter(1)
        self.device.set_trap_configuration(
            sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT,
            0, self.trap_counter, None, False, False, True, 0)
        self.device.set_snoop_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT, 0, False, False, self.mirror_cmd)

    def tearDown(self):
        # Ensure the l3_ac is active
        self.topology.rx_l3_ac.hld_obj.set_active(True)
        self.device.clear_trap_configuration(
            sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT)
        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x0)
        super().tearDown()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_ipv4_broadcast_over_l3_snoop(self):
        '''
          Pass an IPv4 Broadcast packet over L3 AC port.
        '''
        U.run_and_compare(self, self.device, SnoopBroadcastOverL3.V4_BC_PACKET,
                          T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          SnoopBroadcastOverL3.SNOOP_V4_BC_PACKET,
                          self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)
        # original packet should be trapped and dropped by LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT
        packet_count, byte_count = self.trap_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_ipv4_unicast_over_l3_snoop(self):
        '''
          Pass an IPv4 Unicast packet over L3 AC port.
        '''
        U.run_and_compare(self, self.device, SnoopBroadcastOverL3.V4_UC_PACKET,
                          T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          SnoopBroadcastOverL3.SNOOP_V4_UC_PACKET,
                          self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)
        # original packet should be trapped and dropped by LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT
        packet_count, byte_count = self.trap_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_ipv4_broadcast_over_l3_ac_disabled_snoop(self):
        '''
          Pass an IPv4 Broadcast packet over L3 AC port.
          l3_ac disabled, IPv4 Broadcast packet should still be trapped
        '''
        # Disabled the l3_ac, IPv4 Broadcast should be be still trapped
        self.topology.rx_l3_ac.hld_obj.set_active(False)
        self.test_ipv4_broadcast_over_l3_snoop()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_arp_broadcast_over_l3_snoop(self):
        '''
         Turn off arp on port. Arp packet should be trapped with code LA_EVENT_ETHERNET_BCAST_PKT+32'
        '''
        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x0)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP)
        U.run_and_compare(self, self.device,
                          SnoopBroadcastOverL3.ARP_BC_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          SnoopBroadcastOverL3.SNOOP_ARP_BC_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)
        # original packet should be trapped and dropped by LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT
        packet_count, byte_count = self.trap_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x1)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP, 0, None, self.punt_dest, False, False, True, 0)
        U.run_and_compare(self, self.device,
                          SnoopBroadcastOverL3.ARP_BC_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          SnoopBroadcastOverL3.SNOOP_ARP_BC_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_l2_broadcast_over_l3_snoop(self):
        '''
          Pass an L2 Broadcast packet over L3 AC port.
        '''
        U.run_and_compare(self, self.device, SnoopBroadcastOverL3.L2_BC_PACKET,
                          T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          SnoopBroadcastOverL3.SNOOP_L2_BC_PACKET,
                          self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)
        # original packet should be trapped and dropped by LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT
        packet_count, byte_count = self.trap_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)


if __name__ == '__main__':
    unittest.main()
