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

import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T

from sdk_test_case_base import *
from bcast_traps_base import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class TrapBroadcastOverL3(bcast_traps_base):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_broadcast_over_l3_trap(self):
        '''
          Pass an IPv4 Broadcast packet over L3 AC port.
        '''
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT, 0, None, self.punt_dest, False, False, True, 0)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT,
                                           10, None, self.punt_dest, False, False, True, 0)

        U.run_and_compare(self, self.device, TrapBroadcastOverL3.V4_BC_PACKET,
                          T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          TrapBroadcastOverL3.PUNT_V4_BC_PACKET,
                          self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT, 10, None, self.punt_dest, False, False, True, 0)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT,
                                           0, None, self.punt_dest, False, False, True, 0)
        TrapBroadcastOverL3.PUNT_V4_BC_PACKET[U.Punt].code = sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT
        TrapBroadcastOverL3.PUNT_V4_BC_PACKET[U.Punt].destination_lp = sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT
        U.run_and_compare(self, self.device, TrapBroadcastOverL3.V4_BC_PACKET,
                          T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          TrapBroadcastOverL3.PUNT_V4_BC_PACKET,
                          self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)
        TrapBroadcastOverL3.PUNT_V4_BC_PACKET[U.Punt].code = sdk.LA_EVENT_ETHERNET_BCAST_PKT
        TrapBroadcastOverL3.PUNT_V4_BC_PACKET[U.Punt].destination_lp = sdk.LA_EVENT_ETHERNET_BCAST_PKT

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_broadcast_over_l3_trap_skip_p2p(self):
        '''
          Pass an IPv4 Broadcast packet over L3 AC port.
        '''
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT, 0, None, self.punt_dest, False, True, True, 0)

        U.run_and_compare(self, self.device, TrapBroadcastOverL3.V4_BC_PACKET,
                          T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          TrapBroadcastOverL3.PUNT_V4_BC_PACKET,
                          self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_unicast_over_l3_trap(self):
        '''
          Pass an IPv4 Unicast packet over L3 AC port.
        '''
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT, 0, None, self.punt_dest, False, False, True, 0)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT,
                                           10, None, self.punt_dest, False, False, True, 0)
        U.run_and_compare(self, self.device, TrapBroadcastOverL3.V4_UC_PACKET,
                          T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          TrapBroadcastOverL3.PUNT_V4_UC_PACKET,
                          self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_unicast_over_l3_p2p_skip_trap(self):
        '''
          Pass an IPv4 Unicast packet over L3 AC port.
        '''
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT, 0, None, self.punt_dest, False, False, True, 0)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT,
                                           10, None, self.punt_dest, False, False, True, 0)
        U.run_and_compare(self, self.device, TrapBroadcastOverL3.V4_UC_PACKET,
                          T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          TrapBroadcastOverL3.PUNT_V4_UC_PACKET,
                          self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_broadcast_over_l3_ac_disabled_trap(self):
        '''
          Pass an IPv4 Broadcast packet over L3 AC port.
          l3_ac disabled, IPv4 Broadcast packet should still be trapped
        '''
        # Disabled the l3_ac, IPv4 Broadcast should be be still trapped
        self.topology.rx_l3_ac.hld_obj.set_active(False)
        self.test_ipv4_broadcast_over_l3_trap()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_arp_broadcast_over_l3_trap(self):
        '''
         Turn off arp on port. Arp packet should be trapped with code LA_EVENT_ETHERNET_BCAST_PKT'
        '''
        # setup
        self.install_an_entry_in_copc_mac_table(ARP_ETHER_TYPE, 0xffff, T.mac_addr(
            DONT_CARE_MAC), sdk.LA_EVENT_ETHERNET_ARP, T.mac_addr(DONT_CARE_MAC), 0x1)

        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x0)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT, 0, None, self.punt_dest, False, False, True, 0)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT,
                                           10, None, self.punt_dest, False, False, True, 0)
        U.run_and_compare(self, self.device,
                          TrapBroadcastOverL3.ARP_BC_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          TrapBroadcastOverL3.PUNT_ARP_BC_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x1)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP, 0, None, self.punt_dest, False, False, True, 0)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT, 5, None, self.punt_dest, False, False, True, 0)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT,
                                           10, None, self.punt_dest, False, False, True, 0)
        TrapBroadcastOverL3.PUNT_ARP_BC_PACKET[U.Punt].code = sdk.LA_EVENT_ETHERNET_ARP
        TrapBroadcastOverL3.PUNT_ARP_BC_PACKET[U.Punt].destination_lp = sdk.LA_EVENT_ETHERNET_ARP
        U.run_and_compare(self, self.device,
                          TrapBroadcastOverL3.ARP_BC_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          TrapBroadcastOverL3.PUNT_ARP_BC_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x1)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP, 5, None, self.punt_dest, False, False, True, 0)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT, 0, None, self.punt_dest, False, False, True, 0)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT,
                                           10, None, self.punt_dest, False, False, True, 0)
        TrapBroadcastOverL3.PUNT_ARP_BC_PACKET[U.Punt].code = sdk.LA_EVENT_ETHERNET_BCAST_PKT
        TrapBroadcastOverL3.PUNT_ARP_BC_PACKET[U.Punt].destination_lp = sdk.LA_EVENT_ETHERNET_BCAST_PKT
        U.run_and_compare(self, self.device,
                          TrapBroadcastOverL3.ARP_BC_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          TrapBroadcastOverL3.PUNT_ARP_BC_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # teardown
        self.clear_entries_from_copc_mac_table()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_broadcast_over_l3_trap(self):
        '''
          Pass an L2 Broadcast packet over L3 AC port.
        '''
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT, 0, None, self.punt_dest, False, False, True, 0)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT,
                                           10, None, self.punt_dest, False, False, True, 0)
        U.run_and_compare(self, self.device, TrapBroadcastOverL3.L2_BC_PACKET,
                          T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          TrapBroadcastOverL3.PUNT_L2_BC_PACKET,
                          self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)


if __name__ == '__main__':
    unittest.main()
