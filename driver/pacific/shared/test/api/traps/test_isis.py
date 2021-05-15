#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import sim_utils
import topology as T
import nplapicli as nplapi

from traps_base import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class TrapsIsis(TrapsTest):

    ISIS_DAS = [
        '01:80:c2:00:00:14',
        '01:80:c2:00:00:15',
        '09:00:2b:00:00:04',
        '09:00:2b:00:00:05',
        '01:00:5e:90:00:02',
        '01:00:5e:90:00:03']

    @staticmethod
    def get_isis_and_punt_packet(isis_da, is_over_l2=False):
        if is_over_l2:
            ISIS_PACKET_BASE = \
                S.Ether(dst=isis_da, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1)
        else:
            ISIS_PACKET_BASE = \
                S.Ether(dst=isis_da, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

        ISIS_PACKET, __ = U.enlarge_packet_to_min_length(ISIS_PACKET_BASE)

        punt_slp = (T.RX_L2_AC_PORT_GID | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING) if is_over_l2 else T.RX_L3_AC_GID
        punt_code = sdk.LA_EVENT_ETHERNET_ISIS_OVER_L2 if is_over_l2 else sdk.LA_EVENT_L3_ISIS_OVER_L3

        PUNT_PACKET = S.Ether(dst=HOST_MAC_ADDR,
                              src=PUNT_INJECT_PORT_MAC_ADDR,
                              type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                      id=0,
                                                                      vlan=PUNT_VLAN,
                                                                      type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                            fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                            next_header_offset=0,
                                                                                                            source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                                                                                                            code=punt_code,
                                                                                                            source_sp=T.RX_SYS_PORT_GID,
                                                                                                            destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                            source_lp=punt_slp,
                                                                                                            destination_lp=punt_code,
                                                                                                            relay_id=TrapsTest.PUNT_RELAY_ID,
                                                                                                            lpts_flow_type=0) / ISIS_PACKET

        return ISIS_PACKET, PUNT_PACKET

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_isis_over_l3(self):
        '''
           Pass an ISIS packet over L3 AC port.

           Ensure packet is punted for all relevant MAC DA-s.
        '''

        # Setup
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_ISIS_OVER_L3, 0, None, self.punt_dest, False, False, True, 0)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                TrapsIsis.ISIS_DAS[0]),
            sdk.LA_EVENT_L3_ISIS_OVER_L3,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            1,
            0xff)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                TrapsIsis.ISIS_DAS[2]),
            sdk.LA_EVENT_L3_ISIS_OVER_L3,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            1,
            0xff)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                TrapsIsis.ISIS_DAS[4]),
            sdk.LA_EVENT_L3_ISIS_OVER_L3,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            1,
            0xff)

        # Run and Punt
        for isis_da in TrapsIsis.ISIS_DAS:

            ISIS_PACKET, PUNT_PACKET = TrapsIsis.get_isis_and_punt_packet(isis_da)

            U.run_and_compare(self, self.device,
                              ISIS_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                              PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # Teardown
        self.clear_entries_from_copc_mac_table()
        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_ISIS_OVER_L3)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_isis_over_l2(self):
        '''
           Pass an ISIS packet over L2 AC port.

           Ensure packet is punted for all relevant MAC DA-s.
        '''

        # Setup
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_ISIS_OVER_L2, 0, None, self.punt_dest, False, False, True, 0)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                TrapsIsis.ISIS_DAS[0]),
            sdk.LA_EVENT_ETHERNET_ISIS_OVER_L2,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            0,
            0xff)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                TrapsIsis.ISIS_DAS[2]),
            sdk.LA_EVENT_ETHERNET_ISIS_OVER_L2,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            0,
            0xff)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                TrapsIsis.ISIS_DAS[4]),
            sdk.LA_EVENT_ETHERNET_ISIS_OVER_L2,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            0,
            0xff)

        # Run and Punt
        for isis_da in TrapsIsis.ISIS_DAS:

            ISIS_PACKET, PUNT_PACKET = TrapsIsis.get_isis_and_punt_packet(isis_da, is_over_l2=True)
            PUNT_PACKET.relay_id = 0

            U.run_and_compare(self, self.device,
                              ISIS_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                              PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # Teardown
        self.clear_entries_from_copc_mac_table()
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_ISIS_OVER_L2)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_isis_drain(self):
        '''
           Pass an ISIS packet over L3 and L2 AC ports with isis_drain enabled.
           Configure ISIS_DRAIN trap to drop.
           Configure ISIS_OVER_L3 and ISIS_OVER_L2 traps to punt.

           Ensure packet is dropped for all relevant MAC DA-s.
        '''

        # Setup
        npp_attribute = 0x1
        self.topology.rx_eth_port.hld_obj.set_copc_profile(npp_attribute)
        prof_val = self.topology.rx_eth_port.hld_obj.get_copc_profile()
        self.assertEqual(prof_val, npp_attribute)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                TrapsIsis.ISIS_DAS[0]),
            sdk.LA_EVENT_L3_ISIS_DRAIN,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            npp_attribute)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                TrapsIsis.ISIS_DAS[2]),
            sdk.LA_EVENT_L3_ISIS_DRAIN,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            npp_attribute)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                TrapsIsis.ISIS_DAS[4]),
            sdk.LA_EVENT_L3_ISIS_DRAIN,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            npp_attribute)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                TrapsIsis.ISIS_DAS[0]),
            sdk.LA_EVENT_L3_ISIS_OVER_L3,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            1,
            0xff)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                TrapsIsis.ISIS_DAS[2]),
            sdk.LA_EVENT_L3_ISIS_OVER_L3,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            1,
            0xff)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                TrapsIsis.ISIS_DAS[4]),
            sdk.LA_EVENT_L3_ISIS_OVER_L3,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            1,
            0xff)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                TrapsIsis.ISIS_DAS[0]),
            sdk.LA_EVENT_ETHERNET_ISIS_OVER_L2,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            0,
            0xff)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                TrapsIsis.ISIS_DAS[2]),
            sdk.LA_EVENT_ETHERNET_ISIS_OVER_L2,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            0,
            0xff)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                TrapsIsis.ISIS_DAS[4]),
            sdk.LA_EVENT_ETHERNET_ISIS_OVER_L2,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            0,
            0xff)

        self.device.set_trap_configuration(sdk.LA_EVENT_L3_ISIS_OVER_L3, 0, None, self.punt_dest, False, False, True, 0)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_ISIS_OVER_L2, 0, None, self.punt_dest, False, False, True, 0)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_ISIS_DRAIN, 0, None, None, False, False, True, 0)

        # Run and Drop
        for isis_da in TrapsIsis.ISIS_DAS:

            ISIS_PACKET, PUNT_PACKET = TrapsIsis.get_isis_and_punt_packet(isis_da)

            U.run_and_drop(self, self.device,
                           ISIS_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

            ISIS_PACKET, PUNT_PACKET = TrapsIsis.get_isis_and_punt_packet(isis_da, is_over_l2=True)

            U.run_and_drop(self, self.device,
                           ISIS_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Teardown
        self.clear_entries_from_copc_mac_table()
        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_ISIS_OVER_L3)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_ISIS_OVER_L2)
        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_ISIS_DRAIN)


if __name__ == '__main__':
    unittest.main()
