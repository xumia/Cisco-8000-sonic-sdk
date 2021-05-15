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
import nplapicli as nplapi

from traps_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_cisco_protocols(TrapsTest):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_CDP(self):
        '''
           Two test cases
           1. Pass a CDP packet over L3 AC port and ensure packet is punted
           2. Set the destination of the CDP packet trap to None, ensure the packet is dropped
        '''

        S.load_contrib("cdp")

        # Create a meter for rate limiting for CDP punt
        cdp_meter = T.create_meter_set(self, self.device, is_aggregate=True)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS, 0,
                                           cdp_meter, self.punt_dest, False, False, True, 0)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING)

        cdp_da = '01:00:0C:CC:CC:CC'
        pvstp_da = '01:00:0C:CC:CC:CD'

        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(cdp_da),
            sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
            T.mac_addr('ff:ff:ff:ff:ff:fe'))
        CDP_PACKET_BASE = \
            S.Ether(dst=cdp_da, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.LLC() / S.SNAP() / CDPv2_HDR()

        CDP_PACKET, __ = U.enlarge_packet_to_min_length(CDP_PACKET_BASE)

        PUNT_PACKET = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_L3_AC_GID,
                   # destination_lp=0x7fff,
                   destination_lp=sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
                   relay_id=self.PUNT_RELAY_ID, lpts_flow_type=0) / \
            CDP_PACKET

        U.run_and_compare(self, self.device,
                          CDP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        packets, bytes = cdp_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packets, 1)

        # Test PVSTP packet hitting the same trap
        PVSTP_PACKET_BASE = \
            S.Ether(dst=pvstp_da, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1) / \
            S.LLC() / S.SNAP() / CDPv2_HDR()

        PVSTP_PACKET, __ = U.enlarge_packet_to_min_length(PVSTP_PACKET_BASE)

        PUNT_PACKET = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=0,
                   # destination_lp=0x3ffff,
                   destination_lp=sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
                   relay_id=0, lpts_flow_type=0) / \
            PVSTP_PACKET

        U.run_and_compare(self, self.device,
                          PVSTP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        packets, bytes = cdp_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packets, 1)

        # Now set the destination to None and ensure the packet is dropped
        counter = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS, 0, counter, None, False, False, True, 0)

        # run the packet
        U.run_and_drop(self, self.device, CDP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # test counter
        packets, bytes = counter.read(0,  # sub-counter index
                                      True,  # force_update
                                      True)  # clear_on_read
        self.assertEqual(packets, 1)

        # Teardown
        self.clear_entries_from_copc_mac_table()
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_L2PT(self):
        S.load_contrib("cdp")

        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS, 0, None, self.punt_dest, False, False, True, 0)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING)

        l2pt_da = '01:00:0C:CD:CD:D0'

        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(l2pt_da),
            sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
            T.mac_addr('ff:ff:ff:ff:ff:fe'))
        L2PT_PACKET_BASE = \
            S.Ether(dst=l2pt_da, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID2) / \
            S.LLC() / S.SNAP() / CDPv2_HDR()

        L2PT_PACKET, __ = U.enlarge_packet_to_min_length(L2PT_PACKET_BASE)

        PUNT_PACKET = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=0,
                   # destination_lp=0x7fff,
                   destination_lp=sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
                   relay_id=0, lpts_flow_type=0) / \
            L2PT_PACKET

        # Enable L2PT trap
        self.device.set_l2pt_trap_enabled(True)
        enabled = self.device.get_l2pt_trap_enabled()
        self.assertEqual(enabled, True)

        U.run_and_compare(self, self.device,
                          L2PT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # Disable L2PT trap
        self.device.set_l2pt_trap_enabled(False)
        enabled = self.device.get_l2pt_trap_enabled()
        self.assertEqual(enabled, False)

        U.run_and_drop(self, self.device,
                       L2PT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Teardown
        self.clear_entries_from_copc_mac_table()
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)


if __name__ == '__main__':
    unittest.main()
