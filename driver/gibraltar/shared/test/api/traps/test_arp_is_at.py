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
class TrapsARPTest_IsAt(TrapsTest):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_arp_is_at(self):
        '''Pass an ARP packet through an L2AC port.

           1. Ensure packet passes through when ARP trapping on ethernet port is disabled.
           2. Ensure packet is punted when ARP trapping on ethernet port is enabled.
           3. Ensure packet is punted when APP packet DMAC is SVIMAC
           4. Ensure packet is punted when APP packet DMAC is broadcast
        '''
        # Setup
        self.install_an_entry_in_copc_mac_table(ARP_ETHER_TYPE, 0xffff, T.mac_addr(
            DONT_CARE_MAC), sdk.LA_EVENT_ETHERNET_ARP, T.mac_addr(DONT_CARE_MAC), 0x1)

        # 1. Packet going through with ARP trapping disabled
        INPUT_PACKET_WITH_VLAN_BASE = \
            S.Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.ARP(op='is-at')
        INPUT_PACKET_WITH_VLAN, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_VLAN_BASE)

        self.topology.rx_switch.hld_obj.set_mac_entry(
            DA.hld_obj,
            self.topology.tx_l2_ac_port_reg.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x0)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          INPUT_PACKET_WITH_VLAN, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES)

        # 2. Packet punted with ARP trapping enabled
        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x1)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP, 0, None, self.punt_dest, False, False, True, 0)

        PUNT_PACKET_WITH_VLAN = S.Ether(dst=HOST_MAC_ADDR,
                                        src=PUNT_INJECT_PORT_MAC_ADDR,
                                        type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                                id=0,
                                                                                vlan=PUNT_VLAN,
                                                                                type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                                      fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                                      next_header_offset=0,
                                                                                                                      source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                                                                                                                      code=sdk.LA_EVENT_ETHERNET_ARP,
                                                                                                                      source_sp=T.RX_SYS_PORT_GID,
                                                                                                                      destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                                      source_lp=T.RX_L2_AC_PORT_GID | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                                                                                                                      # destination_lp=sdk.la_packet_types.LA_L2_LOGICAL_PORT_GID_INVALID,
                                                                                                                      destination_lp=sdk.LA_EVENT_ETHERNET_ARP,
                                                                                                                      relay_id=0,
                                                                                                                      lpts_flow_type=0) / INPUT_PACKET_WITH_VLAN

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_WITH_VLAN, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # 3. set mac to be the SVI mac

        INPUT_PACKET_WITH_VLAN_BASE = \
            S.Ether(dst=T.RX_SVI_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.ARP(op='is-at')
        INPUT_PACKET_WITH_VLAN, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_VLAN_BASE)

        PUNT_PACKET_WITH_VLAN = S.Ether(dst=HOST_MAC_ADDR,
                                        src=PUNT_INJECT_PORT_MAC_ADDR,
                                        type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                                id=0,
                                                                                vlan=PUNT_VLAN,
                                                                                type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                                      fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                                      next_header_offset=0,
                                                                                                                      source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                                                                                                                      code=sdk.LA_EVENT_ETHERNET_ARP,
                                                                                                                      source_sp=T.RX_SYS_PORT_GID,
                                                                                                                      destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                                      source_lp=T.RX_SVI_GID,
                                                                                                                      # destination_lp=sdk.la_packet_types.LA_L2_LOGICAL_PORT_GID_INVALID,
                                                                                                                      destination_lp=sdk.LA_EVENT_ETHERNET_ARP,
                                                                                                                      relay_id=self.PUNT_RELAY_ID,
                                                                                                                      lpts_flow_type=0) / INPUT_PACKET_WITH_VLAN

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_WITH_VLAN, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # 4. set mac to be broadcast mac

        INPUT_PACKET_WITH_VLAN_BASE = \
            S.Ether(dst='ff:ff:ff:ff:ff:ff', src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.ARP(op='is-at')
        INPUT_PACKET_WITH_VLAN, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_VLAN_BASE)

        PUNT_PACKET_WITH_VLAN = S.Ether(dst=HOST_MAC_ADDR,
                                        src=PUNT_INJECT_PORT_MAC_ADDR,
                                        type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                                id=0,
                                                                                vlan=PUNT_VLAN,
                                                                                type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                                      fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                                      next_header_offset=0,
                                                                                                                      source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                                                                                                                      code=sdk.LA_EVENT_ETHERNET_ARP,
                                                                                                                      source_sp=T.RX_SYS_PORT_GID,
                                                                                                                      destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                                      source_lp=T.RX_L2_AC_PORT_GID | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                                                                                                                      # destination_lp=sdk.la_packet_types.LA_L2_LOGICAL_PORT_GID_INVALID,
                                                                                                                      destination_lp=sdk.LA_EVENT_ETHERNET_ARP,
                                                                                                                      relay_id=0,
                                                                                                                      lpts_flow_type=0) / INPUT_PACKET_WITH_VLAN

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_WITH_VLAN, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        '''Pass an ARP packet through an L3AC port.

           1. Unicast mac address match L3AC port
           2. Unicast mac address not match L3AC port
           3. Broadcast mac address
        '''

        # 1. Unicast mac address match L3AC port
        INPUT_PACKET_WITH_VLAN_BASE = \
            S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.ARP(op='is-at')
        INPUT_PACKET_WITH_VLAN, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_VLAN_BASE)

        PUNT_PACKET_WITH_VLAN = S.Ether(dst=HOST_MAC_ADDR,
                                        src=PUNT_INJECT_PORT_MAC_ADDR,
                                        type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                                id=0,
                                                                                vlan=PUNT_VLAN,
                                                                                type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                                      fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                                      next_header_offset=0,
                                                                                                                      source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                                                                                                                      code=sdk.LA_EVENT_ETHERNET_ARP,
                                                                                                                      source_sp=T.RX_SYS_PORT_GID,
                                                                                                                      destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                                      source_lp=T.RX_L3_AC_GID,
                                                                                                                      # destination_lp=sdk.la_packet_types.LA_L2_LOGICAL_PORT_GID_INVALID,
                                                                                                                      destination_lp=sdk.LA_EVENT_ETHERNET_ARP,
                                                                                                                      relay_id=self.PUNT_RELAY_ID,
                                                                                                                      lpts_flow_type=0) / INPUT_PACKET_WITH_VLAN

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_WITH_VLAN, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # 2. Unicast mac address not match L3AC port
        INPUT_PACKET_WITH_VLAN_BASE = \
            S.Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.ARP(op='is-at')
        INPUT_PACKET_WITH_VLAN, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_VLAN_BASE)

        PUNT_PACKET_WITH_VLAN = S.Ether(dst=HOST_MAC_ADDR,
                                        src=PUNT_INJECT_PORT_MAC_ADDR,
                                        type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                                id=0,
                                                                                vlan=PUNT_VLAN,
                                                                                type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                                      fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                                      next_header_offset=0,
                                                                                                                      source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                                                                                                                      code=sdk.LA_EVENT_ETHERNET_ARP,
                                                                                                                      source_sp=T.RX_SYS_PORT_GID,
                                                                                                                      destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                                      source_lp=T.RX_L3_AC_GID,
                                                                                                                      # destination_lp=sdk.la_packet_types.LA_L2_LOGICAL_PORT_GID_INVALID,
                                                                                                                      destination_lp=sdk.LA_EVENT_ETHERNET_ARP,
                                                                                                                      relay_id=self.PUNT_RELAY_ID,
                                                                                                                      lpts_flow_type=0) / INPUT_PACKET_WITH_VLAN

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_WITH_VLAN, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # 3. Broadcase mac address
        INPUT_PACKET_WITH_VLAN_BASE = \
            S.Ether(dst='ff:ff:ff:ff:ff:ff', src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.ARP(op='is-at')
        INPUT_PACKET_WITH_VLAN, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_VLAN_BASE)

        PUNT_PACKET_WITH_VLAN = S.Ether(dst=HOST_MAC_ADDR,
                                        src=PUNT_INJECT_PORT_MAC_ADDR,
                                        type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                                id=0,
                                                                                vlan=PUNT_VLAN,
                                                                                type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                                      fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                                      next_header_offset=0,
                                                                                                                      source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                                                                                                                      code=sdk.LA_EVENT_ETHERNET_ARP,
                                                                                                                      source_sp=T.RX_SYS_PORT_GID,
                                                                                                                      destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                                      source_lp=T.RX_L3_AC_GID,
                                                                                                                      # destination_lp=sdk.la_packet_types.LA_L2_LOGICAL_PORT_GID_INVALID,
                                                                                                                      destination_lp=sdk.LA_EVENT_ETHERNET_ARP,
                                                                                                                      relay_id=self.PUNT_RELAY_ID,
                                                                                                                      lpts_flow_type=0) / INPUT_PACKET_WITH_VLAN

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_WITH_VLAN, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # Teardown
        self.clear_entries_from_copc_mac_table()
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP)


if __name__ == '__main__':
    unittest.main()
