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
from scapy.all import *
import decor
import topology as T
import nplapicli as nplapi

from traps_base import *

DA_BCAST = T.mac_addr('ff:ff:ff:ff:ff:ff')

MIRROR_CMD_GID = 9

MIRROR_GID_INGRESS_OFFSET = 32
MIRROR_GID_EGRESS_OFFSET = 0
MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_traps_misc(TrapsTest):
    ISIS_DAS = ['01:80:c2:00:00:14',
                '01:80:c2:00:00:15',
                '09:00:2b:00:00:04',
                '09:00:2b:00:00:05',
                '01:00:5e:90:00:02',
                '01:00:5e:90:00:03']

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

    def snoop_setup(self):
        sampling_rate = 1.0
        HOST_MAC_ADDR1 = T.mac_addr('cd:cd:cd:cd:cd:cd')
        mirror_cmd = T.create_l2_mirror_command(
            self.device,
            MIRROR_CMD_INGRESS_GID,
            self.pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN,
            sampling_rate)

        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x1)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT)
        self.device.set_snoop_configuration(sdk.LA_EVENT_ETHERNET_ARP, 0, False, False, mirror_cmd)
        self.install_an_entry_in_copc_mac_table(ARP_ETHER_TYPE, 0xffff, T.mac_addr(
            DONT_CARE_MAC), sdk.LA_EVENT_ETHERNET_ARP, T.mac_addr(DONT_CARE_MAC))

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_arp_snoop(self):

        self.snoop_setup()

        INPUT_PACKET_WITH_VLAN_BASE = \
            S.Ether(dst=DA_BCAST.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.ARP(op='who-has')
        INPUT_PACKET_WITH_VLAN, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_VLAN_BASE)

        PUNT_PACKET_WITH_VLAN = S.Ether(dst=HOST_MAC_ADDR,
                                        src=PUNT_INJECT_PORT_MAC_ADDR,
                                        type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                                id=0,
                                                                                vlan=PUNT_VLAN,
                                                                                type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                                      fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                                      next_header_offset=0,
                                                                                                                      source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                                      code=MIRROR_CMD_INGRESS_GID,
                                                                                                                      source_sp=T.RX_SYS_PORT_GID,
                                                                                                                      destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                                      source_lp=T.RX_L2_AC_PORT_GID | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                                                                                                                      relay_id=T.RX_SWITCH_GID,
                                                                                                                      lpts_flow_type=0) / INPUT_PACKET_WITH_VLAN

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_WITH_VLAN, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        INPUT_PACKET_WITH_VLAN_BASE = \
            S.Ether(dst=DA_BCAST.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.ARP(op='who-has')
        INPUT_PACKET_WITH_VLAN, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_VLAN_BASE)

        PUNT_PACKET_WITH_VLAN = S.Ether(dst=HOST_MAC_ADDR,
                                        src=PUNT_INJECT_PORT_MAC_ADDR,
                                        type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                                id=0,
                                                                                vlan=PUNT_VLAN,
                                                                                type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                                      fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_REDIRECT,
                                                                                                                      next_header_offset=0,
                                                                                                                      source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                                      code=MIRROR_CMD_INGRESS_GID,
                                                                                                                      source_sp=T.RX_SYS_PORT_GID,
                                                                                                                      destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                                      source_lp=T.RX_L3_AC_GID,
                                                                                                                      destination_lp=sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT,
                                                                                                                      relay_id=self.PUNT_RELAY_ID,
                                                                                                                      lpts_flow_type=0) / INPUT_PACKET_WITH_VLAN

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_WITH_VLAN, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        INPUT_PACKET_WITH_VLAN_BASE = \
            S.Ether(dst=DA_BCAST.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
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
                                                                                                                      source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                                      code=MIRROR_CMD_INGRESS_GID,
                                                                                                                      source_sp=T.RX_SYS_PORT_GID,
                                                                                                                      destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                                      source_lp=T.RX_L2_AC_PORT_GID | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                                                                                                                      destination_lp=0,
                                                                                                                      relay_id=T.RX_SWITCH_GID,
                                                                                                                      lpts_flow_type=0) / INPUT_PACKET_WITH_VLAN

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_WITH_VLAN, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        INPUT_PACKET_WITH_VLAN_BASE = \
            S.Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
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
                                                                                                                      source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                                      code=MIRROR_CMD_INGRESS_GID,
                                                                                                                      source_sp=T.RX_SYS_PORT_GID,
                                                                                                                      destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                                      source_lp=T.RX_L2_AC_PORT_GID | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                                                                                                                      destination_lp=0,
                                                                                                                      relay_id=T.RX_SWITCH_GID,
                                                                                                                      lpts_flow_type=0) / INPUT_PACKET_WITH_VLAN

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_WITH_VLAN, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

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
                                                                                                                      fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_REDIRECT,
                                                                                                                      next_header_offset=0,
                                                                                                                      source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                                      code=MIRROR_CMD_INGRESS_GID,
                                                                                                                      source_sp=T.RX_SYS_PORT_GID,
                                                                                                                      destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                                      source_lp=T.RX_SVI_GID,
                                                                                                                      destination_lp=sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT,
                                                                                                                      relay_id=self.PUNT_RELAY_ID,
                                                                                                                      lpts_flow_type=0) / INPUT_PACKET_WITH_VLAN

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_WITH_VLAN, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        INPUT_PACKET_WITH_VLAN_BASE = \
            S.Ether(dst=DA_BCAST.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
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
                                                                                                                      fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_REDIRECT,
                                                                                                                      next_header_offset=0,
                                                                                                                      source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                                      code=MIRROR_CMD_INGRESS_GID,
                                                                                                                      source_sp=T.RX_SYS_PORT_GID,
                                                                                                                      destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                                      source_lp=T.RX_L3_AC_GID,
                                                                                                                      destination_lp=sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT,
                                                                                                                      relay_id=self.PUNT_RELAY_ID,
                                                                                                                      lpts_flow_type=0) / INPUT_PACKET_WITH_VLAN

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_WITH_VLAN, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

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
                                                                                                                      fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_REDIRECT,
                                                                                                                      next_header_offset=0,
                                                                                                                      source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                                      code=MIRROR_CMD_INGRESS_GID,
                                                                                                                      source_sp=T.RX_SYS_PORT_GID,
                                                                                                                      destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                                      source_lp=T.RX_L3_AC_GID,
                                                                                                                      destination_lp=sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT,
                                                                                                                      relay_id=self.PUNT_RELAY_ID,
                                                                                                                      lpts_flow_type=0) / INPUT_PACKET_WITH_VLAN

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_WITH_VLAN, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

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
                                                                                                                      fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_REDIRECT,
                                                                                                                      next_header_offset=0,
                                                                                                                      source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                                      code=MIRROR_CMD_INGRESS_GID,
                                                                                                                      source_sp=T.RX_SYS_PORT_GID,
                                                                                                                      destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                                      source_lp=T.RX_L3_AC_GID,
                                                                                                                      destination_lp=sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT,
                                                                                                                      relay_id=self.PUNT_RELAY_ID,
                                                                                                                      lpts_flow_type=0) / INPUT_PACKET_WITH_VLAN

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_WITH_VLAN, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # Teardown
        self.clear_entries_from_copc_mac_table()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_arp_who_has(self):
        '''Pass an ARP packet through a ethernet port.

           1. Ensure packet received by L2 AC port is punt when ARP trapping on ethernet port is enabled.
           2. Ensure packet received by L3 AC port is punt when ARP trapping on ethernet port is enabled.
        '''

        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x1)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP, 0, None, self.punt_dest, False, False, True, 0)
        self.install_an_entry_in_copc_mac_table(ARP_ETHER_TYPE, 0xffff, T.mac_addr(
            DONT_CARE_MAC), sdk.LA_EVENT_ETHERNET_ARP, T.mac_addr(DONT_CARE_MAC), 0x1)

        # 1. Packet received by L2 AC port is  punted with ARP trapping enabled.

        INPUT_PACKET_WITH_VLAN_BASE = \
            S.Ether(dst='ff:ff:ff:ff:ff:ff', src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.ARP(op='who-has')
        INPUT_PACKET_WITH_VLAN, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_VLAN_BASE)

        INPUT_PACKET_BASE = \
            S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str) / \
            S.ARP(op='who-has')
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

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

        PUNT_PACKET = S.Ether(dst=HOST_MAC_ADDR,
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
                                                                                                            lpts_flow_type=0) / INPUT_PACKET

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_WITH_VLAN, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # 2. Packet received by L3 AC port is  punted with ARP trapping enabled.

        INPUT_PACKET_WITH_VLAN_BASE = \
            S.Ether(dst='ff:ff:ff:ff:ff:ff', src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.ARP(op='who-has')
        INPUT_PACKET_WITH_VLAN, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_VLAN_BASE)

        INPUT_PACKET_BASE = \
            S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str) / \
            S.ARP(op='who-has')
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

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
    def test_cdp_ifg_meter(self):
        S.load_contrib("cdp")
        cdp_da = '01:00:0C:CC:CC:CC'

        self.install_an_entry_in_copc_mac_table(0, 0, T.mac_addr(cdp_da), sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)
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
                   relay_id=self.PUNT_RELAY_ID, lpts_flow_type=0) / CDP_PACKET

        cdp_ifg_meter = T.create_meter_set(self, self.device, is_aggregate=True)

        # self.device.nsim_provider.set_logging(True)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS, 0,
                                           cdp_ifg_meter, self.punt_dest, False, False, True, 0)

        (out_priority, out_meter, out_punt_dest, out_skip_inject_up_packets, out_skip_p2p_packets,
         out_overwrite_phb, out_tc) = self.device.get_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)
        self.assertEqual(out_priority, 0)
        self.assertEqual(out_meter.oid(), cdp_ifg_meter.oid())
        self.assertEqual(out_punt_dest.oid(), self.punt_dest.oid())
        self.assertEqual(out_skip_inject_up_packets, False)
        self.assertEqual(out_skip_p2p_packets, False)
        self.assertEqual(out_overwrite_phb, True)
        self.assertEqual(out_tc, 0)

        U.run_and_compare(self, self.device,
                          CDP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        packets, bytes = cdp_ifg_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packets, 1)

        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS, 0, None, self.punt_dest, False, False, True, 0)

        self.clear_entries_from_copc_mac_table()
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cdp_trap_counter(self):
        S.load_contrib("cdp")
        cdp_da = '01:00:0C:CC:CC:CC'

        self.install_an_entry_in_copc_mac_table(0, 0, T.mac_addr(cdp_da), sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)
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
                   relay_id=self.PUNT_RELAY_ID, lpts_flow_type=0) / CDP_PACKET

        cdp_trap_counter = self.device.create_counter(1)
        # self.device.nsim_provider.set_logging(True)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS, 0,
                                           cdp_trap_counter, self.punt_dest, False, False, True, 0)

        (out_priority, out_counter, out_punt_dest, out_skip_inject_up_packets, out_skip_p2p_packets,
         out_overwrite_phb, out_tc) = self.device.get_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)
        self.assertEqual(out_priority, 0)
        self.assertEqual(out_counter.oid(), cdp_trap_counter.oid())
        self.assertEqual(out_punt_dest.oid(), self.punt_dest.oid())
        self.assertEqual(out_skip_inject_up_packets, False)
        self.assertEqual(out_skip_p2p_packets, False)
        self.assertEqual(out_overwrite_phb, True)
        self.assertEqual(out_tc, 0)

        U.run_and_compare(self, self.device,
                          CDP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        packets, bytes = cdp_trap_counter.read(0, True, True)
        self.assertEqual(packets, 1)

        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS, 0,
                                           None, self.punt_dest, False, False, True, 0)

        self.clear_entries_from_copc_mac_table()
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cdp_statistical_meter(self):
        S.load_contrib("cdp")
        cdp_da = '01:00:0C:CC:CC:CC'

        self.install_an_entry_in_copc_mac_table(0, 0, T.mac_addr(cdp_da), sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)
        CDP_PACKET_BASE = \
            S.Ether(dst=cdp_da, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.LLC() / S.SNAP() / CDPv2_HDR()

        CDP_PACKET, __ = U.enlarge_packet_to_min_length(CDP_PACKET_BASE, 512)

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
                   relay_id=self.PUNT_RELAY_ID, lpts_flow_type=0) / CDP_PACKET

        # use packet>4K for statistical meters to count consistently
        CDP_PACKET_stat = CDP_PACKET / Raw(load=4096 * b'\00')
        PUNT_PACKET_stat = PUNT_PACKET / Raw(load=4096 * b'\00')

        cdp_statistical_meter = T.create_meter_set(self, self.device, is_statistical=True)
        cdp_trap_counter = self.device.create_counter(1)
        # self.device.nsim_provider.set_logging(True)
        self.device.set_trap_configuration(
            sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
            0,
            cdp_statistical_meter,
            self.punt_dest,
            False,
            False,
            True, 0)

        (out_priority, out_meter, out_punt_dest, out_skip_inject_up_packets, out_skip_p2p_packets,
         out_overwrite_phb, out_tc) = self.device.get_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)
        self.assertEqual(out_priority, 0)
        self.assertEqual(out_meter.oid(), cdp_statistical_meter.oid())
        self.assertEqual(out_punt_dest.oid(), self.punt_dest.oid())
        self.assertEqual(out_skip_inject_up_packets, False)
        self.assertEqual(out_skip_p2p_packets, False)
        self.assertEqual(out_overwrite_phb, True)
        self.assertEqual(out_tc, 0)

        U.run_and_compare(self, self.device,
                          CDP_PACKET_stat, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_stat, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        packets, bytes = cdp_statistical_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packets, 1)

        self.device.set_trap_configuration(
            sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
            0,
            cdp_trap_counter,
            self.punt_dest,
            False,
            False,
            True, 0)
        (out_priority, out_counter, out_punt_dest, out_skip_inject_up_packets, out_skip_p2p_packets,
         out_overwrite_phb, out_tc) = self.device.get_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)
        self.assertEqual(out_priority, 0)
        self.assertEqual(out_counter.oid(), cdp_trap_counter.oid())
        self.assertEqual(out_punt_dest.oid(), self.punt_dest.oid())
        self.assertEqual(out_skip_inject_up_packets, False)
        self.assertEqual(out_skip_p2p_packets, False)
        self.assertEqual(out_overwrite_phb, True)
        self.assertEqual(out_tc, 0)

        self.device.set_trap_configuration(
            sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
            0,
            None,
            self.punt_dest,
            False,
            False,
            True, 0)

        self.clear_entries_from_copc_mac_table()
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)

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
                test_traps_misc.ISIS_DAS[0]),
            sdk.LA_EVENT_L3_ISIS_OVER_L3,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            1,
            0xff)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                test_traps_misc.ISIS_DAS[2]),
            sdk.LA_EVENT_L3_ISIS_OVER_L3,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            1,
            0xff)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                test_traps_misc.ISIS_DAS[4]),
            sdk.LA_EVENT_L3_ISIS_OVER_L3,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            1,
            0xff)

        # Run and Punt
        for isis_da in test_traps_misc.ISIS_DAS:

            ISIS_PACKET, PUNT_PACKET = test_traps_misc.get_isis_and_punt_packet(isis_da)

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
                test_traps_misc.ISIS_DAS[0]),
            sdk.LA_EVENT_ETHERNET_ISIS_OVER_L2,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            0,
            0xff)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                test_traps_misc.ISIS_DAS[2]),
            sdk.LA_EVENT_ETHERNET_ISIS_OVER_L2,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            0,
            0xff)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                test_traps_misc.ISIS_DAS[4]),
            sdk.LA_EVENT_ETHERNET_ISIS_OVER_L2,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            0,
            0xff)

        # Run and Punt
        for isis_da in test_traps_misc.ISIS_DAS:

            ISIS_PACKET, PUNT_PACKET = test_traps_misc.get_isis_and_punt_packet(isis_da, is_over_l2=True)
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
                test_traps_misc.ISIS_DAS[0]),
            sdk.LA_EVENT_L3_ISIS_DRAIN,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            npp_attribute)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                test_traps_misc.ISIS_DAS[2]),
            sdk.LA_EVENT_L3_ISIS_DRAIN,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            npp_attribute)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                test_traps_misc.ISIS_DAS[4]),
            sdk.LA_EVENT_L3_ISIS_DRAIN,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            npp_attribute)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                test_traps_misc.ISIS_DAS[0]),
            sdk.LA_EVENT_L3_ISIS_OVER_L3,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            1,
            0xff)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                test_traps_misc.ISIS_DAS[2]),
            sdk.LA_EVENT_L3_ISIS_OVER_L3,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            1,
            0xff)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                test_traps_misc.ISIS_DAS[4]),
            sdk.LA_EVENT_L3_ISIS_OVER_L3,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            1,
            0xff)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                test_traps_misc.ISIS_DAS[0]),
            sdk.LA_EVENT_ETHERNET_ISIS_OVER_L2,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            0,
            0xff)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                test_traps_misc.ISIS_DAS[2]),
            sdk.LA_EVENT_ETHERNET_ISIS_OVER_L2,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            0,
            0xff)
        self.install_an_entry_in_copc_mac_table(
            0,
            0,
            T.mac_addr(
                test_traps_misc.ISIS_DAS[4]),
            sdk.LA_EVENT_ETHERNET_ISIS_OVER_L2,
            T.mac_addr('ff:ff:ff:ff:ff:fe'),
            0,
            0,
            0xff)

        self.device.set_trap_configuration(sdk.LA_EVENT_L3_ISIS_OVER_L3, 0, None, self.punt_dest, False, False, True, 0)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_ISIS_OVER_L2, 0, None, self.punt_dest, False, False, True, 0)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_ISIS_DRAIN, 0, None, None, False, False, True, 0)

        # Run and Drop
        for isis_da in test_traps_misc.ISIS_DAS:

            ISIS_PACKET, PUNT_PACKET = test_traps_misc.get_isis_and_punt_packet(isis_da)

            U.run_and_drop(self, self.device,
                           ISIS_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

            ISIS_PACKET, PUNT_PACKET = test_traps_misc.get_isis_and_punt_packet(isis_da, is_over_l2=True)

            U.run_and_drop(self, self.device,
                           ISIS_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Teardown
        self.clear_entries_from_copc_mac_table()
        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_ISIS_OVER_L3)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_ISIS_OVER_L2)
        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_ISIS_DRAIN)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_mpls_ip_options_trap(self):
        """
        1. Receive one mpls packet with 1 label and IP Option. forward it with pop operation, and catch egress trap
        """

        IP_TTL = 128
        MPLS_TTL = 64
        INPUT_LABEL = sdk.la_mpls_label()
        INPUT_LABEL.label = 0x64
        OUTPUT_LABEL = sdk.la_mpls_label()
        OUTPUT_LABEL.label = 0x20
        PRIVATE_DATA = 0x1234567890abcdef

        INPUT_PACKET_BASE = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            MPLS(label=INPUT_LABEL.label, ttl=MPLS_TTL) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=IP_TTL, options=IPOption(b'\x83\x03\x10'))

        EXPECTED_OUTPUT_PUNTED_PACKET_BASE = \
            Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_MPLS,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_MPLS_BOS_IPV4,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_EGRESS_TRAP,
                   code=sdk.LA_EVENT_IPV4_OPTIONS_EXIST,
                   source_sp=0xFFFF,
                   destination_sp=T.TX_L3_AC_SYS_PORT_REG_GID,
                   source_lp=T.RX_L3_AC_GID,
                   destination_lp=T.TX_L3_AC_REG_GID,
                   reserved2=2,  # garbage
                   relay_id=T.VRF_GID,
                   lpts_flow_type=0) / \
            MPLS(label=INPUT_LABEL.label, ttl=MPLS_TTL) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=IP_TTL, options=IPOption(b'\x83\x03\x10'))

        INPUT_PACKET, EXPECTED_OUTPUT_PUNTED_PACKET = U.pad_input_and_output_packets(INPUT_PACKET_BASE,
                                                                                     EXPECTED_OUTPUT_PUNTED_PACKET_BASE)

        self.device.set_trap_configuration(sdk.LA_EVENT_IPV4_OPTIONS_EXIST, 0, None, self.punt_dest, False, False, True, 0)

        l3_port_impl = T.ip_l3_ac_base(self.topology)
        nh = l3_port_impl.reg_nh.hld_obj

        nhlfe = self.device.create_mpls_php_nhlfe(nh)

        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, nhlfe, PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          EXPECTED_OUTPUT_PUNTED_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_mpls_ttl_trap(self):
        """
        1. Recieve one mpls packet with 1 label and TTL=1. forward it with pop operation, and catch egress trap
        2. Recieve one mpls packet with 1 label and TTL=1. forward it with swap operation, and catch egress trap
        """

        IP_TTL = 128
        MPLS_TTL_1 = 1
        INPUT_LABEL = sdk.la_mpls_label()
        INPUT_LABEL.label = 0x64
        OUTPUT_LABEL = sdk.la_mpls_label()
        OUTPUT_LABEL.label = 0x20
        PRIVATE_DATA = 0x1234567890abcdef

        INPUT_PACKET_TTL_1_BASE = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            MPLS(label=INPUT_LABEL.label, ttl=MPLS_TTL_1) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=IP_TTL)

        EXPECTED_OUTPUT_PUNTED_PACKET_BASE = \
            Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_MPLS,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_MPLS_BOS_IPV4,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_EGRESS_TRAP,
                   code=sdk.LA_EVENT_MPLS_INVALID_TTL,
                   source_sp=0xFFFF,
                   destination_sp=T.TX_L3_AC_SYS_PORT_REG_GID,
                   source_lp=T.RX_L3_AC_GID,
                   destination_lp=T.TX_L3_AC_REG_GID,
                   reserved2=2,  # garbage
                   relay_id=T.VRF_GID,
                   lpts_flow_type=0) / \
            MPLS(label=INPUT_LABEL.label, ttl=MPLS_TTL_1) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=IP_TTL)

        INPUT_PACKET_TTL_1, EXPECTED_OUTPUT_PUNTED_PACKET = U.pad_input_and_output_packets(
            INPUT_PACKET_TTL_1_BASE, EXPECTED_OUTPUT_PUNTED_PACKET_BASE)

        self.device.set_trap_configuration(sdk.LA_EVENT_MPLS_INVALID_TTL, 0, None, self.punt_dest, False, False, True, 0)

        l3_port_impl = T.ip_l3_ac_base(self.topology)
        nh = l3_port_impl.reg_nh.hld_obj

        nhlfe = self.device.create_mpls_php_nhlfe(nh)

        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, nhlfe, PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_TTL_1, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          EXPECTED_OUTPUT_PUNTED_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        nhlfe = self.device.create_mpls_swap_nhlfe(nh, OUTPUT_LABEL)
        lsr.modify_route(INPUT_LABEL, nhlfe)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_TTL_1, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          EXPECTED_OUTPUT_PUNTED_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_no_service_mapping(self):
        '''Pass two packets:

           1. One with valid (P, V) mapping, should pass successfully to the egress.
           2. One with invalid (P, V) mapping, should be dropped.
        '''

        # 1. Valid packet
        INPUT_PACKET_BASE = \
            S.Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        self.topology.rx_switch.hld_obj.set_mac_entry(
            DA.hld_obj,
            self.topology.tx_l2_ac_port_reg.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          INPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES)

        # 2. Dropped packet
        NO_SERVICE_MAPPING_VID = T.RX_L2_AC_PORT_VID1 + 1
        INPUT_PACKET_BASE = \
            S.Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=NO_SERVICE_MAPPING_VID) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        U.run_and_drop(self, self.device, INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_lacp(self):
        '''
           Pass an LACP packet over L3 AC port.
        '''

        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_LACP, 0, None, self.punt_dest, False, False, True, 0)

        lacp_da = '01:80:c2:00:00:02'
        self.install_an_entry_in_copc_mac_table(LACP_ETHER_TYPE, 0xffff, T.mac_addr(lacp_da), sdk.LA_EVENT_ETHERNET_LACP)

        LACP_PACKET_BASE = \
            S.Ether(dst=lacp_da, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_ONE_TAG_PORT_VID, type=U.Ethertype.LACP.value) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)
        LACP_PACKET, __ = U.enlarge_packet_to_min_length(LACP_PACKET_BASE)

        PUNT_PACKET = S.Ether(dst=HOST_MAC_ADDR,
                              src=PUNT_INJECT_PORT_MAC_ADDR,
                              type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                      id=0,
                                                                      vlan=PUNT_VLAN,
                                                                      type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                            fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                            next_header_offset=0,
                                                                                                            source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                                                                                                            code=sdk.LA_EVENT_ETHERNET_LACP,
                                                                                                            source_sp=T.RX_SYS_PORT_GID,
                                                                                                            destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                            source_lp=T.RX_L3_AC_ONE_TAG_GID,
                                                                                                            # destination_lp=0x7fff,
                                                                                                            destination_lp=sdk.LA_EVENT_ETHERNET_LACP,
                                                                                                            relay_id=self.PUNT_RELAY_ID,
                                                                                                            lpts_flow_type=0) / LACP_PACKET

        U.run_and_compare(self, self.device,
                          LACP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # Teardown
        self.clear_entries_from_copc_mac_table()
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_LACP)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ttl(self):
        '''Pass three packets:

           1. One with TTL > 1, should pass successfully to the egress.
           2. One with TTL = 1, should be dropped.
           3. One with TTL = 0, should be dropped.
        '''

        # 1. Valid packet
        INPUT_PACKET_TTL128_BASE = \
            S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

        EXPECTED_OUTPUT_PACKET_BASE = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1)

        INPUT_PACKET_TTL128, EXPECTED_OUTPUT_PACKET = U.pad_input_and_output_packets(
            INPUT_PACKET_TTL128_BASE, EXPECTED_OUTPUT_PACKET_BASE)

        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = DIP.to_num() & 0xffff0000
        prefix.length = 16

        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.topology.fec_l3_ac_reg.hld_obj, PRIVATE_DATA, False)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_TTL128, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        # 2. Dropped packet
        INPUT_PACKET_TTL1_BASE = \
            S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=1)
        INPUT_PACKET_TTL1, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_TTL1_BASE)

        U.run_and_drop(self, self.device, INPUT_PACKET_TTL1, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # 2. Dropped packet
        INPUT_PACKET_TTL0_BASE = \
            S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=0)
        INPUT_PACKET_TTL0, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_TTL0_BASE)

        U.run_and_drop(self, self.device, INPUT_PACKET_TTL0, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Cleanup
        self.topology.vrf.hld_obj.delete_ipv4_route(prefix)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_unsupported_protocol(self):
        '''Pass two packets:

           1. One with valid ethertype, should pass successfully to the egress.
           2. One with invalid ethertype, should be dropped.
        '''

        # 1. Valid packet
        INPUT_PACKET_BASE = \
            S.Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        self.topology.rx_switch.hld_obj.set_mac_entry(
            DA.hld_obj,
            self.topology.tx_l2_ac_port_reg.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          INPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES)

        # 2. Dropped packet
        INPUT_PACKET_PxVx_BASE = \
            S.Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Unknown.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)
        INPUT_PACKET_PxVx, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_PxVx_BASE)

        U.run_and_drop(self, self.device, INPUT_PACKET_PxVx, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)


if __name__ == '__main__':
    unittest.main()
