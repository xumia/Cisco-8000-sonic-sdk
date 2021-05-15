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

DA_BCAST = T.mac_addr('ff:ff:ff:ff:ff:ff')


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_arp_reply(TrapsTest):

    def install_entry_in_copc_mac_table(
            self,
            ether_value,
            ether_mask,
            my_mac_value,
            my_mac_mask,
            is_svi_value,
            is_svi_mask,
            event):

        key1 = []
        f1 = sdk.field()
        f1.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_ETHERTYPE
        f1.val.mac.ethertype = ether_value
        f1.mask.mac.ethertype = ether_mask
        key1.append(f1)

        f2 = sdk.field()
        f2.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_MY_MAC
        f2.val.mac.my_mac = my_mac_value
        f2.mask.mac.my_mac = my_mac_mask
        key1.append(f2)

        f3 = sdk.field()
        f3.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_IS_SVI
        f3.val.mac.is_svi = is_svi_value
        f3.mask.mac.is_svi = is_svi_mask
        key1.append(f3)

        result1 = sdk.result()
        result1.event = event

        self.copc_mac.append(key1, result1)

    def clear_copc_mac_table(self):
        self.copc_mac.clear()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_arp_reply(self):
        # Setup
        self.install_entry_in_copc_mac_table(ARP_ETHER_TYPE, 0xffff, True, True, True, True, sdk.LA_EVENT_ETHERNET_ARP)
        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x1)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP, 0, None, self.punt_dest, False, False, True, 0)

        # 1. ARP packet with known unicast mac
        INPUT_PACKET_WITH_VLAN_BASE = \
            S.Ether(dst=T.RX_SVI_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.ARP(op='is-at')
        INPUT_PACKET_WITH_VLAN, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_VLAN_BASE)

        PUNT_PACKET_WITH_VLAN = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_ARP,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_SVI_GID,
                   destination_lp=sdk.LA_EVENT_ETHERNET_ARP,
                   relay_id=self.PUNT_RELAY_ID,
                   lpts_flow_type=0) / INPUT_PACKET_WITH_VLAN

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_WITH_VLAN, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        self.clear_copc_mac_table()

        # 2. ARP packet with unknown unicast mac
        self.install_entry_in_copc_mac_table(ARP_ETHER_TYPE, 0xffff, False, True, True, True, sdk.LA_EVENT_ETHERNET_ARP)
        INPUT_PACKET_WITH_VLAN_BASE = \
            S.Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.ARP(op='is-at')
        INPUT_PACKET_WITH_VLAN, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_VLAN_BASE)

        PUNT_PACKET_WITH_VLAN = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_ARP,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING + T.RX_L2_AC_PORT_GID,
                   destination_lp=sdk.LA_EVENT_ETHERNET_ARP,
                   relay_id=0,
                   lpts_flow_type=0) / INPUT_PACKET_WITH_VLAN

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_WITH_VLAN, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        self.clear_copc_mac_table()

        # 3. ARP packet with broadcast mac
        self.install_entry_in_copc_mac_table(ARP_ETHER_TYPE, 0xffff, False, True, True, True, sdk.LA_EVENT_ETHERNET_ARP)
        INPUT_PACKET_WITH_VLAN_BASE = \
            S.Ether(dst=DA_BCAST.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.ARP(op='is-at')
        INPUT_PACKET_WITH_VLAN, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_VLAN_BASE)

        PUNT_PACKET_WITH_VLAN = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_ARP,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING + T.RX_L2_AC_PORT_GID,
                   destination_lp=sdk.LA_EVENT_ETHERNET_ARP,
                   relay_id=0,
                   lpts_flow_type=0) / INPUT_PACKET_WITH_VLAN

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_WITH_VLAN, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # Teardown
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP)


if __name__ == '__main__':
    unittest.main()
