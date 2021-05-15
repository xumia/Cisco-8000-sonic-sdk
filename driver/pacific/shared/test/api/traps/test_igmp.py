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
import sim_utils
import topology as T
import scapy.contrib.igmp

from traps_base import *
import decor

SIP = T.ipv4_addr('12.10.12.10')
DIP = T.ipv4_addr('224.0.0.5')


@unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
class TrapsIGMP(TrapsTest):
    def test_igmp(self):
        # Using General Purpose COPC Trap0 for IGMP
        self.device.set_trap_configuration(sdk.LA_EVENT_L2_LPTS_TRAP0, 0, None, self.punt_dest, False, False, True, 0)
        self.install_an_entry_in_copc_ipv4_table(0x2, 0xff, 0x0, 0x0, 0x1, 0x1, 0x0,
                                                 0x0, False, False, sdk.LA_EVENT_L2_LPTS_TRAP0)
        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x1)
        IGMP_PACKET_BASE = \
            S.Ether(dst=T.RX_L3_AC_IPv4_MC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str) / \
            scapy.contrib.igmp.IGMP(type=0x11)

        IGMP_PACKET, __ = U.enlarge_packet_to_min_length(IGMP_PACKET_BASE)

        PUNT_PACKET = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_L2_LPTS_TRAP0,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_L3_AC_GID,
                   destination_lp=sdk.LA_EVENT_L2_LPTS_TRAP0,
                   relay_id=self.PUNT_RELAY_ID,
                   lpts_flow_type=0) / IGMP_PACKET

        U.run_and_compare(self, self.device,
                          IGMP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        self.device.clear_trap_configuration(sdk.LA_EVENT_L2_LPTS_TRAP0)
        self.clear_entries_from_copc_ipv4_table()

    def test_igmp_router_alert(self):
        self.device.set_trap_configuration(sdk.LA_EVENT_L2_LPTS_TRAP0, 0, None, self.punt_dest, False, False, True, 0)
        self.install_an_entry_in_copc_ipv4_table(0x2, 0xff, 0x0, 0x0, 0x1, 0x1, 0x0,
                                                 0x0, False, False, sdk.LA_EVENT_L2_LPTS_TRAP0)
        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x1)
        IGMP_PACKET_BASE = \
            S.Ether(dst=T.RX_L3_AC_IPv4_MC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, options=scapy.layers.inet.IPOption_Router_Alert()) / \
            scapy.contrib.igmp.IGMP(type=0x22)

        IGMP_PACKET, __ = U.enlarge_packet_to_min_length(IGMP_PACKET_BASE)

        PUNT_PACKET = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_L2_LPTS_TRAP0,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_L3_AC_GID,
                   destination_lp=sdk.LA_EVENT_L2_LPTS_TRAP0,
                   relay_id=self.PUNT_RELAY_ID,
                   lpts_flow_type=0) / IGMP_PACKET

        U.run_and_compare(self, self.device,
                          IGMP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        self.device.clear_trap_configuration(sdk.LA_EVENT_L2_LPTS_TRAP0)
        self.clear_entries_from_copc_ipv4_table()


if __name__ == '__main__':
    unittest.main()
