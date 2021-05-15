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

import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import decor
import topology as T

from traps.traps_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class Snoopdhcp(TrapsTest):

    INPUT_PACKET_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
        S.UDP(sport=0x44, dport=0x43) / \
        S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304) / \
        S.DHCP(options=[("message-type", "discover"), "end"])
    INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

    PUNT_PACKET = \
        S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
        U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
               fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_REDIRECT,
               next_header_offset=0,
               source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
               code=0x11,
               source_sp=T.RX_SYS_PORT_GID,
               destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
               source_lp=T.RX_L3_AC_GID,
               destination_lp = sdk.LA_EVENT_L3_LPM_DROP,
               relay_id=T.VRF_GID,
               lpts_flow_type=0) / INPUT_PACKET

    def setUp(self):
        super().setUp()
        sampling_rate = 1.0
        HOST_MAC_ADDR1 = T.mac_addr('cd:cd:cd:cd:cd:cd')
        self.mirror_cmd = T.create_l2_mirror_command(
            self.device,
            0x11,
            self.pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN,
            sampling_rate)

        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER)

    def tearDown(self):
        super().tearDown()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_snoop_no_skip(self):
        self.device.set_snoop_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER, 0, False, False, self.mirror_cmd)

        U.run_and_drop(self, self.device,
                       Snoopdhcp.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        self.device.clear_snoop_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER)

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_snoop_skip_inject_up(self):
        self.device.set_snoop_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER, 0, True, False, self.mirror_cmd)

        U.run_and_drop(self, self.device,
                       Snoopdhcp.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        self.device.clear_snoop_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER)

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_snoop_skip_p2p(self):
        self.device.set_snoop_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER, 0, False, True, self.mirror_cmd)

        U.run_and_drop(self, self.device,
                       Snoopdhcp.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        self.device.clear_snoop_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER)

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_snoop_skip_all(self):
        self.device.set_snoop_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER, 0, True, True, self.mirror_cmd)

        U.run_and_drop(self, self.device,
                       Snoopdhcp.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        self.device.clear_snoop_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER)


if __name__ == '__main__':
    unittest.main()
