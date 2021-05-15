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

from traps_base import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class TrapsTTLTest(TrapsTest):

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


if __name__ == '__main__':
    unittest.main()
