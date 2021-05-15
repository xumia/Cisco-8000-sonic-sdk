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
class TrapsUnsupportedProtocol(TrapsTest):

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
