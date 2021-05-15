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
import packet_test_defs as P
import sim_utils
import topology as T
import nplapicli as nplapi
import decor

from traps.traps_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class PTPOverEth(TrapsTest):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ptp_over_eth(self):
        '''PTP over eth, should always be punted to CPU.

        '''
        INPUT_PACKET = \
            S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str) / \
            P.PTPv2() / ("a" * 100)

        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_PTP_OVER_ETH, 0, None, self.punt_dest, False, False, True, 0)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING)
        self.install_an_entry_in_copc_mac_table(PTP_ETHER_TYPE, 0xffff, T.mac_addr(
            DONT_CARE_MAC), sdk.LA_EVENT_ETHERNET_PTP_OVER_ETH, T.mac_addr(DONT_CARE_MAC))

        PUNT_PACKET = S.Ether(dst=HOST_MAC_ADDR,
                              src=PUNT_INJECT_PORT_MAC_ADDR,
                              type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                      id=0,
                                                                      vlan=PUNT_VLAN,
                                                                      type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                            fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                            next_header_offset=0,
                                                                                                            source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                                                                                                            code=sdk.LA_EVENT_ETHERNET_PTP_OVER_ETH,
                                                                                                            source_sp=T.RX_SYS_PORT_GID,
                                                                                                            destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                            source_lp=0,
                                                                                                            # destination_lp=sdk.la_packet_types.LA_L2_LOGICAL_PORT_GID_INVALID,
                                                                                                            destination_lp=sdk.LA_EVENT_ETHERNET_PTP_OVER_ETH,
                                                                                                            relay_id=0,
                                                                                                            lpts_flow_type=0) / INPUT_PACKET

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # Teardown
        self.clear_entries_from_copc_mac_table()
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP)


if __name__ == '__main__':
    unittest.main()
