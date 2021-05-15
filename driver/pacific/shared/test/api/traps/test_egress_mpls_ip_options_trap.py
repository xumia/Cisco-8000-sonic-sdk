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
from scapy.all import *
import sim_utils
import topology as T

from traps_base import *

load_contrib('mpls')


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class egress_mpls_ip_options_trap(TrapsTest):
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

    INPUT_PACKET, EXPECTED_OUTPUT_PUNTED_PACKET = U.pad_input_and_output_packets(
        INPUT_PACKET_BASE, EXPECTED_OUTPUT_PUNTED_PACKET_BASE)

    def setUp(self):
        super().setUp()

        self.device.set_trap_configuration(sdk.LA_EVENT_IPV4_OPTIONS_EXIST, 0, None, self.punt_dest, False, False, True, 0)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_mpls_ip_options_trap(self):
        """
        1. Receive one mpls packet with 1 label and IP Option. forward it with pop operation, and catch egress trap
        """
        l3_port_impl = T.ip_l3_ac_base(self.topology)
        nh = l3_port_impl.reg_nh.hld_obj

        nhlfe = self.device.create_mpls_php_nhlfe(nh)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PUNTED_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)


if __name__ == '__main__':
    unittest.main()
