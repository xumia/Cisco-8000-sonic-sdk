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
from scapy.all import *
import sim_utils
import topology as T
import packet_test_utils as U
from ecn_voq_set_base import *
import decor
import ip_test_base

load_contrib('mpls')


@unittest.skipUnless(decor.is_gibraltar(), "ECN VoQ tests supported only on GB")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class test_ecn_voq_set(ecn_voq_set_base):
    protocol = sdk.la_l3_protocol_e_IPV4_UC
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl = ip_test_base.ipv4_test_base

    SA = T.mac_addr('be:ef:5d:35:7a:35')
    SIP = T.ipv4_addr('12.10.12.10')
    IP_TTL = 0x90
    IN_TOS = sdk.la_ip_tos()
    IN_TOS.fields.ecn = 0x3

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=SIP.addr_str, dst=ecn_voq_set_base.DIP.addr_str, ttl=IP_TTL, tos=IN_TOS.flat)

    EXPECTED_OUTPUT_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        IP(src=SIP.addr_str, dst=ecn_voq_set_base.DIP.addr_str, ttl=IP_TTL - 1, tos=IN_TOS.flat)

    INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

    @unittest.skipUnless(decor.is_gibraltar(), "ECN VoQ tests supported only on GB")
    def test_ecn_voq(self):
        self._test_ecn_voq()


if __name__ == '__main__':
    unittest.main()
