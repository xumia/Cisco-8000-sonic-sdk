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
import ip_test_base
import packet_test_utils as U
import scapy.all as S
import sim_utils
import topology as T
from ip_routing_counters_base import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ipv4_svi_counters_ip_routing_counters(ip_routing_counters_base):
    l3_port_impl_class = T.ip_svi_base
    ip_impl_class = ip_test_base.ipv4_test_base
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')

    INPUT_PACKET_BASE = \
        S.Ether(dst=T.RX_SVI_MAC.addr_str, src=ip_routing_counters_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_counters_base.TTL) / \
        S.Raw(load=0xdeadbeefdeadbeefdeadbeefdeadbeef)

    EXPECTED_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_counters_base.TTL - 1) / \
        S.Raw(load=0xdeadbeefdeadbeefdeadbeefdeadbeef)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = U.pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)

    def test_counter_route_single_nh(self):
        self._test_counter_route_single_nh()


if __name__ == '__main__':
    unittest.main()
