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

import unittest
import ip_test_base
import packet_test_utils as U
import scapy.all as S
import topology as T
from ip_tunnel_transit_counter_base import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ipv4_known_unicast_routing_pkt_count(ip_tunnel_transit_counter_base):
    l3_port_impl_class = T.ip_svi_base
    ip_impl_class = ip_test_base.ipv4_test_base
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    SIP_INNER = T.ipv4_addr('102.10.12.10')
    DIP_INNER = T.ipv4_addr('202.81.95.250')

    INPUT_PACKET_BASE_GUE = \
        S.Ether(dst=T.RX_SVI_MAC.addr_str, src=ip_tunnel_transit_counter_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_tunnel_transit_counter_base.TTL) / \
        S.UDP(sport=0x17cf, dport=0x17c0) / \
        S.IP(src=SIP_INNER.addr_str, dst=DIP_INNER.addr_str, ttl=ip_tunnel_transit_counter_base.TTL)

    EXPECTED_OUTPUT_PACKET_BASE_GUE = \
        S.Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_tunnel_transit_counter_base.TTL - 1) / \
        S.UDP(sport=0x17cf, dport=0x17c0) / \
        S.IP(src=SIP_INNER.addr_str, dst=DIP_INNER.addr_str, ttl=ip_tunnel_transit_counter_base.TTL)

    INPUT_PACKET_BASE_GRE = \
        S.Ether(dst=T.RX_SVI_MAC.addr_str, src=ip_tunnel_transit_counter_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_tunnel_transit_counter_base.TTL) / \
        S.GRE() / \
        S.IP(src=SIP_INNER.addr_str, dst=DIP_INNER.addr_str, ttl=ip_tunnel_transit_counter_base.TTL)

    EXPECTED_OUTPUT_PACKET_BASE_GRE = \
        S.Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_tunnel_transit_counter_base.TTL - 1) / \
        S.GRE() / \
        S.IP(src=SIP_INNER.addr_str, dst=DIP_INNER.addr_str, ttl=ip_tunnel_transit_counter_base.TTL)

    INPUT_PACKET_BASE_IP_IN_IP = \
        S.Ether(dst=T.RX_SVI_MAC.addr_str, src=ip_tunnel_transit_counter_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_tunnel_transit_counter_base.TTL) / \
        S.IP(src=SIP_INNER.addr_str, dst=DIP_INNER.addr_str, ttl=ip_tunnel_transit_counter_base.TTL)

    EXPECTED_OUTPUT_PACKET_BASE_IP_IN_IP = \
        S.Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_tunnel_transit_counter_base.TTL - 1) / \
        S.IP(src=SIP_INNER.addr_str, dst=DIP_INNER.addr_str, ttl=ip_tunnel_transit_counter_base.TTL)

    INPUT_PACKET_GUE, EXPECTED_OUTPUT_PACKET_GUE = U.pad_input_and_output_packets(
        INPUT_PACKET_BASE_GUE, EXPECTED_OUTPUT_PACKET_BASE_GUE)
    INPUT_PACKET_GRE, EXPECTED_OUTPUT_PACKET_GRE = U.pad_input_and_output_packets(
        INPUT_PACKET_BASE_GRE, EXPECTED_OUTPUT_PACKET_BASE_GRE)
    INPUT_PACKET_IP_IN_IP, EXPECTED_OUTPUT_PACKET_IP_IN_IP = U.pad_input_and_output_packets(
        INPUT_PACKET_BASE_IP_IN_IP, EXPECTED_OUTPUT_PACKET_BASE_IP_IN_IP)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_transit_counter_gue_pkt(self):
        self._test_transit_counter_gue_pkt()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_transit_counter_gre_pkt(self):
        self._test_transit_counter_gre_pkt()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_transit_counter_ip_over_ip_pkt(self):
        self._test_transit_counter_ip_over_ip_pkt()


if __name__ == '__main__':
    unittest.main()
