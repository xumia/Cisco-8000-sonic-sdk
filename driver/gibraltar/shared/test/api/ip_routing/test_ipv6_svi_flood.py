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

import decor
import unittest
from leaba import sdk
import decor
import ip_test_base
import packet_test_utils as U
import scapy.all as S
import topology as T
from sdk_test_case_base import *
from ip_routing_svi_flood_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_ipv6_svi_flood(ip_routing_svi_flood_base):
    protocol = sdk.la_l3_protocol_e_IPV6_UC
    ip_impl = ip_test_base.ipv6_test_base
    rx_svi_ip = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1211')
    tx_svi_host_ip = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    tx2_svi_ip = T.ipv6_addr('3333:0db8:0a0b:12f0:0000:0000:0000:3333')
    sip = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:2222')
    TTL = 128

    # packets for host case
    input_packet_base = \
        S.Ether(dst=ip_routing_svi_flood_base.rx_svi_mac.addr_str,
                src='be:ef:5d:35:7a:35') / \
        S.IPv6(dst=tx_svi_host_ip.addr_str,
               src=sip.addr_str, hlim=TTL, plen=40) /\
        S.TCP() / Raw(load='0xdeadbeefdeadbeef')

    output_packet_base = \
        S.Ether(dst=ip_routing_svi_flood_base.tx_svi_host_mac.addr_str,
                src=ip_routing_svi_flood_base.tx_svi_mac.addr_str) / \
        S.IPv6(dst=tx_svi_host_ip.addr_str,
               src=sip.addr_str, hlim=TTL - 1, plen=40) /\
        S.TCP() / Raw(load='0xdeadbeefdeadbeef')

    input_packet, output_packet = U.pad_input_and_output_packets(input_packet_base, output_packet_base)

    input_packet_with_vlan_base = \
        S.Ether(dst=ip_routing_svi_flood_base.rx_svi_mac.addr_str,
                src='be:ef:5d:35:7a:35',
                type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=ip_routing_svi_flood_base.rx_vlan1) / \
        S.IPv6(dst=tx_svi_host_ip.addr_str,
               src=sip.addr_str, hlim=TTL, plen=40) /\
        S.TCP() / Raw(load='0xdeadbeefdeadbeef')

    output_packet_with_vlan_base = \
        S.Ether(dst=ip_routing_svi_flood_base.tx_svi_host_mac.addr_str,
                src=ip_routing_svi_flood_base.tx_svi_mac.addr_str,
                type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=ip_routing_svi_flood_base.tx_vlan1) / \
        S.IPv6(dst=tx_svi_host_ip.addr_str,
               src=sip.addr_str, hlim=TTL - 1, plen=40) /\
        S.TCP() / Raw(load='0xdeadbeefdeadbeef')

    input_packet_with_vlan, output_packet_with_vlan = U.pad_input_and_output_packets(
        input_packet_with_vlan_base, output_packet_with_vlan_base)

    # packets for nh case
    input_packet_nh_base = \
        S.Ether(dst=ip_routing_svi_flood_base.rx_svi_mac.addr_str,
                src='be:ef:5d:35:7a:35') / \
        S.IPv6(dst=tx2_svi_ip.addr_str,
               src=sip.addr_str, hlim=TTL, plen=40) /\
        S.TCP() / Raw(load='0xdeadbeefdeadbeef')

    output_packet_base_nh = \
        S.Ether(dst=ip_routing_svi_flood_base.nh_mac.addr_str,
                src=ip_routing_svi_flood_base.tx2_svi_mac.addr_str) / \
        S.IPv6(dst=tx2_svi_ip.addr_str,
               src=sip.addr_str, hlim=TTL - 1, plen=40) /\
        S.TCP() / Raw(load='0xdeadbeefdeadbeef')

    input_packet_nh, output_packet_nh = U.pad_input_and_output_packets(input_packet_nh_base, output_packet_base_nh)

    input_packet_with_vlan_base_nh = \
        S.Ether(dst=ip_routing_svi_flood_base.rx_svi_mac.addr_str,
                src='be:ef:5d:35:7a:35',
                type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=ip_routing_svi_flood_base.rx_vlan1) /\
        S.IPv6(dst=tx2_svi_ip.addr_str,
               src=sip.addr_str, hlim=TTL, plen=40) /\
        S.TCP() / Raw(load='0xdeadbeefdeadbeef')

    output_packet_with_vlan_base_nh = \
        S.Ether(dst=ip_routing_svi_flood_base.nh_mac.addr_str,
                src=ip_routing_svi_flood_base.tx2_svi_mac.addr_str,
                type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=ip_routing_svi_flood_base.tx2_vlan1) / \
        S.IPv6(dst=tx2_svi_ip.addr_str,
               src=sip.addr_str, hlim=TTL - 1, plen=40) /\
        S.TCP() / Raw(load='0xdeadbeefdeadbeef')

    input_packet_with_vlan_nh, output_packet_with_vlan_nh = U.pad_input_and_output_packets(
        input_packet_with_vlan_base_nh, output_packet_with_vlan_base_nh)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_rcy_port_flood(self):
        self.create_inject_up_on_rcy_port()
        self.do_test_svi_flood()


if __name__ == '__main__':
    unittest.main()
