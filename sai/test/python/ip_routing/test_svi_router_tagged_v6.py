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

import basic_router_common
import pytest
import saicli as S
import sai_packet_utils as U
import sai_test_utils as st_utils
from scapy.all import *


@pytest.mark.usefixtures("svi_route_tag_v6_topology")
class Test_svi_route_v6(basic_router_common.test_basic_route):

    def test_topology_config(self):
        pytest.top.deconfigure_svi_route_topology()
        pytest.top.configure_svi_route_topology(tag=True)
        pytest.top.deconfigure_svi_route_topology()
        pytest.top.configure_svi_route_topology(tag=True)

    # broadcast arp in from bridge port
    def test_ndp_punt(self):
        dst_mac = "33:33:ff:48:00:00"
        dst_ip = "ff02::1:ff48:0"
        in_pkt = Ether(dst=dst_mac, src=pytest.top.svi_mac2) / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / \
            IPv6(src="::", dst=dst_ip, hlim=64) / \
            ICMPv6ND_NS()

        out_pkt = Ether(dst=dst_mac, src=pytest.top.svi_mac2, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / \
            IPv6(src="::", dst=dst_ip, hlim=64) / \
            ICMPv6ND_NS()

        ndp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY, S.SAI_PACKET_ACTION_TRAP, 255)
        U.punt_test(self, in_pkt, pytest.top.sw_port, out_pkt)
        pytest.tb.remove_trap(ndp_trap)

    # neighbor1 -> host
    def test_ipv6_punt(self):
        in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / \
            IPv6(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.local_ip1, hlim=64) / \
            UDP(sport=64, dport=2048)

        out_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / \
            IPv6(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.local_ip1, hlim=64) / \
            UDP(sport=64, dport=2048)

        ip2me_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_IP2ME, S.SAI_PACKET_ACTION_TRAP)
        U.punt_test(self, in_pkt, pytest.top.sw_port, out_pkt)
        pytest.tb.remove_trap(ip2me_trap)

    # host -> neighbor_ip2
    def test_inject_up(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_dst_neighbor_ip, hlim=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_dst_neighbor_ip, hlim=63) / \
            UDP(sport=64, dport=2048)

        U.inject_up_test(self, in_pkt, expected_out_pkt)

    # host -> svi_dst_neighbor
    def test_inject_down(self):
        in_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_dst_neighbor_ip, hlim=63) / \
            UDP(sport=64, dport=2048)

        U.inject_down_test(self, in_pkt)

    # neighbor1 -> svi_neighbor
    def test_rp_to_svi(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_dst_neighbor_ip, hlim=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            Dot1Q(vlan=pytest.top.vlan) /\
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_dst_neighbor_ip, hlim=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

    # svi_neighbor -> neighbor1
    def test_svi_to_rp(self):
        in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            Dot1Q(vlan=pytest.top.vlan) /\
            IPv6(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.neighbor_ip1, hlim=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.neighbor_ip1, hlim=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.out_port, expected_out_pkt, pytest.top.in_port)

    # neighbor1 -> svi_route2_ip
    def test_rp_to_svi_nh(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, hlim=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            Dot1Q(vlan=pytest.top.vlan) /\
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, hlim=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

    # svi_neighbor -> route_ip3
    def test_svi_to_rp_nh(self):
        in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            Dot1Q(vlan=pytest.top.vlan) /\
            IPv6(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route_ip3, hlim=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route_ip3, hlim=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.out_port, expected_out_pkt, pytest.top.in_port)
