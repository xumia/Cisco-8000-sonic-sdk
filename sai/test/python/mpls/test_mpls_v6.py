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

import pytest
import random
import saicli as S
from scapy.all import *
from sai_packet_test_defs import *
import sai_packet_utils as U


@pytest.mark.usefixtures("mpls_v6_topology")
class Test_mpls_v6():

    def test_topology_config(self):
        pytest.top.deconfigure_mpls_topology()
        pytest.top.configure_mpls_topology()
        pytest.top.deconfigure_mpls_topology()
        pytest.top.configure_mpls_topology()

    # inseg_entry with next hop = next_hop_group with two entries:
    #                             next_hop MPLS, and next_hop IP
    def test_inseg_to_next_hop_group(self):

        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            MPLS(label=pytest.top.mpls_in_next_hop, ttl=64) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.route3_ip, hlim=64) / \
            UDP(sport=64, dport=2048)

        in_pkt2 = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            MPLS(label=pytest.top.mpls_in_next_hop2, ttl=64) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.route3_ip, hlim=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.route3_ip, hlim=63) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt2 = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            MPLS(label=pytest.top.mpls_out_label, ttl=63) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.route3_ip, hlim=64) / \
            UDP(sport=64, dport=2048)

        # Sending two different packets, to explore both ECMP paths
        # Found out by trial and error two labels mapped to two different paths
        U.run_and_compare_set(
            self, in_pkt, pytest.top.in_port, {
                pytest.top.out_port: expected_out_pkt, pytest.top.in_port: expected_out_pkt2})

        U.run_and_compare_set(
            self, in_pkt2, pytest.top.in_port, {
                pytest.top.out_port: expected_out_pkt, pytest.top.in_port: expected_out_pkt2})

    # route with next hop = next_hop_group with two entries:
    #                       next_hop MPLS, and next_hop IP
    def test_route_to_next_hop_group(self):
        for i in range(5):
            # random port, so we will explore both ECMP paths
            udp_port = random.randint(1000, 2000)

            in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
                IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.route3_ip, hlim=64) / \
                UDP(sport=64, dport=udp_port)

            expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
                IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.route3_ip, hlim=63) / \
                UDP(sport=64, dport=udp_port)

            expected_out_pkt2 = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
                MPLS(label=pytest.top.mpls_out_label, ttl=63) / \
                IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.route3_ip, hlim=63) / \
                UDP(sport=64, dport=udp_port)

            U.run_and_compare_set(
                self, in_pkt, pytest.top.in_port, {
                    pytest.top.out_port: expected_out_pkt, pytest.top.in_port: expected_out_pkt2})

    # route with next hop = next_hop type MPLS
    def test_push(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.route4_ip, hlim=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            MPLS(label=pytest.top.mpls_out_label, ttl=63) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.route4_ip, hlim=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.in_port)

    def test_pop(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            MPLS(label=pytest.top.mpls_in_label_pop, ttl=64) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

    def test_php(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            MPLS(label=pytest.top.mpls_in_label_php, ttl=64) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)
