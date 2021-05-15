#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import sai_packet_utils as U
import sai_test_utils as st_utils
from scapy.all import *


@pytest.mark.usefixtures("dot1q_bridge_v4_topology")
class Test_dot1q_bridge():
    def test_ucast_pkt_forward(self):
        in_pkt = Ether(dst=pytest.top.neighbor_mac2, src="00:ef:00:ef:00:ef") / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        pre_in_stats = pytest.tb.get_ingress_bridge_port_stats(pytest.tb.bridge_ports[pytest.top.in_port])
        pre_out_stats = pytest.tb.get_egress_bridge_port_stats(pytest.tb.bridge_ports[pytest.top.out_port])

        U.run_and_compare(self, in_pkt, pytest.top.in_port, in_pkt, pytest.top.out_port)

        in_stats = pytest.tb.get_ingress_bridge_port_stats(pytest.tb.bridge_ports[pytest.top.in_port])
        #assert in_stats[0] == pre_in_stats[0] + 1

        out_stats = pytest.tb.get_egress_bridge_port_stats(pytest.tb.bridge_ports[pytest.top.out_port])
        #assert out_stats[0] == pre_out_stats[0] + 1
        #assert in_stats[1] - pre_in_stats[1] == out_stats[1] - pre_out_stats[1]
        in_stats = pytest.tb.get_port_stats(pytest.tb.ports[pytest.top.in_port])
        pytest.tb.dump_port_stats(in_stats)
        out_stats = pytest.tb.get_port_stats(pytest.tb.ports[pytest.top.out_port])
        pytest.tb.dump_port_stats(out_stats)

    def test_ucast_inject_up(self):
        in_pkt = Ether(dst=pytest.top.neighbor_mac2, src="00:ef:00:ef:00:ef") / \
            Dot1Q(vlan=pytest.top.vlan) /\
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src="00:ef:00:ef:00:ef") / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        U.inject_up_test(self, in_pkt, expected_out_pkt)
        expected_out_pkt = in_pkt

    def test_unknown_pkt_forward(self):
        in_pkt = Ether(dst="00:cd:ab:cd:ab:cd", src="00:ef:00:ef:00:ef") / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        pre_in_stats = pytest.tb.get_ingress_bridge_port_stats(pytest.tb.bridge_ports[pytest.top.in_port])
        pre_out_stats = pytest.tb.get_egress_bridge_port_stats(pytest.tb.bridge_ports[pytest.top.out_port])

        U.run_and_compare(self, in_pkt, pytest.top.in_port, in_pkt, pytest.top.out_port)

        in_stats = pytest.tb.get_ingress_bridge_port_stats(pytest.tb.bridge_ports[pytest.top.in_port])
        #assert in_stats[0] == pre_in_stats[0] + 1

        out_stats = pytest.tb.get_egress_bridge_port_stats(pytest.tb.bridge_ports[pytest.top.out_port])
        #assert out_stats[0] == pre_out_stats[0] + 1
        #assert in_stats[1] - pre_in_stats[1] == out_stats[1] - pre_out_stats[1]
        in_stats = pytest.tb.get_port_stats(pytest.tb.ports[pytest.top.in_port])
        pytest.tb.dump_port_stats(in_stats)
        out_stats = pytest.tb.get_port_stats(pytest.tb.ports[pytest.top.out_port])
        pytest.tb.dump_port_stats(out_stats)

    def test_unknown_inject_up(self):
        in_pkt = Ether(dst="ab:cd:ab:cd:ab:cd", src="00:ef:00:ef:00:ef") / \
            Dot1Q(vlan=pytest.top.vlan) /\
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst="ab:cd:ab:cd:ab:cd", src="00:ef:00:ef:00:ef") / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        U.inject_up_test(self, in_pkt, expected_out_pkt)
        expected_out_pkt = in_pkt

    @pytest.mark.skipif(st_utils.is_sai_17x_or_higher(), reason="Test for SAI 1.5.x only")
    def test_inject_down_15x(self):
        in_pkt = Ether(dst="ab:cd:ab:cd:ab:cd", src="00:ef:00:ef:00:ef") / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        U.inject_down_test(self, in_pkt, queue_index=0)

    @pytest.mark.skipif(st_utils.is_sai_15x(), reason="Disabled on SAI 1.5.x")
    def test_inject_down(self):
        in_pkt = Ether(dst="ab:cd:ab:cd:ab:cd", src="00:ef:00:ef:00:ef") / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        U.inject_down_test(self, in_pkt, queue_index=3)
