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
from saicli import *
import pdb


@pytest.mark.usefixtures("dot1q_bridge_v4_lag_topology")
@pytest.mark.skipif(st_utils.is_sai_15x(), reason="Disabled on SAI 1.5.x")
class Test_dot1q_bridge_lag():
    def test_ucast_pkt_forward(self):
        in_pkt = Ether(dst=pytest.top.neighbor_mac2, src="00:ef:00:ef:00:ef") / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare_set(self, in_pkt, pytest.top.in_port, {pytest.top.out_port: in_pkt, pytest.top.rt_port: in_pkt})

        in_stats = pytest.tb.get_port_stats(pytest.tb.ports[pytest.top.in_port])
        pytest.tb.dump_port_stats(in_stats)
        in_stats = pytest.tb.get_port_stats(pytest.tb.ports[pytest.top.sw_port])
        pytest.tb.dump_port_stats(in_stats)
        out_stats = pytest.tb.get_port_stats(pytest.tb.ports[pytest.top.out_port])
        pytest.tb.dump_port_stats(out_stats)
        out_stats = pytest.tb.get_port_stats(pytest.tb.ports[pytest.top.rt_port])
        pytest.tb.dump_port_stats(out_stats)

    def test_lag_member_remove_add(self):
        pytest.tb.remove_lag_member(pytest.top.lag_member_id3)
        pytest.tb.remove_lag_member(pytest.top.lag_member_id4)

        pytest.top.lag_member_id3 = pytest.tb.create_lag_member(pytest.top.lag_id2, pytest.top.out_port)
        pytest.top.lag_member_id4 = pytest.tb.create_lag_member(pytest.top.lag_id2, pytest.top.rt_port)

        in_pkt = Ether(dst="00:cd:ab:cd:ab:cd", src="00:ef:00:ef:00:ef") / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare_set(self, in_pkt, pytest.top.in_port, {pytest.top.out_port: in_pkt, pytest.top.rt_port: in_pkt})

    def test_bridge_port_before_lag_member(self):
        pytest.top.deconfigure_bridge_ports()

        pytest.tb.remove_lag_member(pytest.top.lag_member_id3)
        pytest.tb.remove_lag_member(pytest.top.lag_member_id4)

        pytest.top.configure_bridge_ports(pytest.top.vlan, pytest.top.lag_id1, pytest.top.lag_id2, True)

        pytest.top.lag_member_id3 = pytest.tb.create_lag_member(pytest.top.lag_id2, pytest.top.out_port)
        pytest.top.lag_member_id4 = pytest.tb.create_lag_member(pytest.top.lag_id2, pytest.top.rt_port)

        in_pkt = Ether(dst="00:cd:ab:cd:ab:cd", src="00:ef:00:ef:00:ef") / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare_set(self, in_pkt, pytest.top.in_port, {pytest.top.out_port: in_pkt, pytest.top.rt_port: in_pkt})

    def test_ucast_inject_up(self):
        in_pkt = Ether(dst=pytest.top.neighbor_mac2, src="00:ef:00:ef:00:ef") / \
            Dot1Q(vlan=pytest.top.vlan) /\
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src="00:ef:00:ef:00:ef") / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        U.inject_up_test(self, in_pkt, expected_out_pkt)
        expected_out_pkt = in_pkt

    def test_unknown_pkt_forward(self):
        in_pkt = Ether(dst="00:cd:ab:cd:ab:cd", src="00:ef:00:ef:00:ef") / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        pre_in_stats = pytest.tb.get_ingress_bridge_port_stats(pytest.tb.bridge_ports[pytest.top.lag_id1])
        pre_out_stats = pytest.tb.get_egress_bridge_port_stats(pytest.tb.bridge_ports[pytest.top.lag_id2])

        U.run_and_compare_set(self, in_pkt, pytest.top.in_port, {pytest.top.out_port: in_pkt, pytest.top.rt_port: in_pkt})

        in_stats = pytest.tb.get_ingress_bridge_port_stats(pytest.tb.bridge_ports[pytest.top.lag_id1])
        #assert in_stats[0] == pre_in_stats[0] + 1

        out_stats = pytest.tb.get_egress_bridge_port_stats(pytest.tb.bridge_ports[pytest.top.lag_id2])
        #assert out_stats[0] == pre_out_stats[0] + 1
        #assert in_stats[1] - pre_in_stats[1] == out_stats[1] - pre_out_stats[1]
        in_stats = pytest.tb.get_port_stats(pytest.tb.ports[pytest.top.in_port])
        pytest.tb.dump_port_stats(in_stats)
        in_stats = pytest.tb.get_port_stats(pytest.tb.ports[pytest.top.sw_port])
        pytest.tb.dump_port_stats(in_stats)
        out_stats = pytest.tb.get_port_stats(pytest.tb.ports[pytest.top.out_port])
        pytest.tb.dump_port_stats(out_stats)
        out_stats = pytest.tb.get_port_stats(pytest.tb.ports[pytest.top.rt_port])
        pytest.tb.dump_port_stats(out_stats)

    def test_unknown_inject_up(self):
        in_pkt = Ether(dst="ab:cd:ab:cd:ab:cd", src="00:ef:00:ef:00:ef") / \
            Dot1Q(vlan=pytest.top.vlan) /\
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst="ab:cd:ab:cd:ab:cd", src="00:ef:00:ef:00:ef") / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        U.inject_up_test(self, in_pkt, expected_out_pkt)
        expected_out_pkt = in_pkt

    def test_inject_down(self):
        in_pkt = Ether(dst="ab:cd:ab:cd:ab:cd", src="00:ef:00:ef:00:ef") / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        U.inject_down_test(self, in_pkt, queue_index=0)

    def test_lag_label(self):
        label = pytest.tb.get_lag_label(pytest.top.lag_id1)
        assert label == "Label1"
        pytest.tb.set_lag_label(pytest.top.lag_id1, "lag_label1")
        label = pytest.tb.get_lag_label(pytest.top.lag_id1)
        assert label == "lag_label1"
