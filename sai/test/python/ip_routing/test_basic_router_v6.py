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
import saicli as S
import sai_packet_utils as U
import sai_test_base as st_base
from scapy.all import *
import basic_router_common
import sai_test_utils as st_utils
import sai_topology as topology
from sai_test_utils import *


@pytest.mark.usefixtures("basic_route_v6_topology")
class Test_basic_route_v6(basic_router_common.test_basic_route):

    def test_topology_config(self):
        pytest.top.deconfigure_basic_route_topology()
        pytest.top.configure_basic_route_topology()
        pytest.top.deconfigure_basic_route_topology()
        pytest.top.configure_basic_route_topology()

    def test_ndp_punt(self):
        dst_mac = "33:33:ff:48:00:00"
        dst_ip = "ff02::1:ff48:0"
        in_pkt = Ether(dst=dst_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src="::", dst=dst_ip, hlim=64) / \
            ICMPv6ND_NS()

        ndp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY, S.SAI_PACKET_ACTION_TRAP, 255)
        U.punt_test(self, in_pkt, pytest.top.in_port)
        pytest.tb.remove_trap(ndp_trap)

    # neighbor1 -> host
    def test_ipv6_punt(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.local_ip1, hlim=64) / \
            UDP(sport=64, dport=2048)

        ip2me_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_IP2ME, S.SAI_PACKET_ACTION_TRAP)
        U.punt_test(self, in_pkt, pytest.top.in_port)
        pytest.tb.remove_trap(ip2me_trap)

    # host -> neighbor_ip2
    def test_inject_up(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=63) / \
            UDP(sport=64, dport=2048)

        U.inject_up_test(self, in_pkt, expected_out_pkt)

    # host -> neighbor_ip2
    def test_inject_down(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=64) / \
            UDP(sport=64, dport=2048)

        U.inject_down_test(self, in_pkt)

    # neighbor1 -> neighbor2
    def test_route(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=64) / \
            UDP(sport=64, dport=2048) / ("\0" * 100)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=63) / \
            UDP(sport=64, dport=2048) / ("\0" * 100)

        rif_1_before = pytest.tb.get_router_interface_stats(pytest.tb.rif_id_1)
        rif_2_before = pytest.tb.get_router_interface_stats(pytest.tb.rif_id_2)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        rif_1_after = pytest.tb.get_router_interface_stats(pytest.tb.rif_id_1)
        rif_2_after = pytest.tb.get_router_interface_stats(pytest.tb.rif_id_2)

        # verify counter values
        rif_1_before[SAI_ROUTER_INTERFACE_STAT_IN_OCTETS] += len(in_pkt) + 4  # + 4 because of FCS
        rif_2_before[SAI_ROUTER_INTERFACE_STAT_OUT_OCTETS] += len(expected_out_pkt) + 4
        rif_1_before[SAI_ROUTER_INTERFACE_STAT_IN_PACKETS] += 1
        rif_2_before[SAI_ROUTER_INTERFACE_STAT_OUT_PACKETS] += 1
        rif_1_before[SAI_ROUTER_INTERFACE_STAT_IPV6_IN_OCTETS] += len(in_pkt) + 4
        rif_2_before[SAI_ROUTER_INTERFACE_STAT_IPV6_OUT_OCTETS] += len(expected_out_pkt) + 4
        rif_1_before[SAI_ROUTER_INTERFACE_STAT_IPV6_IN_PACKETS] += 1
        rif_2_before[SAI_ROUTER_INTERFACE_STAT_IPV6_OUT_PACKETS] += 1

        assert rif_1_before == rif_1_after
        assert rif_2_before == rif_2_after

    def test_admin_attr(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=63) / \
            UDP(sport=64, dport=2048)

        self.common_test_admin_attr(in_pkt, expected_out_pkt, "v6")

    # neighbor2 -> neighbor_ll
    def test_link_local(self):
        if pytest.top.ip_type == "v6":
            in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
                IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.v6_inj_ll_ip, hlim=64) / \
                UDP(sport=64, dport=2048)

            expected_out_pkt = Ether(dst=pytest.top.v6_link_local_mac, src=pytest.tb.router_mac) / \
                IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.v6_inj_ll_ip, hlim=63) / \
                UDP(sport=64, dport=2048)

            U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

    def test_remove_and_readd(self):
        pytest.tb.remove_next_hop(pytest.tb.nh_id1)
        pytest.tb.remove_neighbor(pytest.tb.rif_id_1, pytest.top.neighbor_ip1)
        pytest.tb.remove_next_hop(pytest.tb.nh_id2)
        pytest.tb.remove_neighbor(pytest.tb.rif_id_2, pytest.top.neighbor_ip2)
        pytest.tb.create_neighbor(pytest.tb.rif_id_1, pytest.top.neighbor_ip1, pytest.top.neighbor_mac1)
        pytest.tb.create_next_hop(pytest.top.neighbor_ip1, pytest.tb.rif_id_1)
        pytest.tb.create_neighbor(pytest.tb.rif_id_2, pytest.top.neighbor_ip2, pytest.top.neighbor_mac2)
        pytest.tb.create_next_hop(pytest.top.neighbor_ip2, pytest.tb.rif_id_2)

    def test_route_neighbor_mac_change(self):
        mac1 = "00:12:12:34:34:aa"
        mac2 = "00:12:12:34:34:bb"
        mac3 = "00:12:12:34:34:cc"

        in_pkt1 = Ether(dst=pytest.tb.router_mac, src=mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=64) / \
            UDP(sport=64, dport=2048)

        in_pkt2 = Ether(dst=pytest.tb.router_mac, src=mac2) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=64) / \
            UDP(sport=64, dport=2048)

        in_pkt3 = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=63) / \
            UDP(sport=64, dport=2048)

        self.common_test_route_neighbor_mac_change(in_pkt1, in_pkt2, in_pkt3, expected_out_pkt, mac1, mac2, mac3)

    @pytest.mark.skipif(st_utils.is_sai_15x(), reason="Disabled on SAI 1.5.x")
    def test_decrement_ttl(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=64) / \
            UDP(sport=64, dport=2048)

        # test: default decrement TTL should be on
        decrement = pytest.tb.get_object_attr(pytest.tb.ports[pytest.top.out_port], SAI_PORT_ATTR_DISABLE_DECREMENT_TTL)
        assert(decrement is False)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # test: no decrement TTL
        pytest.tb.disable_decrement_ttl(pytest.top.out_port)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=64) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # test: decrement TTL
        pytest.tb.enable_decrement_ttl(pytest.top.out_port)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # test: no decrement TTL=1
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=1) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=1) / \
            UDP(sport=64, dport=2048)

        pytest.tb.disable_decrement_ttl(pytest.top.out_port)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # decrement TTL for other test cases after
        pytest.tb.enable_decrement_ttl(pytest.top.out_port)
