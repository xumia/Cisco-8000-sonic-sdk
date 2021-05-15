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
import sai_packet_utils as U
import sai_test_base as st_base
from scapy.all import *
import basic_router_common
import sai_test_utils as st_utils
import sai_topology as topology


@pytest.mark.usefixtures("next_hop_group_v6_topology")
class Test_next_hop_group_v6(basic_router_common.test_basic_route):
    def test_topology_config(self):
        pytest.top.deconfigure_next_hop_group_base_topology()
        pytest.top.configure_next_hop_group_base_topology()
        pytest.top.deconfigure_next_hop_group_base_topology()
        pytest.top.configure_next_hop_group_base_topology()

    # neighbor1 -> svi_route2_ip
    def test_rp_to_svi_nh(self):
        # combine one router port and one svi port for a next hop group
        nh_group = pytest.tb.create_next_hop_group()
        nh_mem1 = pytest.tb.create_next_hop_group_member(nh_group, pytest.tb.nh_id2)
        nh_mem2 = pytest.tb.create_next_hop_group_member(nh_group, pytest.tb.svi_nh)
        self.check_next_hop_group_member_list(nh_group, [pytest.tb.nh_id2, pytest.tb.svi_nh])

        # route through nh
        pytest.tb.create_route(
            pytest.tb.virtual_router_id,
            pytest.top.route_prefix3,
            pytest.top.route_prefix3_mask,
            pytest.tb.nh_id1)
        pytest.tb.create_route(
            pytest.tb.virtual_router_id,
            pytest.top.svi_route2_prefix,
            pytest.top.svi_route2_mask,
            nh_group)

        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, hlim=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt1 = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, hlim=63) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt2 = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, hlim=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare_set(
            self, in_pkt, pytest.top.in_port, {
                pytest.top.out_port: expected_out_pkt1, pytest.top.rt_port: expected_out_pkt2})

        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.route_prefix3, pytest.top.route_prefix3_mask)
        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.svi_route2_prefix, pytest.top.svi_route2_mask)
        pytest.tb.remove_next_hop_group_member(nh_mem1)
        pytest.tb.remove_next_hop_group_member(nh_mem2)
        pytest.tb.remove_next_hop_group(nh_group)

    # svi_neighbor -> route_ip3
    def test_svi_to_rp_nh(self):
        # combine two router ports for nexthop group
        nh_group = pytest.tb.create_next_hop_group()
        nh_mem1 = pytest.tb.create_next_hop_group_member(nh_group, pytest.tb.nh_id1)
        nh_mem2 = pytest.tb.create_next_hop_group_member(nh_group, pytest.tb.nh_id2)

        # route through nh
        pytest.tb.create_route(
            pytest.tb.virtual_router_id,
            pytest.top.route_prefix3,
            pytest.top.route_prefix3_mask,
            nh_group)
        pytest.tb.create_route(
            pytest.tb.virtual_router_id,
            pytest.top.svi_route2_prefix,
            pytest.top.svi_route2_mask,
            pytest.tb.svi_nh)

        in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            IPv6(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route_ip3, hlim=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt1 = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route_ip3, hlim=63) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt2 = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route_ip3, hlim=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare_set(
            self, in_pkt, pytest.top.out_port, {
                pytest.top.in_port: expected_out_pkt1, pytest.top.rt_port: expected_out_pkt2})
        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.route_prefix3, pytest.top.route_prefix3_mask)
        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.svi_route2_prefix, pytest.top.svi_route2_mask)
        pytest.tb.remove_next_hop_group_member(nh_mem1)
        pytest.tb.remove_next_hop_group_member(nh_mem2)
        pytest.tb.remove_next_hop_group(nh_group)

    def test_distribute_nh_in_group(self):
        tolerance = 0.08    # tolerance of distribution comparison
        ip_i_range = 10    # index of paacket generation loops, i and j, where i * j is the total flows of traffic
        ip_j_range = 10

        total_packets = ip_j_range * ip_i_range
        ip_addr_perfix = "1133:db8:"    # ip_addr_perfix = "1133:db8:a00::" and prefix_mask = "ffff:ffff:ff00::"
        # function to increment the ip address (creation of different flows)

        def ip_inc(i, j):
            # Note: Hashing entropy issue. In IPv6, only increment of lower 8 bits seem to result in same key.
            #       And, all 256 go to same next hop member. Therefore, << 8
            return "{0}{1}::{2}".format(ip_addr_perfix, format(10 * 256 + 1 + i, 'x'), format(j * 256, 'x'))

        # next hop exit ports within single next hop group
        nh_ports = [pytest.top.in_port, pytest.top.rt_port, pytest.top.rt_port1]
        test_weights = [{pytest.top.in_port: 3, pytest.top.rt_port: 1, pytest.top.rt_port1: 4},
                        {pytest.top.in_port: 2, pytest.top.rt_port: 3, pytest.top.rt_port1: 1}]

        # combine 3 router ports for nexthop group
        nh_group = pytest.tb.create_next_hop_group()
        nh_mem1 = pytest.tb.create_next_hop_group_member(nh_group, pytest.tb.nh_id1, 10)
        nh_mem2 = pytest.tb.create_next_hop_group_member(nh_group, pytest.tb.nh_id2, 1)
        nh_mem3 = pytest.tb.create_next_hop_group_member(nh_group, pytest.tb.nh_id3, 1)

        # route through nh
        pytest.tb.create_route(
            pytest.tb.virtual_router_id,
            pytest.top.route_prefix3,
            pytest.top.route_prefix3_mask,
            nh_group)
        pytest.tb.create_route(
            pytest.tb.virtual_router_id,
            pytest.top.svi_route2_prefix,
            pytest.top.svi_route2_mask,
            pytest.tb.svi_nh)

        nh_mems = {pytest.top.in_port: nh_mem1, pytest.top.rt_port: nh_mem2, pytest.top.rt_port1: nh_mem3}

        for weight_grp in test_weights:
            total_nhw = 0
            nhw = weight_grp
            for port_pif in nh_ports:
                # setup next_hop_group member weight and calculate total weight
                pytest.tb.configure_next_hop_group_member_weight(nh_mems[port_pif], nhw[port_pif])
                total_nhw = total_nhw + nhw[port_pif]

            # check number of created next_hop members (ecmp members in group)
            # Get number of members from the last next_hop group, which is the one in test case
            total_ecmp_members = pytest.tb.number_of_ecmp_members_in_group(-1)
            pytest.tb.log('**** Result: weight ==== {0}'.format(nhw))
            pytest.tb.log('**** Result: ecmp_members: {}, total_weight: {}'.format(total_ecmp_members, total_nhw))

            if total_ecmp_members != total_nhw:
                raise

            pkt_cntrs = {}

            for i, j in itertools.product(range(ip_i_range), range(ip_j_range)):
                route_ip = ip_inc(i, j)
                in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
                    IPv6(src=pytest.top.svi_dst_neighbor_ip, dst=route_ip, hlim=64) / \
                    UDP(sport=64, dport=2048)

                expected_out_pkt1 = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
                    IPv6(src=pytest.top.svi_dst_neighbor_ip, dst=route_ip, hlim=63) / \
                    UDP(sport=64, dport=2048)

                expected_out_pkt2 = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
                    IPv6(src=pytest.top.svi_dst_neighbor_ip, dst=route_ip, hlim=63) / \
                    UDP(sport=64, dport=2048)

                expected_out_pkt3 = Ether(dst=pytest.top.neighbor_mac4, src=pytest.tb.router_mac) / \
                    IPv6(src=pytest.top.svi_dst_neighbor_ip, dst=route_ip, hlim=63) / \
                    UDP(sport=64, dport=2048)

                U.run_and_compare_set(self,
                                      in_pkt,
                                      pytest.top.out_port,
                                      {pytest.top.in_port: expected_out_pkt1,
                                       pytest.top.rt_port: expected_out_pkt2,
                                       pytest.top.rt_port1: expected_out_pkt3},
                                      False,
                                      pkt_cntrs)

            pytest.tb.log('**** Result: Counters ==== {0}'.format(pkt_cntrs))
            pkt_ratio = {}
            nhw_ratio = {}
            nhw_match = {}
            for port_pif in nh_ports:
                pkt_ratio[port_pif] = round(pkt_cntrs[port_pif] / total_packets, 2)
                nhw_ratio[port_pif] = round(nhw[port_pif] / total_nhw, 2)
                nhw_match[port_pif] = round(abs(nhw_ratio[port_pif] - pkt_ratio[port_pif]), 2) <= tolerance

            pytest.tb.log('**** Result: ratio vs weight ==== {0} vs {1}'.format(pkt_ratio, nhw_ratio))
            pytest.tb.log('**** Result: test passed ==== {0}'.format(nhw_match))

            for port_pif in nh_ports:
                assert nhw_match[port_pif], 'Distribution not matched with tolerance({0}). pkt_ratio:{1} vs weight:{2}'.format(
                    tolerance, pkt_ratio, nhw_ratio)

        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.route_prefix3, pytest.top.route_prefix3_mask)
        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.svi_route2_prefix, pytest.top.svi_route2_mask)
        pytest.tb.remove_next_hop_group_member(nh_mem1)
        pytest.tb.remove_next_hop_group_member(nh_mem2)
        pytest.tb.remove_next_hop_group_member(nh_mem3)

        # check if all ecmp members are remove correctly.
        total_ecmp_members = pytest.tb.number_of_ecmp_members_in_group(-1)
        if total_ecmp_members != 0:
            raise

        pytest.tb.remove_next_hop_group(nh_group)
