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
import sai_test_utils as st_utils
from scapy.all import *
import sai_topology as topology
import time


@pytest.mark.usefixtures("basic_route_v6_topology")
class Test_trap_groups_policer():
    trap_group = None
    trap_group_3 = None
    cpu_queue_list = None
    ndp_trap = None
    bgpv6_trap = None

    def create_trap_group_policer(self, cir = 6000, cbs = 2000):
        args = {}
        args[S.SAI_POLICER_ATTR_METER_TYPE] = S.SAI_METER_TYPE_PACKETS
        args[S.SAI_POLICER_ATTR_MODE] = S.SAI_POLICER_MODE_SR_TCM
        args[S.SAI_POLICER_ATTR_CBS] = cbs
        args[S.SAI_POLICER_ATTR_CIR] = cir
        args[S.SAI_POLICER_ATTR_RED_PACKET_ACTION] = S.SAI_PACKET_ACTION_DROP
        return pytest.tb.create_policer(args)

    # assign a new policer to the group and return the old policer back
    def set_trap_group_policer(self, group, policer):
        old_policer = pytest.tb.get_object_attr(group, S.SAI_HOSTIF_TRAP_GROUP_ATTR_POLICER)
        pytest.tb.set_trap_group_policer(group, policer)
        return old_policer

    def bgpv6_packet(self, count):
        num_pkts_before, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
        s_i_p = st_utils.lane_to_slice_ifg_pif(pytest.top.in_port)

        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.local_ip1, hlim=64, nh=6) / \
            TCP(sport=179, dport=50)

        if pytest.tb.is_hw():
            pytest.tb.inject_packet_down(in_pkt, pytest.top.in_port)
            st_utils.print_port_queue_stats(pytest.tb, pytest.tb.cpu_port)
            num_pkts, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
            if count != 0:
                assert pkt_sip == pytest.tb.ports[pytest.top.in_port]
                U.assertEqualPackets(self, out_pkt, U.scapy_to_hex(in_pkt))
        else:
            U.punt_test(self, in_pkt, pytest.top.in_port, in_pkt, 1, self.bgpv6_trap)

    def ndp_packet(self, count):
        num_pkts_before, out_pkt_before, pkt_sip_before, pkt_trap_id_before, pkt_dst_port_before, pkt_src_lag = pytest.tb.get_punt_packet()
        s_i_p = st_utils.lane_to_slice_ifg_pif(pytest.top.in_port)

        da_v6 = "33:33:ff:48:00:00"
        dip_v6 = "FF02::1"

        in_pkt = Ether(dst=da_v6, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=dip_v6, hlim=255) / \
            ICMPv6ND_NS()

        if pytest.tb.is_hw():
            pytest.tb.inject_packet_down(in_pkt, port)
            st_utils.print_port_queue_stats(pytest.tb, pytest.tb.cpu_port)
        else:
            pytest.tb.inject_network_packet(in_pkt, s_i_p["slice"], s_i_p["ifg"], s_i_p["pif"])
            time.sleep(1)

            num_pkts, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
            if self.ndp_trap is None or pkt_trap_id != self.ndp_trap:
                num_pkts = num_pkts_before

            assert num_pkts == num_pkts_before + count

            if count != 0:
                U.assertEqualPackets(self, out_pkt, U.scapy_to_hex(in_pkt))
                assert pkt_sip == pytest.tb.ports[pytest.top.in_port]

    def test_trap_without_group(self):
        self.ndp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY, S.SAI_PACKET_ACTION_TRAP, 255)
        self.bgpv6_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_BGPV6, S.SAI_PACKET_ACTION_TRAP, 252)
        self.bgpv6_packet(1)
        self.ndp_packet(1)
        pytest.tb.remove_object(self.ndp_trap)
        pytest.tb.remove_object(self.bgpv6_trap)

    def test_trap_with_group_no_policer(self):
        self.ndp_packet(0)

        self.ndp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY, S.SAI_PACKET_ACTION_TRAP, 255)
        self.ndp_packet(1)
        trap_group_0 = pytest.tb.create_trap_group(0)
        self.ndp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY,
                                              S.SAI_PACKET_ACTION_TRAP, 255, trap_group_0)
        self.ndp_packet(1)

        pytest.tb.remove_object(self.ndp_trap)
        pytest.tb.remove_object(trap_group_0)

    def test_trap_with_group_policer(self):
        trap_group_1 = pytest.tb.create_trap_group(1)
        trap_policer = self.create_trap_group_policer()
        self.set_trap_group_policer(trap_group_1, trap_policer)
        self.ndp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY,
                                              S.SAI_PACKET_ACTION_TRAP, 255, trap_group_1)

        p_stats_before = pytest.tb.get_policer_stats(trap_policer)
        self.bgpv6_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_BGPV6, S.SAI_PACKET_ACTION_TRAP, 255, trap_group_1)
        self.ndp_packet(1)
        p_stats_after_ndp = pytest.tb.get_policer_stats(trap_policer)
        assert (p_stats_after_ndp[0] - p_stats_before[0]) == 1
        self.bgpv6_packet(1)
        p_stats_after_bgp = pytest.tb.get_policer_stats(trap_policer)
        assert (p_stats_after_bgp[0] - p_stats_before[0]) == 2
        pytest.tb.remove_object(self.ndp_trap)
        pytest.tb.remove_object(self.bgpv6_trap)
        pytest.tb.remove_object(trap_group_1)
        pytest.tb.remove_object(trap_policer)

    def trap_group_policers_create(self, trap_spec_dict):
        trap_set = {}
        for trap, spec in trap_spec_dict.items():
            trap_info = {}
            trap_info["trap_group"] = pytest.tb.create_trap_group(spec["tc"])
            trap_info["trap_policer"] = self.create_trap_group_policer(spec["cir"])
            self.set_trap_group_policer(trap_info["trap_group"], trap_info["trap_policer"])
            trap_oid = pytest.tb.create_trap(trap, S.SAI_PACKET_ACTION_TRAP, spec["prio"], trap_info["trap_group"])
            trap_set[trap_oid] = trap_info
        return trap_set

    def trap_group_policers_remove(self, trap_set):
        for trap_oid, trap_info in trap_set.items():
            pytest.tb.remove_object(trap_oid)
            pytest.tb.remove_object(trap_info["trap_group"])
            pytest.tb.remove_object(trap_info["trap_policer"])

    def test_trap_group_policers(self):
        trap_spec_dict = {S.SAI_HOSTIF_TRAP_TYPE_ARP_REQUEST: {"tc": 0, "cir": 6000, "prio": 255},
                          S.SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY: {"tc": 1, "cir": 2000, "prio": 255},
                          S.SAI_HOSTIF_TRAP_TYPE_DHCPV6: {"tc": 2, "cir": 6000, "prio": 255},
                          S.SAI_HOSTIF_TRAP_TYPE_BGPV6: {"tc": 3, "cir": 6000, "prio": 255},
                          S.SAI_HOSTIF_TRAP_TYPE_DHCP: {"tc": 4, "cir": 6000, "prio": 255},
                          S.SAI_HOSTIF_TRAP_TYPE_L3_MTU_ERROR: {"tc": 5, "cir": 6000, "prio": 255},
                          S.SAI_HOSTIF_TRAP_TYPE_IP2ME: {"tc": 6, "cir": 6000, "prio": 255},
                          S.SAI_HOSTIF_TRAP_TYPE_TTL_ERROR: {"tc": 7, "cir": 6000, "prio": 255}}
        trap_set = self.trap_group_policers_create(trap_spec_dict)
        self.trap_group_policers_remove(trap_set)
        trap_set = self.trap_group_policers_create(trap_spec_dict)
        self.trap_group_policers_remove(trap_set)
