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
class Test_trap_groups():
    trap_group = None
    trap_group_3 = None
    cpu_queue_list = None

    def create_traps_with_group(self, group):
        #self.arp_trap = self.create_trap(SAI_HOSTIF_TRAP_TYPE_ARP_REQUEST, SAI_PACKET_ACTION_TRAP, 255)
        self.ndp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY, S.SAI_PACKET_ACTION_TRAP, 255, group)
        self.ip2me_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_IP2ME, S.SAI_PACKET_ACTION_TRAP, group=group)
        self.dhcp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_DHCP, S.SAI_PACKET_ACTION_TRAP, 242, group)
        self.dhcp6_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_DHCPV6, S.SAI_PACKET_ACTION_TRAP, 243, group)
        self.bgpv6_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_BGPV6, S.SAI_PACKET_ACTION_TRAP, 252, group)
        self.bgp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_BGP, S.SAI_PACKET_ACTION_TRAP, 251, group)

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
        num_pkts_before, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
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
            assert num_pkts == num_pkts_before + count
            if count != 0:
                U.assertEqualPackets(self, out_pkt, U.scapy_to_hex(in_pkt))
                assert pkt_sip == pytest.tb.ports[pytest.top.in_port]

    def test_create_trap_group_lpts(self):
        if self.trap_group is None:
            self.trap_group = pytest.tb.create_trap_group(2)
        self.create_traps_with_group(self.trap_group)

        if self.trap_group_3 is None:
            self.trap_group_3 = pytest.tb.create_trap_group(3)

        self.bgpv6_packet(1)
        # set set trap group from 2 to 3
        pytest.tb.set_trap_group(self.bgpv6_trap, self.trap_group_3)
        self.bgpv6_packet(1)

        # pytest.tb.do_warm_boot() - ??? todo this fail. need to check

        self.ndp_packet(1)
        # set set trap group from 2 to 3
        pytest.tb.set_trap_group(self.ndp_trap, self.trap_group_3)
        self.ndp_packet(1)

        pytest.tb.remove_trap_group(self.trap_group_3)
        pytest.tb.remove_trap_group(self.trap_group)

    def test_trap_group_queue_lpts(self):
        if self.trap_group is None:
            self.trap_group = pytest.tb.create_trap_group(2)
        self.create_traps_with_group(self.trap_group)

        pytest.tb.set_trap_group(self.ndp_trap, self.trap_group)

        self.ndp_packet(1)
        pytest.tb.set_trap_group_queue(self.trap_group, 4)
        self.ndp_packet(1)
        pytest.tb.remove_trap_group(self.trap_group)

    def test_trap_group_remove_lpts(self):
        if self.trap_group is None:
            self.trap_group = pytest.tb.create_trap_group(2)
        self.create_traps_with_group(self.trap_group)

        if self.trap_group_3 is None:
            self.trap_group_3 = pytest.tb.create_trap_group(3)

        self.ndp_packet(1)
        # set set trap group from 2 to 3
        pytest.tb.set_trap_group(self.ndp_trap, self.trap_group_3)
        self.ndp_packet(1)
        pytest.tb.remove_trap_group(self.trap_group_3)
        self.ndp_packet(1)
        self.trap_group_3 = pytest.tb.create_trap_group(3)
