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
class Test_traps_lpts():
    def create_traps_lpts(self):
        self.ndp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY, S.SAI_PACKET_ACTION_DROP, 255)
        self.ip2me_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_IP2ME, S.SAI_PACKET_ACTION_DROP, 245)
        self.dhcp6_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_DHCPV6, S.SAI_PACKET_ACTION_DROP, 240)
        self.bgpv6_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_BGPV6, S.SAI_PACKET_ACTION_TRAP, 252)
        self.bgp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_BGP, S.SAI_PACKET_ACTION_TRAP, 251)

    def remove_traps_lpts(self):
        pytest.tb.remove_trap(self.ndp_trap)
        pytest.tb.remove_trap(self.ip2me_trap)
        pytest.tb.remove_trap(self.dhcp6_trap)
        pytest.tb.remove_trap(self.bgp_trap)
        pytest.tb.remove_trap(self.bgpv6_trap)

    def bgpv6_packet(self, count, trap_type):
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
            U.punt_test(self, in_pkt, pytest.top.in_port, in_pkt, 1, trap_type)

    def ndp_packet(self, count, trap_type):
        num_pkts_before, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
        s_i_p = st_utils.lane_to_slice_ifg_pif(pytest.top.in_port)

        da_v6 = "33:33:ff:48:00:00"
        dip_v6 = "FF02::1"

        in_pkt = Ether(dst=da_v6, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=dip_v6, hlim=255) / \
            ICMPv6ND_NS()
        expected_out_pkt = in_pkt

        if pytest.tb.is_hw():
            pytest.tb.inject_packet_down(in_pkt, port)
            st_utils.print_port_queue_stats(pytest.tb, pytest.tb.cpu_port)
        else:
            U.punt_test(self, in_pkt, pytest.top.in_port, expected_out_pkt, count, trap_type)

    def dhcp6_packet(self, count, trap_type):
        in_pkt = \
            Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1, type=0x86DD) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.local_ip1, hlim=64, nh=58) / \
            UDP(sport=68, dport=67)

        expected_out_pkt = in_pkt

        U.punt_test(self, in_pkt, pytest.top.in_port, expected_out_pkt, count, trap_type)

    def test_lpts_trap_priority(self):
        self.create_traps_lpts()
        pytest.tb.set_trap_action(self.ndp_trap, S.SAI_PACKET_ACTION_TRAP)
        pytest.tb.set_trap_action(self.ip2me_trap, S.SAI_PACKET_ACTION_TRAP)
        # test ndp priority
        self.ndp_packet(1, self.ndp_trap)

        pytest.tb.set_trap_priority(self.ndp_trap, 245)
        pytest.tb.set_trap_priority(self.ip2me_trap, 255)
        # test ip2me priority
        self.ndp_packet(1, self.ip2me_trap)

        self.remove_traps_lpts()

    def test_ndp_trap(self):
        self.create_traps_lpts()
        pytest.tb.set_trap_action(self.ndp_trap, S.SAI_PACKET_ACTION_TRAP)
        pytest.tb.set_trap_action(self.ip2me_trap, S.SAI_PACKET_ACTION_DROP)
        self.ndp_packet(1, self.ndp_trap)
        # setting ip2me action to trap with higher priority
        pytest.tb.set_trap_action(self.ip2me_trap, S.SAI_PACKET_ACTION_TRAP)
        pytest.tb.set_trap_priority(self.ndp_trap, 235)
        pytest.tb.set_trap_priority(self.ip2me_trap, 255)
        self.bgpv6_packet(1, self.ip2me_trap)

        self.remove_traps_lpts()

    def test_dhcp6_trap(self):
        self.create_traps_lpts()
        # test dhcpv6 trap and priority
        pytest.tb.set_trap_priority(self.dhcp6_trap, 255)
        pytest.tb.set_trap_action(self.dhcp6_trap, S.SAI_PACKET_ACTION_TRAP)
        self.dhcp6_packet(1, self.dhcp6_trap)

        self.remove_traps_lpts()

    def test_bgpv6_drop(self):
        self.create_traps_lpts()
        # setting bgpv6 to have higher priority
        pytest.tb.set_trap_priority(self.ndp_trap, 245)
        pytest.tb.set_trap_priority(self.bgpv6_trap, 255)

        self.bgpv6_packet(1, self.bgpv6_trap)

        self.remove_traps_lpts()

    def test_bgpv6_ip2me_trap(self):
        self.create_traps_lpts()
        # setting action to trap
        pytest.tb.set_trap_action(self.ip2me_trap, S.SAI_PACKET_ACTION_TRAP)
        pytest.tb.set_trap_action(self.bgpv6_trap, S.SAI_PACKET_ACTION_TRAP)
        # set bgpv6 to high priority
        pytest.tb.set_trap_priority(self.ip2me_trap, 242)
        pytest.tb.set_trap_priority(self.bgpv6_trap, 255)
        self.bgpv6_packet(1, self.bgpv6_trap)
        # set ip2me to high priority
        pytest.tb.set_trap_priority(self.ip2me_trap, 255)
        pytest.tb.set_trap_priority(self.bgpv6_trap, 242)
        self.bgpv6_packet(1, self.ip2me_trap)
        # set action of bgpv6 to drop (test trap action)
        pytest.tb.set_trap_action(self.bgpv6_trap, S.SAI_PACKET_ACTION_DROP)
        self.bgpv6_packet(1, self.ip2me_trap)
        # setting bgpv6 action to trap with higher priority
        pytest.tb.set_trap_action(self.ip2me_trap, S.SAI_PACKET_ACTION_DROP)
        pytest.tb.set_trap_action(self.bgpv6_trap, S.SAI_PACKET_ACTION_TRAP)

        self.bgpv6_packet(1, self.bgpv6_trap)

        self.remove_traps_lpts()
