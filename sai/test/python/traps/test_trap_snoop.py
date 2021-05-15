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
from scapy.all import *
import sai_test_utils as st_utils
import saicli as S


@pytest.mark.usefixtures("svi_route_no_tag_v4_topology")
class Test_trap_snoop():
    trap_group = None
    trap_group_2 = None

    def lacp_packet_snoop(self, count, trap_type):
        lacp_da = '01:80:c2:00:00:02'

        in_pkt = Ether(dst=lacp_da, src=pytest.top.svi_dst_neighbor_mac, type=U.Ethertype.LACP.value) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.neighbor_ip1, ttl=64)

        expected_out_punt_pkt = Ether(dst=lacp_da, src=pytest.top.svi_dst_neighbor_mac) / \
            Dot1Q(prio=0, vlan=pytest.top.vlan, type=U.Ethertype.LACP.value) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.neighbor_ip1, ttl=64)

        exp_out_port_packets = {pytest.top.sw_port: in_pkt}

        U.run_and_compare_snoop(self, in_pkt, pytest.top.out_port, exp_out_port_packets, expected_out_punt_pkt, count, trap_type)

    def lacp_packet(self, count, trap_type):
        num_pkts_before, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
        s_i_p = st_utils.lane_to_slice_ifg_pif(pytest.top.in_port)
        lacp_da = '01:80:c2:00:00:02'

        in_pkt = Ether(dst=lacp_da, src=pytest.top.svi_dst_neighbor_mac, type=U.Ethertype.LACP.value) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.neighbor_ip1, ttl=64)

        expected_out_punt_pkt = in_pkt
        U.punt_test(self, in_pkt, pytest.top.in_port, expected_out_punt_pkt, count, trap_type)

    def test_snoop_action_change(self):
        st_utils.skipIf(pytest.tb.is_gb)
        self.lacp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_LACP, S.SAI_PACKET_ACTION_DROP, 250)
        print("lacp_trap: " + str(self.lacp_trap))
        pytest.tb.set_trap_action(self.lacp_trap, S.SAI_PACKET_ACTION_LOG)
        self.lacp_packet_snoop(1, self.lacp_trap)

        # test trap action change (trap_type not checked)
        pytest.tb.set_trap_action(self.lacp_trap, S.SAI_PACKET_ACTION_TRAP)
        self.lacp_packet(1, self.lacp_trap)

        pytest.tb.remove_trap(self.lacp_trap)

    def test_snoop_priority(self):
        st_utils.skipIf(pytest.tb.is_gb)
        self.lacp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_LACP, S.SAI_PACKET_ACTION_LOG, 250)
        # test snoop priority change
        pytest.tb.set_trap_priority(self.lacp_trap, 252)
        self.lacp_packet_snoop(1, self.lacp_trap)

        pytest.tb.set_trap_priority(self.lacp_trap, 245)
        self.lacp_packet_snoop(1, self.lacp_trap)

        pytest.tb.remove_trap(self.lacp_trap)

    def test_snoop_group_change(self):
        self.trap_group = pytest.tb.create_trap_group(1)
        self.lacp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_LACP, S.SAI_PACKET_ACTION_LOG, 255, self.trap_group)
        trap_group_id = pytest.tb.get_trap_group(self.lacp_trap)
        assert self.trap_group == trap_group_id

        if self.trap_group_2 is None:
            self.trap_group_2 = pytest.tb.create_trap_group(2)
        pytest.tb.set_trap_group(self.lacp_trap, self.trap_group_2)

        trap_group_id = pytest.tb.get_trap_group(self.lacp_trap)
        # check after trap group changed
        assert self.trap_group_2 == trap_group_id
