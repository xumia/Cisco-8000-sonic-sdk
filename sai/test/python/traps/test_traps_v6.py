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
import decor


@pytest.mark.usefixtures("basic_route_v6_topology")
class Test_traps_v6():

    def ndp_punt(self, count):
        da_v6 = "33:33:ff:48:00:00"
        dip_v6 = "FF02::1"

        in_pkt = Ether(dst=da_v6, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=dip_v6, hlim=255) / \
            ICMPv6ND_NS()

        expected_out_pkt = in_pkt

        num_pkts_before, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
        s_i_p = st_utils.lane_to_slice_ifg_pif(pytest.top.in_port)

        pytest.tb.inject_network_packet(in_pkt, s_i_p["slice"], s_i_p["ifg"], s_i_p["pif"])
        time.sleep(1)

        num_pkts, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
        assert num_pkts == num_pkts_before + count
        if count != 0:
            U.assertEqualPackets(self, out_pkt, U.scapy_to_hex(in_pkt))
            assert pkt_sip == pytest.tb.ports[pytest.top.in_port]

    def test_ndp_drop(self):
        ndp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY, S.SAI_PACKET_ACTION_DROP, 255)
        ip2me_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_IP2ME, S.SAI_PACKET_ACTION_DROP, 245)
        pytest.tb.set_trap_action(ndp_trap, S.SAI_PACKET_ACTION_DROP)
        pytest.tb.set_trap_action(ip2me_trap, S.SAI_PACKET_ACTION_DROP)
        self.ndp_punt(0)
        pytest.tb.remove_trap(ndp_trap)
        pytest.tb.remove_trap(ip2me_trap)

    def test_ndp_trap(self):
        ndp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY, S.SAI_PACKET_ACTION_DROP, 255)
        ip2me_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_IP2ME, S.SAI_PACKET_ACTION_DROP, 245)
        pytest.tb.set_trap_action(ndp_trap, S.SAI_PACKET_ACTION_TRAP)
        pytest.tb.set_trap_action(ip2me_trap, S.SAI_PACKET_ACTION_DROP)
        self.ndp_punt(1)
        pytest.tb.remove_trap(ndp_trap)
        pytest.tb.remove_trap(ip2me_trap)

    def test_remove_ip2m(self):
        ip2me_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_IP2ME, S.SAI_PACKET_ACTION_DROP, 245)
        pytest.tb.remove_trap(ip2me_trap)
