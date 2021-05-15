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

import trap_common
import pytest
import saicli as S
import sai_packet_utils as U
import sai_test_base as st_base
import sai_test_utils as st_utils
from scapy.all import *
import sai_topology as topology
import time


@pytest.mark.usefixtures("basic_route_v4_topology")
class Test_trap_groups_event_policer(trap_common.test_trap_common):

    def lacp_packet(self, count):
        num_pkts_before, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
        s_i_p = st_utils.lane_to_slice_ifg_pif(pytest.top.in_port)

        if pytest.tb.is_hw():
            attr = S.sai_attribute_t(S.SAI_SWITCH_ATTR_CPU_PORT, 0)
            pytest.tb.apis[S.SAI_API_SWITCH].get_switch_attribute(pytest.tb.switch_id, 1, attr)
            cpu_queue_list = pytest.tb.get_queue_list(attr.value.oid)

            for q in cpu_queue_list.to_pylist():
                q_cnts = pytest.tb.get_queue_stats(q)
                if q_cnts[0] != 0:
                    print("q_cnts: queue {0} packets {1} drops {2}\n" .format(hex(q), q_cnts[0], q_cnts[1]))
            num_pkts, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
            print("punt pkts: num_pkts {0} sip {1}\n" .format(num_pkts, hex(pkt_sip)))
        else:
            lacp_da = '01:80:c2:00:00:02'

            # use LACP for spirent generated traffic
            # in_pkt = \
            #    Ether(dst=lacp_da, src="00:01:02:03:04:05", type=U.Ethertype.LLDP.value) / \
            #    IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64)
            in_pkt = \
                Ether(dst=lacp_da, src="00:01:02:03:04:05", type=U.Ethertype.LACP.value) / \
                IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64)

            expected_out_pkt = in_pkt

            num_pkts_before, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
            s_i_p = st_utils.lane_to_slice_ifg_pif(pytest.top.in_port)

            pytest.tb.inject_network_packet(in_pkt, s_i_p["slice"], s_i_p["ifg"], s_i_p["pif"])
            time.sleep(1)

            num_pkts, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
            assert num_pkts == num_pkts_before + count
            assert num_pkts == num_pkts_before + count
            if count != 0:
                U.assertEqualPackets(self, out_pkt, U.scapy_to_hex(in_pkt))
                assert pkt_sip == pytest.tb.ports[pytest.top.in_port]

    def test_create_trap_group_event(self):
        trap_group_2 = pytest.tb.create_trap_group(2)
        self.create_traps_with_group(trap_group_2)

        trap_group_3 = pytest.tb.create_trap_group(3)

        self.lacp_packet(1)
        # set set trap group from 2 to 3
        pytest.tb.set_trap_group(self.lacp_trap, trap_group_3)
        self.lacp_packet(1)

        self.remove_traps()
        pytest.tb.remove_trap_group(trap_group_3)
        pytest.tb.remove_trap_group(trap_group_2)

    def test_trap_group_queue_event(self):
        trap_group_2 = pytest.tb.create_trap_group(2)
        self.create_traps_with_group(trap_group_2)

        pytest.tb.set_trap_group(self.lacp_trap, trap_group_2)

        self.lacp_packet(1)
        pytest.tb.set_trap_group_queue(trap_group_2, 4)
        self.lacp_packet(1)

        self.remove_traps()
        pytest.tb.remove_trap_group(trap_group_2)

    def test_trap_group_remove_event(self):
        trap_group_2 = pytest.tb.create_trap_group(2)
        self.create_traps_with_group(trap_group_2)

        trap_group_3 = pytest.tb.create_trap_group(3)

        self.lacp_packet(1)

        pytest.tb.do_warm_boot()

        # set set trap group from 2 to 3
        pytest.tb.set_trap_group(self.lacp_trap, trap_group_3)
        self.lacp_packet(1)
        pytest.tb.remove_trap_group(trap_group_3)
        self.lacp_packet(1)

        trap_group_default = pytest.tb.get_default_trap_group()
        trap_group_lacp = pytest.tb.get_trap_group(self.lacp_trap)
        trap_group_arp = pytest.tb.get_trap_group(self.arp_trap)

        assert trap_group_default == trap_group_lacp

        self.remove_traps()
        pytest.tb.remove_trap_group(trap_group_2)

    # test with snoop action
    # test with policer value change
