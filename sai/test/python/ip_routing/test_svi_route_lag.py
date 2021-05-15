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
import sai_test_utils as st_utils
from scapy.all import *


@pytest.mark.usefixtures("svi_route_lag_v4_topology")
@pytest.mark.skipif(st_utils.is_sai_15x(), reason="Disabled on SAI 1.5.x")
class Test_route_lag():
    def test_topology_config(self):
        obj_count, obj_list = pytest.tb.get_object_keys(S.SAI_OBJECT_TYPE_NEIGHBOR_ENTRY)
        pytest.top.deconfigure_svi_route_lag_topology()
        obj_count, obj_list = pytest.tb.get_object_keys(S.SAI_OBJECT_TYPE_NEIGHBOR_ENTRY)
        pytest.top.configure_svi_route_lag_topology()
        obj_count, obj_list = pytest.tb.get_object_keys(S.SAI_OBJECT_TYPE_NEIGHBOR_ENTRY)
        pytest.top.deconfigure_svi_route_lag_topology()
        obj_count, obj_list = pytest.tb.get_object_keys(S.SAI_OBJECT_TYPE_NEIGHBOR_ENTRY)
        pytest.top.configure_svi_route_lag_topology()
        obj_count, obj_list = pytest.tb.get_object_keys(S.SAI_OBJECT_TYPE_NEIGHBOR_ENTRY)

    def test_rp_to_svi_lag(self):
        st_utils.skipIf(pytest.tb.is_gb)
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_dst_neighbor_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_dst_neighbor_ip, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)
        # Disable traffic distribution on one of the lag members
        pytest.tb.set_lag_mem_egress_set_state(pytest.top.lag_member_id, disable=True)
        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.sw_port)
        # Unable traffic distribution and check the traffic back through out_port
        pytest.tb.set_lag_mem_egress_set_state(pytest.top.lag_member_id, disable=False)
        pytest.tb.set_lag_mem_egress_set_state(pytest.top.lag_member_id2, disable=True)
        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

    def test_svi_lag_to_rp(self):
        in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.neighbor_ip1, len=150, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.neighbor_ip1, len=150, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.out_port, expected_out_pkt, pytest.top.in_port)

    def test_lag_arp_punt(self):
        pytest.tb.log("Created LAG ID: {}".format(pytest.top.lag_id))

        in_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=pytest.top.svi_dst_neighbor_mac) / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / ARP()

        arp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_ARP_REQUEST, S.SAI_PACKET_ACTION_TRAP, 255)

        U.punt_test(self, in_pkt, pytest.top.out_port)
        num_pkts, out_pkt, pkt_sip1, pkt_trap_id, pkt_dst_port, pkt_src_lag1 = pytest.tb.get_punt_packet()
        pytest.tb.log(
            "punt pkt1: sip({}) trap_id({}) dst_port({}) lag_oid({})".format(
                pkt_sip1,
                pkt_trap_id,
                pkt_dst_port,
                pkt_src_lag1))
        assert (pkt_src_lag1 == pytest.top.lag_id)

        U.punt_test(self, in_pkt, pytest.top.sw_port)
        num_pkts, out_pkt, pkt_sip2, pkt_trap_id, pkt_dst_port, pkt_src_lag2 = pytest.tb.get_punt_packet()
        pytest.tb.log(
            "punt pkt2: sip({}) trap_id({}) dst_port({}) lag_oid({})".format(
                pkt_sip2,
                pkt_trap_id,
                pkt_dst_port,
                pkt_src_lag2))
        assert (pkt_src_lag2 == pytest.top.lag_id)

        assert (pkt_src_lag1 == pkt_src_lag2)
        assert (pkt_sip1 != pkt_sip2)

        pytest.tb.remove_trap(arp_trap)
