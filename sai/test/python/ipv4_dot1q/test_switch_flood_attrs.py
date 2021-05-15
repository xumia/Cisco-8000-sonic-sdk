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
import sai_test_utils as st_utils
from scapy.all import *
import saicli as S


@pytest.mark.usefixtures("flood_local_learn_bridge_topology")
class Test_flood_and_learn():
    unknown_ucast_mac = "00:00:BE:EF:DE:AD"
    bcast_mac = "FF:FF:FF:FF:FF:FF"
    mcast_mac = "01:00:5E:00:00:01"
    src_mac = "00:00:12:34:56:78"
    ucast_ip = "1.2.3.4"
    bcast_ip = "1.2.3.255"
    mcast_ip = "224.0.0.1"
    src_ip = "5.6.7.8"

    ucast_in_pkt = Ether(dst=unknown_ucast_mac, src=src_mac) / \
        IP(src=src_ip, dst=ucast_ip, ttl=64) / \
        UDP(sport=64, dport=2048)

    bcast_in_pkt = Ether(dst=bcast_mac, src=src_mac) / \
        IP(src=src_ip, dst=bcast_ip, ttl=64) / \
        UDP(sport=64, dport=2048)

    mcast_in_pkt = Ether(dst=mcast_mac, src=src_mac) / \
        IP(src=src_ip, dst=mcast_ip, ttl=64) / \
        UDP(sport=64, dport=2048)

    def test_default_flood(self):
        port_packets = {pytest.top.out_port: self.ucast_in_pkt, pytest.top.sw_port: self.ucast_in_pkt}
        U.run_and_compare_set(self, self.ucast_in_pkt, pytest.top.in_port, port_packets, match_all=True, with_learn=True)

        port_packets = {pytest.top.out_port: self.bcast_in_pkt, pytest.top.sw_port: self.bcast_in_pkt}
        U.run_and_compare_set(self, self.bcast_in_pkt, pytest.top.in_port, port_packets, match_all=True, with_learn=True)

        port_packets = {pytest.top.out_port: self.mcast_in_pkt, pytest.top.sw_port: self.mcast_in_pkt}
        U.run_and_compare_set(self, self.mcast_in_pkt, pytest.top.in_port, port_packets, match_all=True, with_learn=True)

    def test_drop_forward(self):
        pytest.tb.set_object_attr(
            pytest.tb.switch_id,
            S.SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_PACKET_ACTION,
            S.SAI_PACKET_ACTION_DROP,
            True)
        port_packets = {pytest.top.out_port: self.ucast_in_pkt, pytest.top.sw_port: self.ucast_in_pkt}
        U.run_and_compare_set(self, self.ucast_in_pkt, pytest.top.in_port, port_packets, match_all=True, with_learn=True)

        port_packets = {pytest.top.out_port: self.bcast_in_pkt, pytest.top.sw_port: self.bcast_in_pkt}
        U.run_and_compare_set(self, self.bcast_in_pkt, pytest.top.in_port, port_packets, match_all=True, with_learn=True)

        port_packets = {}
        U.run_and_compare_set(self, self.mcast_in_pkt, pytest.top.in_port, port_packets, match_all=True, with_learn=True)

        pytest.tb.set_object_attr(
            pytest.tb.switch_id,
            S.SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_PACKET_ACTION,
            S.SAI_PACKET_ACTION_FORWARD,
            True)
        pytest.tb.set_object_attr(
            pytest.tb.switch_id,
            S.SAI_SWITCH_ATTR_FDB_UNICAST_MISS_PACKET_ACTION,
            S.SAI_PACKET_ACTION_DROP,
            True)
        port_packets = {}
        U.run_and_compare_set(self, self.ucast_in_pkt, pytest.top.in_port, port_packets, match_all=True, with_learn=True)

        port_packets = {pytest.top.out_port: self.bcast_in_pkt, pytest.top.sw_port: self.bcast_in_pkt}
        U.run_and_compare_set(self, self.bcast_in_pkt, pytest.top.in_port, port_packets, match_all=True, with_learn=True)

        port_packets = {pytest.top.out_port: self.mcast_in_pkt, pytest.top.sw_port: self.mcast_in_pkt}
        U.run_and_compare_set(self, self.mcast_in_pkt, pytest.top.in_port, port_packets, match_all=True, with_learn=True)

        pytest.tb.set_object_attr(
            pytest.tb.switch_id,
            S.SAI_SWITCH_ATTR_FDB_UNICAST_MISS_PACKET_ACTION,
            S.SAI_PACKET_ACTION_FORWARD,
            True)
        pytest.tb.set_object_attr(
            pytest.tb.switch_id,
            S.SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_PACKET_ACTION,
            S.SAI_PACKET_ACTION_DROP,
            True)
        port_packets = {pytest.top.out_port: self.ucast_in_pkt, pytest.top.sw_port: self.ucast_in_pkt}
        U.run_and_compare_set(self, self.ucast_in_pkt, pytest.top.in_port, port_packets, match_all=True, with_learn=True)

        port_packets = {}
        U.run_and_compare_set(self, self.bcast_in_pkt, pytest.top.in_port, port_packets, match_all=True, with_learn=True)

        port_packets = {pytest.top.out_port: self.mcast_in_pkt, pytest.top.sw_port: self.mcast_in_pkt}
        U.run_and_compare_set(self, self.mcast_in_pkt, pytest.top.in_port, port_packets, match_all=True, with_learn=True)
