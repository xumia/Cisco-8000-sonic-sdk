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

import basic_router_common
import pytest
import saicli as S
import sai_packet_utils as U
import sai_test_utils as st_utils
from scapy.all import *


@pytest.mark.usefixtures("svi_route_tag_v4_topology")
class Test_svi_route_v4(basic_router_common.test_basic_route):

    def test_topology_config(self):
        pytest.top.deconfigure_svi_route_topology()
        pytest.top.configure_svi_route_topology(tag=True)
        pytest.top.deconfigure_svi_route_topology()
        pytest.top.configure_svi_route_topology(tag=True)

    # broadcast arp in from bridge port
    def test_arp_punt(self):
        in_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=pytest.top.svi_mac2) / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / ARP()

        out_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=pytest.top.svi_mac2) / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / ARP()

        arp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_ARP_REQUEST, S.SAI_PACKET_ACTION_TRAP, 255)
        U.punt_test(self, in_pkt, pytest.top.sw_port, out_pkt)
        pytest.tb.remove_trap(arp_trap)

    # neighbor1 -> host
    def test_ipv4_punt(self):
        in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.local_ip1, ttl=64) / \
            UDP(sport=64, dport=2048)

        out_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.local_ip1, ttl=64) / \
            UDP(sport=64, dport=2048)

        ip2me_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_IP2ME, S.SAI_PACKET_ACTION_TRAP)
        U.punt_test(self, in_pkt, pytest.top.sw_port, out_pkt)
        pytest.tb.remove_trap(ip2me_trap)

    # host -> neighbor_ip2
    def test_inject_up(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_dst_neighbor_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            Dot1Q(vlan=pytest.top.vlan) /\
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_dst_neighbor_ip, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.inject_up_test(self, in_pkt, expected_out_pkt)

    # host -> svi_dst_neighbor
    def test_inject_down(self):
        in_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_dst_neighbor_ip, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.inject_down_test(self, in_pkt)

    # neighbor1 -> svi_neighbor

    def test_rp_to_svi(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_dst_neighbor_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            Dot1Q(vlan=pytest.top.vlan) /\
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_dst_neighbor_ip, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

    def test_rp_to_svi_egress_flood(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_dst_neighbor_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            Dot1Q(vlan=pytest.top.vlan) /\
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_dst_neighbor_ip, ttl=63) / \
            UDP(sport=64, dport=2048)

        # test egress flooding when fdb does not exist
        pytest.tb.remove_fdb_entry(pytest.tb.vlans[pytest.top.vlan], pytest.top.svi_dst_neighbor_mac)
        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # no error when next hop programmed without fdb entry
        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.svi_route3_prefix, pytest.top.svi_route3_mask)
        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.svi_route2_prefix, pytest.top.svi_route2_mask)
        # TBD need to get sdk mac move fix for nexthop removal working
        pytest.tb.remove_next_hop(pytest.tb.svi_nh)
        pytest.tb.svi_nh = pytest.tb.create_next_hop(pytest.top.svi_dst_neighbor_ip, pytest.tb.svi_rif_id)
        pytest.tb.create_route(
            pytest.tb.virtual_router_id,
            pytest.top.svi_route3_prefix,
            pytest.top.svi_route3_mask,
            pytest.tb.svi_nh)
        pytest.tb.create_route(
            pytest.tb.virtual_router_id,
            pytest.top.svi_route2_prefix,
            pytest.top.svi_route2_mask,
            pytest.tb.svi_nh)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # restore the test
        pytest.tb.create_fdb_entry(pytest.tb.vlans[pytest.top.vlan],
                                   pytest.top.svi_dst_neighbor_mac,
                                   pytest.tb.bridge_ports[pytest.top.out_port])

    # svi_neighbor -> neighbor1
    def test_svi_to_rp(self):
        in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            Dot1Q(vlan=pytest.top.vlan) /\
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.neighbor_ip1, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.neighbor_ip1, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.out_port, expected_out_pkt, pytest.top.in_port)

    # neighbor1 -> svi_route2_ip
    def test_rp_to_svi_nh(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            Dot1Q(vlan=pytest.top.vlan) /\
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

    # neighbor1 -> svi_route2_ip
    def test_mtu_trap(self):
        st_utils.skipIf(pytest.tb.is_gb)
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            Dot1Q(vlan=pytest.top.vlan) /\
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, ttl=63) / \
            UDP(sport=64, dport=2048)

        pytest.tb.set_mtu_router_interface(pytest.tb.svi_rif_id, 1000)
        mtuerr_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_L3_MTU_ERROR, S.SAI_PACKET_ACTION_TRAP, 255)

        in_pkt_mtu = in_pkt / ("\0" * 1000)

        num_pkts_before, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()

        s_i_p = st_utils.lane_to_slice_ifg_pif(pytest.top.in_port)
        pytest.tb.inject_network_packet(in_pkt_mtu, s_i_p["slice"], s_i_p["ifg"], s_i_p["pif"])
        time.sleep(1)

        num_pkts, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()

        assert num_pkts == num_pkts_before + 1
        exp_out_ip = in_pkt_mtu[IP].build()
        exp_out_ip = IP(exp_out_ip)
        exp_out_ip.ttl = 63
        U.assertEqualPackets(self, out_pkt, U.scapy_to_hex(exp_out_ip))
        assert pkt_dst_port == pytest.tb.ports[pytest.top.out_port]
        assert pkt_trap_id == mtuerr_trap

        pytest.tb.remove_trap(mtuerr_trap)

    # svi_neighbor -> route_ip3
    def test_svi_to_rp_nh(self):
        in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            Dot1Q(vlan=pytest.top.vlan) /\
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route_ip3, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route_ip3, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.out_port, expected_out_pkt, pytest.top.in_port)
