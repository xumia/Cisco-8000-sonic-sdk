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


@pytest.mark.usefixtures("svi_route_no_tag_v4_topology")
class Test_svi_route_v4(basic_router_common.test_basic_route):

    def test_topology_config(self):
        pytest.top.deconfigure_svi_route_topology()
        pytest.top.configure_svi_route_topology()
        pytest.top.deconfigure_svi_route_topology()
        pytest.top.configure_svi_route_topology()

    # broadcast arp in from bridge port
    def test_arp_punt(self):
        in_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=pytest.top.svi_mac2) / ARP()

        out_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=pytest.top.svi_mac2, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / ARP()

        arp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_ARP_REQUEST, S.SAI_PACKET_ACTION_TRAP, 255)
        U.punt_test(self, in_pkt, pytest.top.sw_port, out_pkt)
        pytest.tb.remove_trap(arp_trap)

    # neighbor1 -> host
    def test_ipv4_punt(self):
        in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.local_ip1, ttl=64) / \
            UDP(sport=64, dport=2048)

        out_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.local_ip1, ttl=64) / \
            UDP(sport=64, dport=2048)

        ip2me_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_IP2ME, S.SAI_PACKET_ACTION_TRAP)
        U.punt_test(self, in_pkt, pytest.top.sw_port, out_pkt)
        pytest.tb.remove_trap(ip2me_trap)

    def test_arp_inject_up(self):
        in_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=pytest.top.svi_mac, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / ARP()

        out_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=pytest.top.svi_mac) / ARP()

        arp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_ARP_REQUEST, S.SAI_PACKET_ACTION_TRAP, 255)

        U.inject_up_test(self, in_pkt, out_pkt)

        pytest.tb.remove_trap(arp_trap)

    # host -> neighbor_ip2
    def test_inject_up(self):
        total_bytes = 0

        # payload size... 10158 Max payload include inject header. Max MTU 10240
        pkt_lens = [
            random.randrange(1000, 1437),
            random.randrange(1438, 2500),
            random.randrange(2501, 6000), 8111]

        # nsim only upto 8K bytes, but HW can goes upto 10239 Bytes
        if pytest.tb.is_hw():
            pkt_lens.append(8112)
            pkt_lens.append(9500)
            pkt_lens.append(10158)

        for paylaod_size in pkt_lens:
            data = ""
            for i in range(paylaod_size):
                data = "{}{}".format(data, chr(random.randrange(40, 125)))

            in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.neighbor_mac1) / \
                Dot1Q(prio=0, vlan=pytest.top.vlan) / \
                IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_dst_neighbor_ip, ttl=64) / \
                UDP(sport=64, dport=2048) / Raw(load=data)

            expected_out_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
                IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_dst_neighbor_ip, ttl=63) / \
                UDP(sport=64, dport=2048) / Raw(load=data)

            total_bytes = total_bytes + len(in_pkt)
            pytest.tb.log("packet length = {}, total ({})".format(len(in_pkt), total_bytes))

            if pytest.tb.is_hw():
                pytest.tb.inject_packet_up(in_pkt)
                if pytest.tb.debug_log:
                    st_utils.print_ports_stats(pytest.tb)

                counters = pytest.tb.get_port_stats(pytest.tb.ports[pytest.top.out_port])

                assert counters[20] == total_bytes, "At port[{}], Tx Bytes({}) != Expected({})".format(
                    hex(pytest.top.out_port), counters[20], total_bytes)
            else:
                U.inject_up_test(self, in_pkt, expected_out_pkt)

    # host -> svi_dst_neighbor
    def test_inject_down(self):
        in_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_dst_neighbor_ip, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.inject_down_test(self, in_pkt)

    # neighbor1 -> svi_neighbor
    def test_rp_to_svi_neigh(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_dst_neighbor_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_dst_neighbor_ip, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

    def test_rp_to_svi_egress_flood(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_dst_neighbor_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_dst_neighbor_ip, ttl=63) / \
            UDP(sport=64, dport=2048)

        # test egress flooding
        # test traffic after remove fdb
        pytest.tb.remove_fdb_entry(pytest.tb.vlans[pytest.top.vlan], pytest.top.svi_dst_neighbor_mac)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # test creating next hop without fdb entry programemd
        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.svi_route3_prefix, pytest.top.svi_route3_mask)
        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.svi_route2_prefix, pytest.top.svi_route2_mask)
        # TBD need to get sdk mac move to work for next hop removal
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
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.neighbor_ip1, len=150, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.neighbor_ip1, len=150, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.out_port, expected_out_pkt, pytest.top.in_port)

    # neighbor1 -> svi_route2_ip
    def test_mtu_trap(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, ttl=64) / \
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

    # neighbor1 -> svi_route2_ip
    @pytest.mark.skipif(st_utils.is_sai_17x_or_higher(), reason="Test for SAI 1.5.x only")
    def test_rp_to_svi_nh_15x(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

    # neighbor1 -> svi_route2_ip
    @pytest.mark.skipif(st_utils.is_sai_15x(), reason="Disabled on SAI 1.5.x")
    def test_rp_to_svi_nh(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # test: no decrement TTL
        pytest.tb.disable_decrement_ttl(pytest.top.out_port)

        expected_out_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # test: no decrement TTL=1
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, ttl=1) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, ttl=1) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # decrement TTL for other test cases after
        pytest.tb.enable_decrement_ttl(pytest.top.out_port)

    # svi_neighbor -> route_ip3
    @pytest.mark.skipif(st_utils.is_sai_17x_or_higher(), reason="Test for SAI 1.5.x only")
    def test_svi_to_rp_nh_15x(self):
        in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route_ip3, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route_ip3, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.out_port, expected_out_pkt, pytest.top.in_port)

    # svi_neighbor -> route_ip3
    @pytest.mark.skipif(st_utils.is_sai_15x(), reason="Disabled on SAI 1.5.x")
    def test_svi_to_rp_nh(self):
        in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route_ip3, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route_ip3, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.out_port, expected_out_pkt, pytest.top.in_port)

        # test: no decrement TTL
        pytest.tb.disable_decrement_ttl(pytest.top.in_port)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route_ip3, ttl=64) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.out_port, expected_out_pkt, pytest.top.in_port)

        # test: no decrement TTL=1
        in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route_ip3, ttl=1) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route_ip3, ttl=1) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.out_port, expected_out_pkt, pytest.top.in_port)

        # decrement TTL for other test cases after
        pytest.tb.enable_decrement_ttl(pytest.top.in_port)

    @pytest.mark.skipif(st_utils.is_sai_17x_or_higher(), reason="Test for SAI 1.5.x only")
    def test_longest_prefix_matching_15x(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, ttl=63) / \
            UDP(sport=64, dport=2048)
        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route3_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route3_ip, ttl=63) / \
            UDP(sport=64, dport=2048)
        U.run_and_compare(self, in_pkt, pytest.top.out_port, expected_out_pkt, pytest.top.in_port)

        in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route4_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route4_ip, ttl=63) / \
            UDP(sport=64, dport=2048)
        U.run_and_compare(self, in_pkt, pytest.top.out_port, expected_out_pkt, pytest.top.rt_port)

    @pytest.mark.skipif(st_utils.is_sai_15x(), reason="Disabled on SAI 1.5.x")
    def test_longest_prefix_matching(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, ttl=63) / \
            UDP(sport=64, dport=2048)
        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route3_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route3_ip, ttl=63) / \
            UDP(sport=64, dport=2048)
        U.run_and_compare(self, in_pkt, pytest.top.out_port, expected_out_pkt, pytest.top.in_port)

        in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route4_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route4_ip, ttl=63) / \
            UDP(sport=64, dport=2048)
        U.run_and_compare(self, in_pkt, pytest.top.out_port, expected_out_pkt, pytest.top.rt_port)

        # test: no decrement TTL
        pytest.tb.disable_decrement_ttl(pytest.top.in_port)
        pytest.tb.disable_decrement_ttl(pytest.top.out_port)
        pytest.tb.disable_decrement_ttl(pytest.top.rt_port)

        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, ttl=64) / \
            UDP(sport=64, dport=2048)
        expected_out_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.svi_route2_ip, ttl=64) / \
            UDP(sport=64, dport=2048)
        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route3_ip, ttl=64) / \
            UDP(sport=64, dport=2048)
        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route3_ip, ttl=64) / \
            UDP(sport=64, dport=2048)
        U.run_and_compare(self, in_pkt, pytest.top.out_port, expected_out_pkt, pytest.top.in_port)

        in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route4_ip, ttl=64) / \
            UDP(sport=64, dport=2048)
        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.route4_ip, ttl=64) / \
            UDP(sport=64, dport=2048)
        U.run_and_compare(self, in_pkt, pytest.top.out_port, expected_out_pkt, pytest.top.rt_port)

        # decrement TTL for other test cases after
        pytest.tb.enable_decrement_ttl(pytest.top.in_port)
        pytest.tb.enable_decrement_ttl(pytest.top.out_port)
        pytest.tb.enable_decrement_ttl(pytest.top.rt_port)

    def ttlerr_packet(self, count, trap_type):

        in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst=pytest.top.neighbor_ip1, ttl=1)

        in_pad_len = 0
        if len(in_pkt) < 72:
            in_pad_len = 72 - len(in_pkt)
            padded_in_packet = in_pkt / ("\0" * in_pad_len)
        else:
            padded_in_packet = in_pkt

        num_pkts_before, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
        s_i_p = st_utils.lane_to_slice_ifg_pif(pytest.top.out_port)

        pytest.tb.inject_network_packet(padded_in_packet, s_i_p["slice"], s_i_p["ifg"], s_i_p["pif"])
        time.sleep(1)

        num_pkts, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
        assert num_pkts == num_pkts_before + count
        if count != 0:
            exp_out_ip = padded_in_packet[IP].build()
            exp_out_ip = IP(exp_out_ip)
            exp_out_ip.ttl = 0
            U.assertEqualPackets(self, out_pkt, U.scapy_to_hex(exp_out_ip))
            assert pkt_trap_id == trap_type
            assert pkt_dst_port == pytest.tb.ports[pytest.top.in_port]
            # until the ttlerror punt packet system source port gets fixed
            #assert pkt_sip == pytest.tb.ports[pytest.top.out_port]
            assert pkt_sip == 0

    def test_ttl_trap(self):
        trap1 = self.ttlerr_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_TTL_ERROR, S.SAI_PACKET_ACTION_DROP, 245)
        trap2 = self.mtuerr_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_L3_MTU_ERROR, S.SAI_PACKET_ACTION_DROP, 240)
        pytest.tb.set_trap_action(self.mtuerr_trap, S.SAI_PACKET_ACTION_TRAP)
        pytest.tb.set_trap_action(self.ttlerr_trap, S.SAI_PACKET_ACTION_TRAP)

        # setting ttlerr priority higher than the other trap
        pytest.tb.set_trap_priority(self.ttlerr_trap, 255)
        self.ttlerr_packet(1, self.ttlerr_trap)
        pytest.tb.remove_trap(trap1)
        pytest.tb.remove_trap(trap2)
