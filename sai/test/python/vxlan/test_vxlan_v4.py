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
from saicli import *
import sai_packet_utils as U
from scapy.all import *
import sai_test_utils as st_utils
import sai_packet_test_defs as P
import unittest


# svi router topology for IPv4 and IPv6 tests
#                    -----------------------------------------
#                    |in_port: rif1                 out_port:| <--> svi_dst_neighbor_mac
# neighbor_ip1       |route_prefix1                          |      svi_dst_host1
# neighbor_mac1 <--> |router_mac    svi_rif:                 |
#                    |              vlan                     |
#                    |              svi_dst_prefix   sw_port:| <--> acc_host
#                    |              svi_mac                  |
#                    |                                       |
#                    -----------------------------------------
@pytest.mark.usefixtures("svi_route_no_tag_v4_topology")
class Test_vxlan_v4():

    vxlan_router_mac = "00:aa:bb:cc:dd:ee"
    vxlan_tunnel_neighbor_mac = "00:be:af:de:ad:00"

    def send_vxlan_packet(self, mac_addr=None):
        dst_mac = self.vxlan_tunnel_neighbor_mac
        if mac_addr is not None:
            dst_mac = mac_addr

        in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst="1.2.3.4", ttl=63) / \
            UDP(sport=64, dport=2048)

        out_pkt = Ether(dst=dst_mac, src=self.vxlan_router_mac) / \
            IP(src=pytest.top.svi_dst_neighbor_ip, dst="1.2.3.4", ttl=62) / \
            UDP(sport=64, dport=2048)

        vxlan_out_pkt = Ether(src=pytest.tb.router_mac, dst=pytest.top.neighbor_mac1) / \
            IP(dst=pytest.top.v4_vxlan_remote_lpbk, src=pytest.top.v4_vxlan_local_lpbk, id=0, flags=2, ttl=255) / \
            UDP(sport=37386, dport=4789, chksum=0) / \
            P.VXLAN(flags='Instance', vni=9000) / \
            out_pkt

        self.tun_nh = pytest.tb.create_next_hop(pytest.top.v4_vxlan_remote_lpbk, pytest.top.tunnel,
                                                SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP, mac_addr=mac_addr)
        pytest.tb.create_route(pytest.tb.virtual_router_id, "1.2.3.0", "255.255.255.0", self.tun_nh)

        U.run_and_compare(self, in_pkt, pytest.top.out_port, vxlan_out_pkt, pytest.top.in_port)

        num_tunnel_ids, tunnel_ids = pytest.tb.get_object_keys(SAI_OBJECT_TYPE_TUNNEL)
        num_tunnel_map_ids, tunnel_map_ids = pytest.tb.get_object_keys(SAI_OBJECT_TYPE_TUNNEL_MAP)
        num_tunnel_map_entry_ids, tunnel_map_entry_ids = pytest.tb.get_object_keys(SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY)

        pytest.tb.remove_route(pytest.tb.virtual_router_id, "1.2.3.0", "255.255.255.0")
        pytest.tb.remove_next_hop(self.tun_nh)

    # vxlan encap
    def test_vxlan_encap(self):
        st_utils.skipIf(pytest.tb.is_gb)

        pytest.top.configure_one_vxlan_tunnel_topology()
        pytest.tb.create_route(pytest.tb.virtual_router_id, pytest.top.v4_vxlan_remote_lpbk, pytest.top.full_mask, pytest.tb.nh_id1)

        self.send_vxlan_packet()

        self.send_vxlan_packet("00:11:22:33:44:00")

        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.v4_vxlan_remote_lpbk, pytest.top.full_mask)

        pytest.top.deconfigure_one_vxlan_tunnel_topology()

    def test_vxlan_decap(self):
        st_utils.skipIf(pytest.tb.is_gb)

        pytest.top.configure_one_vxlan_tunnel_topology()
        pytest.tb.create_route(pytest.tb.virtual_router_id, pytest.top.v4_vxlan_remote_lpbk, pytest.top.full_mask, pytest.tb.nh_id1)

        #exp_out_pkt = Ether(dst="00:aa:bb:cc:dd:ee", src=self.top.svi_dst_neighbor_mac)
        in_pkt = Ether(dst=self.vxlan_router_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            IP(dst=pytest.top.svi_dst_neighbor_ip, src="15.0.0.1", ttl=64) / ("\0" * 26)

        vxlan_in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.v4_vxlan_remote_lpbk, dst=pytest.top.v4_vxlan_local_lpbk,
               id=0, flags=2, ttl=64) / \
            UDP(sport=6522, dport=4789, chksum=0) / \
            P.VXLAN(flags='Instance', vni=9000) / \
            in_pkt

        exp_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            IP(dst=pytest.top.svi_dst_neighbor_ip, src="15.0.0.1", ttl=63) / ("\0" * 26)

        self.tun_nh = pytest.tb.create_next_hop(pytest.top.v4_vxlan_remote_lpbk, pytest.top.tunnel, SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP)
        pytest.tb.create_route(pytest.tb.virtual_router_id, "1.2.3.0", "255.255.255.0", self.tun_nh)

        U.run_and_compare(self, vxlan_in_pkt, pytest.top.in_port, exp_pkt, pytest.top.out_port)

        pytest.tb.remove_route(pytest.tb.virtual_router_id, "1.2.3.0", "255.255.255.0")
        pytest.tb.remove_next_hop(self.tun_nh)
        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.v4_vxlan_remote_lpbk, pytest.top.full_mask)
        pytest.top.deconfigure_one_vxlan_tunnel_topology()
