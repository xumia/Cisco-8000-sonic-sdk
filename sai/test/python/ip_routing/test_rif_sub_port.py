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
import basic_router_common

VLAN = 26


@pytest.fixture(scope="class")
def lag_rif_sub_port_topology(base_v4_topology):
    pytest.tb.configure_ports([pytest.top.in_port_cfg, pytest.top.out_port_cfg, pytest.top.sw_port_cfg])
    # configure lag with 2 lag members
    pytest.top.lag_id = pytest.tb.create_lag("Label1")
    pytest.top.lag_member_id = pytest.tb.create_lag_member(pytest.top.lag_id, pytest.top.out_port)
    pytest.top.lag_member_id2 = pytest.tb.create_lag_member(pytest.top.lag_id, pytest.top.sw_port)
    pytest.tb.ports[pytest.top.lag_id] = pytest.top.lag_id
    # configure rif 1 as PORT
    pytest.top.configure_rif_id_1(pytest.top.in_port)
    # configure lag id as SUB_PORT
    pytest.tb.rif_id_2 = pytest.tb.create_router_interface(
        pytest.tb.virtual_router_id, pytest.top.lag_id, S.SAI_ROUTER_INTERFACE_TYPE_SUB_PORT, pytest.tb.router_mac, pytest.top.vlan)
    pytest.tb.create_route(pytest.tb.virtual_router_id, pytest.top.route_prefix2, pytest.top.route_prefix2_mask, pytest.tb.rif_id_2)
    pytest.tb.create_neighbor(pytest.tb.rif_id_2, pytest.top.neighbor_ip2, pytest.top.neighbor_mac2)
    pytest.tb.nh_id2 = pytest.tb.create_next_hop(pytest.top.neighbor_ip2, pytest.tb.rif_id_2)

    # default route
    pytest.tb.create_route(pytest.tb.virtual_router_id, pytest.top.default_ip, pytest.top.default_ip_mask, S.SAI_NULL_OBJECT_ID)

    pytest.tb.setup_vrf_punt_path(pytest.tb.virtual_router_id, pytest.top.local_ip1, pytest.top.full_mask)
    pytest.tb.setup_vrf_punt_path(pytest.tb.virtual_router_id, pytest.top.local_ip2, pytest.top.full_mask)

    pytest.top.configure_rif_loopback()

    yield
    # deconfigure topology
    pytest.top.deconfigure_rif_loopback()
    pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.local_ip1, pytest.top.full_mask)
    pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.local_ip2, pytest.top.full_mask)

    pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.default_ip, pytest.top.default_ip_mask)

    pytest.tb.remove_next_hop(pytest.tb.nh_id2)
    pytest.tb.remove_neighbor(pytest.tb.rif_id_2, pytest.top.neighbor_ip2)
    pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.route_prefix2, pytest.top.route_prefix2_mask)
    pytest.tb.remove_router_interface(pytest.tb.rif_id_2)

    pytest.tb.remove_lag_member(pytest.top.lag_member_id)
    pytest.tb.remove_lag_member(pytest.top.lag_member_id2)
    pytest.tb.remove_lag(pytest.top.lag_id)

    pytest.top.deconfigure_rif_id_1()
    del pytest.tb.ports[pytest.top.lag_id]
    pytest.tb.remove_ports()


@pytest.mark.usefixtures("lag_rif_sub_port_topology")
@pytest.mark.skipif(st_utils.is_sai_15x(), reason="Disabled on SAI 1.5.x")
class Test_lag_sub_port():
    def test_rp_to_rp_lag(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare_set(
            self, in_pkt, pytest.top.in_port, {
                pytest.top.out_port: expected_out_pkt, pytest.top.sw_port: expected_out_pkt})

        # check the vid for sub port
        assert pytest.tb.get_object_attr(pytest.tb.rif_id_2,
                                         S.SAI_ROUTER_INTERFACE_ATTR_TYPE) == S.SAI_ROUTER_INTERFACE_TYPE_SUB_PORT
        assert pytest.tb.get_object_attr(pytest.tb.rif_id_2, S.SAI_ROUTER_INTERFACE_ATTR_OUTER_VLAN_ID) == pytest.top.vlan

    def test_rp_lag_to_rp(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac2) / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / \
            IP(src=pytest.top.neighbor_ip2, dst=pytest.top.neighbor_ip1, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip2, dst=pytest.top.neighbor_ip1, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.out_port, expected_out_pkt, pytest.top.in_port)


@pytest.fixture(scope="class")
def rif_sub_port_topology(base_v4_topology):
    pytest.tb.configure_ports([pytest.top.in_port_cfg, pytest.top.out_port_cfg])

    # configure rif 1 as SUB_PORT with bridge
    pytest.top.configure_bridge_port(pytest.top.vlan, pytest.top.in_port)
    pytest.tb.rif_id_1 = pytest.tb.create_router_interface(
        pytest.tb.virtual_router_id,
        pytest.top.in_port,
        S.SAI_ROUTER_INTERFACE_TYPE_SUB_PORT,
        pytest.tb.router_mac,
        VLAN)
    pytest.tb.create_route(
        pytest.tb.virtual_router_id,
        pytest.top.route_prefix1,
        pytest.top.route_prefix1_mask,
        pytest.top.tb.rif_id_1)
    pytest.tb.create_neighbor(pytest.tb.rif_id_1, pytest.top.neighbor_ip1, pytest.top.neighbor_mac1)
    pytest.tb.nh_id1 = pytest.tb.create_next_hop(pytest.top.neighbor_ip1, pytest.top.tb.rif_id_1)

    # configure rif 2 as SUB_PORT with bridge
    pytest.tb.rif_id_2 = pytest.tb.create_router_interface(
        pytest.tb.virtual_router_id,
        pytest.top.out_port,
        S.SAI_ROUTER_INTERFACE_TYPE_SUB_PORT,
        pytest.tb.router_mac,
        pytest.top.vlan)
    pytest.tb.create_route(
        pytest.tb.virtual_router_id,
        pytest.top.route_prefix2,
        pytest.top.route_prefix2_mask,
        pytest.top.tb.rif_id_2)
    pytest.tb.create_neighbor(pytest.tb.rif_id_2, pytest.top.neighbor_ip2, pytest.top.neighbor_mac2)
    pytest.tb.nh_id2 = pytest.tb.create_next_hop(pytest.top.neighbor_ip2, pytest.top.tb.rif_id_2)

    # default route
    pytest.tb.create_route(pytest.tb.virtual_router_id, pytest.top.default_ip, pytest.top.default_ip_mask, S.SAI_NULL_OBJECT_ID)
    pytest.tb.setup_vrf_punt_path(pytest.tb.virtual_router_id, pytest.top.local_ip1, pytest.top.full_mask)
    pytest.tb.setup_vrf_punt_path(pytest.tb.virtual_router_id, pytest.top.local_ip2, pytest.top.full_mask)

    pytest.top.configure_rif_loopback()

    yield

    pytest.top.deconfigure_rif_loopback()
    pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.local_ip1, pytest.top.full_mask)
    pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.local_ip2, pytest.top.full_mask)

    pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.default_ip, pytest.top.default_ip_mask)

    pytest.tb.remove_next_hop(pytest.tb.nh_id1)
    pytest.tb.remove_neighbor(pytest.tb.rif_id_1, pytest.top.neighbor_ip1)
    pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.route_prefix1, pytest.top.route_prefix1_mask)
    pytest.tb.remove_router_interface(pytest.tb.rif_id_1)

    pytest.tb.remove_next_hop(pytest.tb.nh_id2)
    pytest.tb.remove_neighbor(pytest.tb.rif_id_2, pytest.top.neighbor_ip2)
    pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.route_prefix2, pytest.top.route_prefix2_mask)
    pytest.tb.remove_router_interface(pytest.tb.rif_id_2)

    pytest.top.deconfigure_bridge_ports()

    pytest.tb.remove_ports()


@pytest.mark.usefixtures("rif_sub_port_topology")
class Test_sub_port():
    # neighbor1 -> neighbor2
    def test_route(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            Dot1Q(prio=0, vlan=VLAN) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # test route from neighbor2 -> neighbor1
        in_pkt2 = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac2) / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / \
            IP(src=pytest.top.neighbor_ip2, dst=pytest.top.neighbor_ip1, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt2 = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            Dot1Q(prio=0, vlan=VLAN) / \
            IP(src=pytest.top.neighbor_ip2, dst=pytest.top.neighbor_ip1, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt2, pytest.top.out_port, expected_out_pkt2, pytest.top.in_port)
