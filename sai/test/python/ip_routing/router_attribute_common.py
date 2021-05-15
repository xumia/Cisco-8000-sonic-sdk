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
from sai_test_utils import *
from scapy.all import *


class test_router_attributes():
    def test_object_type_query(self):
        type = S.sai_object_type_query(pytest.tb.nh_id1)
        assert type == S.SAI_OBJECT_TYPE_NEXT_HOP

    def test_set_get_rif_attr(self):
        assert pytest.tb.get_object_attr(pytest.tb.rif_id_1, S.SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE)
        assert pytest.tb.get_object_attr(pytest.tb.rif_id_1,
                                         S.SAI_ROUTER_INTERFACE_ATTR_PORT_ID) == pytest.tb.ports[pytest.top.in_port]
        assert pytest.tb.get_object_attr(pytest.tb.rif_id_1, S.SAI_ROUTER_INTERFACE_ATTR_TYPE) == S.SAI_ROUTER_INTERFACE_TYPE_PORT
        assert pytest.tb.get_object_attr(pytest.tb.rif_id_1,
                                         S.SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID) == pytest.tb.virtual_router_id

        mac_addr = "00:56:67:78:89:9a"
        pytest.tb.set_object_attr(pytest.tb.rif_id_1, S.SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS, mac_addr, verify=True)

    def test_set_get_neighbor_dst_mac(self):
        # assuming neighbor entry already created in topology
        ip_addr = U.sai_ip(pytest.top.neighbor_ip1)
        nbr = sai_neighbor_entry_t(pytest.tb.switch_id, pytest.tb.rif_id_1, ip_addr)
        mac_addr = "00:12:12:34:34:56"
        pytest.tb.set_object_attr([SAI_OBJECT_TYPE_NEIGHBOR_ENTRY, nbr],
                                  SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS, mac_addr, verify=True)

    def test_set_get_route_attr(self):
        route_entry = pytest.tb.create_route(
            pytest.tb.virtual_router_id,
            pytest.top.route_prefix3,
            pytest.top.route_prefix3_mask,
            pytest.tb.nh_id1)

        assert pytest.tb.get_object_attr(route_entry, S.SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION) == S.SAI_PACKET_ACTION_FORWARD
        pytest.tb.set_object_attr(route_entry, S.SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION, S.SAI_PACKET_ACTION_DROP, verify=True)
        pytest.tb.set_object_attr(route_entry, S.SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION, S.SAI_PACKET_ACTION_TRAP, verify=True)
        pytest.tb.set_object_attr(route_entry, S.SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION, S.SAI_PACKET_ACTION_FORWARD, verify=True)

        assert pytest.tb.get_object_attr(route_entry, S.SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID) == pytest.tb.nh_id1
        pytest.tb.set_object_attr(route_entry, S.SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID, pytest.tb.nh_id2, verify=True)

        # This is a bit ugly. We assume the route was created in somewhere in topology
        attr = S.sai_attribute_t(S.SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION, 0)
        ip_addr = U.sai_ip(pytest.top.route_prefix1)
        ip_mask = U.sai_ip(pytest.top.route_prefix1_mask)
        route_entry2 = [
            S.SAI_OBJECT_TYPE_ROUTE_ENTRY,
            S.sai_route_entry_t(
                pytest.tb.switch_id,
                pytest.tb.virtual_router_id,
                ip_addr,
                ip_mask)]
        assert pytest.tb.get_object_attr(route_entry2, S.SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION) == S.SAI_PACKET_ACTION_FORWARD

        # subnet added to interface can only have forward action so far
        with expect_sai_error(S.SAI_STATUS_NOT_IMPLEMENTED):
            pytest.tb.set_object_attr(route_entry2, S.SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION, S.SAI_PACKET_ACTION_DROP)

        pytest.tb.remove_object(route_entry)

    def test_get_next_hop_attr(self):
        assert pytest.tb.get_object_attr(pytest.tb.nh_id1, S.SAI_NEXT_HOP_ATTR_TYPE) == S.SAI_NEXT_HOP_TYPE_IP
        assert pytest.tb.get_object_attr(pytest.tb.nh_id1, S.SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID) == pytest.tb.rif_id_1
        assert pytest.tb.get_object_attr(pytest.tb.nh_id1, S.SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID) == pytest.tb.rif_id_1
        assert pytest.tb.get_object_attr(pytest.tb.nh_id1, S.SAI_NEXT_HOP_ATTR_IP) == pytest.top.neighbor_ip1


class test_router_mac_attr():

    def test_rif_and_vrf_mac_attr(self):
        pytest.tb.configure_ports([pytest.top.sw_port_cfg])
        # create router interface without mac
        # test without vrf mac and without rif mac
        pytest.tb.rif_id_3 = pytest.tb.create_router_interface(
            pytest.tb.virtual_router_id, pytest.top.sw_port, S.SAI_ROUTER_INTERFACE_TYPE_PORT, no_mac_addr = True)
        pytest.tb.create_route(
            pytest.tb.virtual_router_id,
            pytest.top.v4_route4_prefix,
            pytest.top.v4_route4_mask,
            pytest.tb.rif_id_3)
        pytest.tb.create_neighbor(pytest.tb.rif_id_3, pytest.top.neighbor_ip4, pytest.top.neighbor_mac4)
        pytest.tb.nh_id3 = pytest.tb.create_next_hop(pytest.top.neighbor_ip4, pytest.tb.rif_id_3)

        assert pytest.tb.get_object_attr(pytest.tb.virtual_router_id,
                                         S.SAI_VIRTUAL_ROUTER_ATTR_SRC_MAC_ADDRESS) == "00:00:00:00:00:00"

        assert pytest.tb.get_object_attr(pytest.tb.switch_id, S.SAI_SWITCH_ATTR_SRC_MAC_ADDRESS) == "00:01:02:03:04:05"

        assert pytest.tb.get_object_attr(pytest.tb.rif_id_3,
                                         S.SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS) == "00:01:02:03:04:05"

        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip4, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip4, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.sw_port, expected_out_pkt, pytest.top.out_port)

        # test with vrf mac and without rif mac
        mac_addr = "00:05:05:05:05:05"
        pytest.tb.set_object_attr(pytest.tb.virtual_router_id, S.SAI_VIRTUAL_ROUTER_ATTR_SRC_MAC_ADDRESS, mac_addr, verify=True)

        # check if rif mac is equal to the vrf mac
        assert pytest.tb.get_object_attr(pytest.tb.rif_id_3,
                                         S.SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS) == "00:05:05:05:05:05"

        in_pkt = Ether(dst="00:05:05:05:05:05", src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip4, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src="00:05:05:05:05:05") / \
            IP(src=pytest.top.neighbor_ip4, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.sw_port, expected_out_pkt, pytest.top.out_port)

        # set vrf mac with different mac
        mac_addr = "00:0a:0b:0c:0d:0e"
        pytest.tb.set_object_attr(pytest.tb.virtual_router_id, S.SAI_VIRTUAL_ROUTER_ATTR_SRC_MAC_ADDRESS, mac_addr, verify=True)

        # check if the rif src mac is set with the new vrf mac
        assert pytest.tb.get_object_attr(pytest.tb.rif_id_3, S.SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS) == "00:0a:0b:0c:0d:0e"

        # test with vrf mac and rif mac
        mac_addr = "00:56:67:78:89:9a"
        pytest.tb.set_object_attr(pytest.tb.rif_id_3, S.SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS, mac_addr, verify=True)

        in_pkt = Ether(dst="00:56:67:78:89:9a", src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip4, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src="00:0a:0b:0c:0d:0e") / \
            IP(src=pytest.top.neighbor_ip4, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.sw_port, expected_out_pkt, pytest.top.out_port)

        # deconfigure objects created
        pytest.tb.remove_next_hop(pytest.tb.nh_id3)
        pytest.tb.remove_neighbor(pytest.tb.rif_id_3, pytest.top.neighbor_ip4)
        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.v4_route4_prefix, pytest.top.v4_route4_mask)
        pytest.tb.remove_router_interface(pytest.tb.rif_id_3)
