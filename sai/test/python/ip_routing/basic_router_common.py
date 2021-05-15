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
from sai_test_utils import *
import sai_packet_utils as U


class test_basic_route():

    def check_next_hop_group_member_list(self, nh_group, nh_list = []):
        mem_list = sai_object_list_t([])
        attr = sai_attribute_t(SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_MEMBER_LIST, mem_list)
        with expect_sai_error(SAI_STATUS_BUFFER_OVERFLOW):
            pytest.tb.apis[SAI_API_NEXT_HOP_GROUP].get_next_hop_group_attribute(nh_group, 1, attr)
        assert attr.value.objlist.count == len(nh_list)
        mem_list = sai_object_list_t([0] * attr.value.objlist.count)
        attr = sai_attribute_t(SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_MEMBER_LIST, mem_list)
        pytest.tb.apis[SAI_API_NEXT_HOP_GROUP].get_next_hop_group_attribute(nh_group, 1, attr)
        for nh_mem in attr.value.objlist.to_pylist():
            nh = pytest.tb.get_object_attr(nh_mem, SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID)
            assert (nh in nh_list)

    def print_rif_stats(self, tb):
        if tb.debug_log:
            tb.get_router_interface_stats(tb.rif_id_1, dump=True)
            tb.get_router_interface_stats(tb.rif_id_2, dump=True)

    def common_test_admin_attr(self, in_pkt, expected_out_pkt, ip_type):
        if ip_type == "v4":
            router_interface_admin_attr = SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE
            virtual_router_admin_attr = SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE
            other_router_interface_admin_attr = SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE
            other_virtual_router_admin_attr = SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE
        else:
            router_interface_admin_attr = SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE
            virtual_router_admin_attr = SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE
            other_router_interface_admin_attr = SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE
            other_virtual_router_admin_attr = SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # Set router interface admin state down. Packets should be dropped.
        pytest.tb.set_object_attr(pytest.tb.rif_id_1, router_interface_admin_attr, False)
        try:
            U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)
            assert False  # run_and_compare should fail. We should not get here
        except BaseException:
            pass

        # Set router interface admin state up. Test should pass
        pytest.tb.set_object_attr(pytest.tb.rif_id_1, router_interface_admin_attr, True)
        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # Set virtual router admin state down. Packets should be dropped
        pytest.tb.set_object_attr(pytest.tb.virtual_router_id, virtual_router_admin_attr, False)
        try:
            U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)
            assert False  # run_and_compare should fail. We should not get here
        except BaseException:
            pass

        # Set virtual router admin state up. Put other protocol type to down. Test should pass
        pytest.tb.set_object_attr(pytest.tb.virtual_router_id, virtual_router_admin_attr, True)
        pytest.tb.set_object_attr(pytest.tb.virtual_router_id, other_virtual_router_admin_attr, False)
        pytest.tb.set_object_attr(pytest.tb.rif_id_1, other_router_interface_admin_attr, False)
        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

    def common_test_route_neighbor_mac_change(self, in_pkt1, in_pkt2, in_pkt3, expected_out_pkt, mac1, mac2, mac3):
        # Test1: Change neighbor mac and test route
        ip_addr = U.sai_ip(pytest.top.neighbor_ip1)
        nbr = [SAI_OBJECT_TYPE_NEIGHBOR_ENTRY, sai_neighbor_entry_t(pytest.tb.switch_id, pytest.tb.rif_id_1, ip_addr)]
        new_neigh_mac_addr = mac1
        pytest.tb.set_object_attr(nbr, SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS, new_neigh_mac_addr, verify=True)

        U.run_and_compare(self, in_pkt1, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)
        self.print_rif_stats(pytest.tb)

        # Test2: Remove neighbor entry, verify dst mac setter and test route
        pytest.tb.remove_neighbor(pytest.tb.rif_id_1, pytest.top.neighbor_ip1)
        new_neigh_mac_addr = mac2
        pytest.tb.set_object_attr(nbr, SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS, new_neigh_mac_addr, verify=True)

        U.run_and_compare(self, in_pkt2, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)
        self.print_rif_stats(pytest.tb)

        # Remove the neighbor host entry that was created as part of setter call and readd using create api
        pytest.tb.remove_neighbor(pytest.tb.rif_id_1, pytest.top.neighbor_ip1)
        pytest.tb.create_neighbor(pytest.tb.rif_id_1, pytest.top.neighbor_ip1, pytest.top.neighbor_mac1)

        # Test3: Remove next hop and verify mac setter
        pytest.tb.remove_next_hop(pytest.tb.nh_id1)
        new_neigh_mac_addr = mac3
        pytest.tb.set_object_attr(nbr, SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS, new_neigh_mac_addr, verify=True)
        # readd next hop
        pytest.tb.nh_id1 = pytest.tb.create_next_hop(pytest.top.neighbor_ip1, pytest.tb.rif_id_1)

        # Test3: revert to original mac and test route
        new_neigh_mac_addr = pytest.top.neighbor_mac1
        pytest.tb.set_object_attr(nbr, SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS, new_neigh_mac_addr, verify=True)

        U.run_and_compare(self, in_pkt3, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)
        self.print_rif_stats(pytest.tb)
