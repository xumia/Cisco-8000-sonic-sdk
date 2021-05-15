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
from sai_test_utils import *

ATTR_VALUE = 1024
ATTR_VALUE_2 = 16
AGING_TIME = 300
MAX_ACL_ENTRY = 10000
MIN_ACL_ENTRY = 0


@pytest.mark.usefixtures("basic_route_v4_topology")
class Test_route_attribute_change():

    def test_route_no_next_hop(self):
        pytest.tb.create_route(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            None,
            S.SAI_PACKET_ACTION_DROP)
        action = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION)
        assert action == S.SAI_PACKET_ACTION_DROP

        pytest.tb.set_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION,
            S.SAI_PACKET_ACTION_FORWARD)
        action = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION)
        assert action == S.SAI_PACKET_ACTION_FORWARD

        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.route4_prefix, pytest.top.route4_mask)

    def test_route_punt_actions(self):
        pytest.tb.setup_vrf_punt_path(pytest.tb.virtual_router_id, pytest.top.route4_prefix, pytest.top.route4_mask)

        action = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION)
        assert action == S.SAI_PACKET_ACTION_FORWARD

        pytest.tb.set_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION,
            S.SAI_PACKET_ACTION_DROP)
        action = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION)
        assert action == S.SAI_PACKET_ACTION_DROP

        # next hop is cpu port, set to trap is meaningless
        # for now the get for this situation is forwarding
        pytest.tb.set_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION,
            S.SAI_PACKET_ACTION_TRAP)
        action = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION)
        assert action == S.SAI_PACKET_ACTION_FORWARD

        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.route4_prefix, pytest.top.route4_mask)

    def test_route_rif_actions(self):
        # sonic test case, create
        pytest.tb.create_route(pytest.tb.virtual_router_id, pytest.top.route4_prefix, pytest.top.route4_mask, pytest.tb.rif_id_1)

        # set next hop to the same next hop id as create return success
        pytest.tb.set_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID,
            pytest.tb.rif_id_1)

        # create next hop to the same next hop id as create return already exists
        with expect_sai_error(S.SAI_STATUS_ITEM_ALREADY_EXISTS):
            pytest.tb.create_route(
                pytest.tb.virtual_router_id,
                pytest.top.route4_prefix,
                pytest.top.route4_mask,
                pytest.tb.rif_id_1)

        action = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION)
        assert action == S.SAI_PACKET_ACTION_FORWARD

        with expect_sai_error(S.SAI_STATUS_NOT_IMPLEMENTED):
            pytest.tb.set_route_attribute(
                pytest.tb.virtual_router_id,
                pytest.top.route4_prefix,
                pytest.top.route4_mask,
                S.SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION,
                S.SAI_PACKET_ACTION_DROP)

        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.route4_prefix, pytest.top.route4_mask)

    def test_route_nh_actions(self):
        pytest.tb.create_route(pytest.tb.virtual_router_id, pytest.top.route4_prefix, pytest.top.route4_mask, pytest.tb.nh_id1)

        action = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION)
        assert action == S.SAI_PACKET_ACTION_FORWARD

        pytest.tb.set_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION,
            S.SAI_PACKET_ACTION_DROP)
        action = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION)
        assert action == S.SAI_PACKET_ACTION_DROP
        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.route4_prefix, pytest.top.route4_mask)

    def test_route_nexthop_rif_cpu(self):
        pytest.tb.create_route(pytest.tb.virtual_router_id, pytest.top.route4_prefix, pytest.top.route4_mask, pytest.tb.rif_id_1)
        nh = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID)
        assert nh == pytest.tb.rif_id_1

        with expect_sai_error(S.SAI_STATUS_NOT_IMPLEMENTED):
            pytest.tb.set_route_attribute(
                pytest.tb.virtual_router_id,
                pytest.top.route4_prefix,
                pytest.top.route4_mask,
                S.SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID,
                pytest.tb.cpu_port)

        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.route4_prefix, pytest.top.route4_mask)

    def test_route_nexthop_rif_nh(self):
        pytest.tb.create_route(pytest.tb.virtual_router_id, pytest.top.route4_prefix, pytest.top.route4_mask, pytest.tb.nh_id1)
        nh = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID)
        assert nh == pytest.tb.nh_id1

        pytest.tb.set_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route3_prefix,
            pytest.top.route3_mask,
            S.SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID,
            pytest.tb.rif_id_1)

        pytest.tb.set_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID,
            pytest.tb.nh_id1)
        nh = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID)
        assert nh == pytest.tb.nh_id1
        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.route4_prefix, pytest.top.route4_mask)

    def test_route_nexthop_cpu_nh(self):
        pytest.tb.setup_vrf_punt_path(pytest.tb.virtual_router_id, pytest.top.route4_prefix, pytest.top.route4_mask)
        nh = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID)
        assert nh == pytest.tb.cpu_port

        pytest.tb.set_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID,
            pytest.tb.nh_id1)
        nh = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID)
        assert nh == pytest.tb.nh_id1

        pytest.tb.set_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID,
            pytest.tb.cpu_port)
        nh = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID)
        assert nh == pytest.tb.cpu_port
        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.route4_prefix, pytest.top.route4_mask)

    def test_route_user_meta_get_set(self):
        skipIf(not pytest.tb.is_gb)
        route_user_meta_range = pytest.tb.get_object_attr(pytest.tb.switch_id, S.SAI_SWITCH_ATTR_ROUTE_DST_USER_META_DATA_RANGE)
        assert route_user_meta_range == [1, 255]
        neighbor_user_meta_range = pytest.tb.get_object_attr(
            pytest.tb.switch_id, S.SAI_SWITCH_ATTR_NEIGHBOR_DST_USER_META_DATA_RANGE)
        assert neighbor_user_meta_range == [1, 15]
        pytest.tb.create_route(pytest.tb.virtual_router_id, pytest.top.route4_prefix, pytest.top.route4_mask, pytest.tb.nh_id1)
        pytest.tb.set_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_META_DATA,
            100)
        meta_data = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_META_DATA)
        assert meta_data == 100
        pytest.tb.set_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_META_DATA,
            200)
        meta_data = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_META_DATA)
        assert meta_data == 200
        pytest.tb.set_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_META_DATA,
            0)
        meta_data = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_META_DATA)
        assert meta_data == 0
        pytest.tb.set_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_META_DATA,
            255)
        meta_data = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_META_DATA)
        assert meta_data == 255
        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.route4_prefix, pytest.top.route4_mask)

    def test_route_create_with_user_meta(self):
        skipIf(not pytest.tb.is_gb)
        pytest.tb.create_route(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            pytest.tb.nh_id1,
            user_meta=100)
        meta_data = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_META_DATA)
        assert meta_data == 100
        pytest.tb.set_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_META_DATA,
            255)
        meta_data = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_META_DATA)
        assert meta_data == 255

        # Out of range case.
        try:
            pytest.tb.set_route_attribute(
                pytest.tb.virtual_router_id,
                pytest.top.route4_prefix,
                pytest.top.route4_mask,
                S.SAI_ROUTE_ENTRY_ATTR_META_DATA,
                256)
        except Exception as e:
            meta_data = pytest.tb.get_route_attribute(
                pytest.tb.virtual_router_id,
                pytest.top.route4_prefix,
                pytest.top.route4_mask,
                S.SAI_ROUTE_ENTRY_ATTR_META_DATA)
        assert meta_data != 256
        assert meta_data == 255
        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.route4_prefix, pytest.top.route4_mask)

    def test_route_with_user_meta_change_next_hop(self):
        skipIf(not pytest.tb.is_gb)
        pytest.tb.create_route(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            pytest.tb.nh_id1,
            user_meta=100)
        pytest.tb.set_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID,
            pytest.tb.nh_id2)
        meta_data = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.route4_prefix,
            pytest.top.route4_mask,
            S.SAI_ROUTE_ENTRY_ATTR_META_DATA)
        assert meta_data == 100
        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.route4_prefix, pytest.top.route4_mask)

    def test_host_route_user_meta_get_set(self):
        skipIf(not pytest.tb.is_gb)
        # topology has already configured nexthop and neighbor. Remove it and created with user-meta
        pytest.tb.remove_neighbor(pytest.tb.rif_id_1, pytest.top.neighbor_ip1)
        pytest.tb.create_neighbor(pytest.tb.rif_id_1, pytest.top.neighbor_ip1, pytest.top.neighbor_mac1)
        ip_addr = U.sai_ip(pytest.top.neighbor_ip1)
        neighbor = [SAI_OBJECT_TYPE_NEIGHBOR_ENTRY, sai_neighbor_entry_t(pytest.tb.switch_id, pytest.tb.rif_id_1, ip_addr)]
        meta_data = pytest.tb.get_object_attr(neighbor, S.SAI_NEIGHBOR_ENTRY_ATTR_META_DATA)
        assert meta_data == 0  # LA_CLASS_ID_DEFAULT

        meta_data = 10
        pytest.tb.set_object_attr(neighbor, S.SAI_NEIGHBOR_ENTRY_ATTR_META_DATA, meta_data)
        installed_meta_data = pytest.tb.get_object_attr(neighbor, S.SAI_NEIGHBOR_ENTRY_ATTR_META_DATA)
        assert meta_data == installed_meta_data

        meta_data = 15
        pytest.tb.set_object_attr(neighbor, S.SAI_NEIGHBOR_ENTRY_ATTR_META_DATA, meta_data)
        installed_meta_data = pytest.tb.get_object_attr(neighbor, S.SAI_NEIGHBOR_ENTRY_ATTR_META_DATA)
        assert meta_data == installed_meta_data

        # Out of range case.
        meta_data = 16
        try:
            pytest.tb.set_object_attr(neighbor, S.SAI_NEIGHBOR_ENTRY_ATTR_META_DATA, meta_data)
        except Exception as e:
            installed_meta_data = pytest.tb.get_object_attr(neighbor, S.SAI_NEIGHBOR_ENTRY_ATTR_META_DATA)
        assert meta_data != installed_meta_data
        assert 15 == installed_meta_data

    def test_host_route_with_user_meta(self):
        skipIf(not pytest.tb.is_gb)
        # topology has already configured nexthop and neighbor. Remove it and created with user-meta
        pytest.tb.remove_neighbor(pytest.tb.rif_id_1, pytest.top.neighbor_ip1)
        pytest.tb.create_neighbor(pytest.tb.rif_id_1, pytest.top.neighbor_ip1, pytest.top.neighbor_mac1, user_meta=9)
        ip_addr = U.sai_ip(pytest.top.neighbor_ip1)
        neighbor = [SAI_OBJECT_TYPE_NEIGHBOR_ENTRY, sai_neighbor_entry_t(pytest.tb.switch_id, pytest.tb.rif_id_1, ip_addr)]
        meta_data = pytest.tb.get_object_attr(neighbor, S.SAI_NEIGHBOR_ENTRY_ATTR_META_DATA)
        assert meta_data == 9

        meta_data = 10
        pytest.tb.set_object_attr(neighbor, S.SAI_NEIGHBOR_ENTRY_ATTR_META_DATA, meta_data)
        installed_meta_data = pytest.tb.get_object_attr(neighbor, S.SAI_NEIGHBOR_ENTRY_ATTR_META_DATA)
        assert meta_data == installed_meta_data
