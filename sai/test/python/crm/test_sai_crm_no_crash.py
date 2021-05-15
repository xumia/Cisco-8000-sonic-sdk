# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import unittest
import sai_topology as topology
import saicli as S

# the follow tests ensure that a value of 100 is returned from
# score based available attributes, these attributes either need
# backing in the simulator to return values (CENTRAL_EM) or
# a method to bulk add entries (LPM/routes)


@pytest.mark.usefixtures("basic_route_v4_topology")
class Test_crm_route_usage_v4(unittest.TestCase):

    pytest.nsim_accurate = True

    def test_get_ipv4_route_entry(self):
        prev_v4_available = pytest.tb.get_ipv4_route_available_entry()
        pytest.tb.create_route(pytest.tb.virtual_router_id, pytest.top.route4_prefix, pytest.top.route4_mask, pytest.tb.nh_id2)
        pytest.tb.create_route(pytest.tb.virtual_router_id, pytest.top.route3_prefix, pytest.top.route3_mask, pytest.tb.nh_id1)
        current_v4_available = pytest.tb.get_ipv4_route_available_entry()
        self.assertLessEqual(current_v4_available, prev_v4_available)
        prev_v4_available = current_v4_available
        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.route3_prefix, pytest.top.route3_mask)
        current_v4_available = pytest.tb.get_ipv4_route_available_entry()
        self.assertGreaterEqual(current_v4_available, prev_v4_available)
        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.route4_prefix, pytest.top.route4_mask)

    def test_get_ipv4_neighbor_entry(self):
        attr = pytest.tb.get_ipv4_neighbor_available_entry()
        assert S.SAI_MAX_CEM_HACK  == attr


@pytest.mark.usefixtures("basic_route_v6_topology")
class Test_crm_route_usage_v6(unittest.TestCase):

    def test_ipv6_route_entry(self):
        prev_v6_available = pytest.tb.get_ipv6_route_available_entry()
        pytest.tb.create_route(
            pytest.tb.virtual_router_id,
            pytest.top.v6_route3_prefix,
            pytest.top.v6_route3_mask,
            pytest.tb.nh_id1)
        pytest.tb.create_route(
            pytest.tb.virtual_router_id,
            pytest.top.v6_route4_prefix,
            pytest.top.v6_route4_mask,
            pytest.tb.nh_id2)

        current_v6_available = pytest.tb.get_ipv6_route_available_entry()
        self.assertLessEqual(current_v6_available, prev_v6_available)
        prev_v6_available = current_v6_available

        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.v6_route3_prefix, pytest.top.v6_route3_mask)
        current_v6_available = pytest.tb.get_ipv6_route_available_entry()
        self.assertGreaterEqual(current_v6_available, prev_v6_available)

        pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.v6_route4_prefix, pytest.top.v6_route4_mask)

    def test_ipv6_neighbor_entry(self):
        attr = pytest.tb.get_ipv6_neighbor_available_entry()
        assert S.SAI_MAX_CEM_HACK == attr


@pytest.mark.usefixtures("dot1q_bridge_v4_topology")
class Test_crm_route_usage_fdb(unittest.TestCase):

    def test_get_fdb_entry(self):
        prev_fdb_available = pytest.tb.get_fdb_available_entry()
        pytest.tb.create_fdb_entry(pytest.tb.vlans[pytest.top.vlan],
                                   pytest.top.svi_dst_neighbor_mac,
                                   pytest.tb.bridge_ports[pytest.top.in_port])
        pytest.tb.create_fdb_entry(pytest.tb.vlans[pytest.top.vlan],
                                   pytest.top.svi_dst_host1,
                                   pytest.tb.bridge_ports[pytest.top.in_port])
        pytest.tb.create_fdb_entry(pytest.tb.vlans[pytest.top.vlan], pytest.top.svi_acc_host,
                                   pytest.tb.bridge_ports[pytest.top.in_port])

        current_fdb_available = pytest.tb.get_fdb_available_entry()
        self.assertLessEqual(current_fdb_available, prev_fdb_available)
        prev_fdb_available = current_fdb_available

        pytest.tb.remove_fdb_entry(pytest.tb.vlans[pytest.top.vlan], pytest.top.svi_dst_neighbor_mac)
        current_fdb_entry = pytest.tb.get_fdb_available_entry()
        self.assertGreaterEqual(current_fdb_available, prev_fdb_available)

        pytest.tb.remove_fdb_entry(pytest.tb.vlans[pytest.top.vlan], pytest.top.svi_dst_host1)
        pytest.tb.remove_fdb_entry(pytest.tb.vlans[pytest.top.vlan], pytest.top.svi_acc_host)


if __name__ == '__main__':
    unittest.main()
