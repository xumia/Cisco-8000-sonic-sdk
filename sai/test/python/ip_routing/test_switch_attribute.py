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
import sai_test_utils as st_utils

ATTR_VALUE = 1024
ATTR_VALUE_2 = 16
AGING_TIME = 0
MAX_ACL_ENTRY = 10000
MIN_ACL_ENTRY = 0
NO_OF_QUEUES = 8


@pytest.mark.usefixtures("basic_route_v4_topology")
class Test_switch_attributes():

    def test_topology_config(self):
        pytest.top.deconfigure_basic_route_topology()
        pytest.top.configure_basic_route_topology()
        pytest.top.deconfigure_basic_route_topology()
        pytest.top.configure_basic_route_topology()

    def test_acl_entry_min_priority(self):
        attr = pytest.tb.get_acl_entry_min_priority()
        assert MIN_ACL_ENTRY == attr

    def test_acl_entry_max_priority(self):
        attr = pytest.tb.get_acl_entry_max_priority()
        assert MAX_ACL_ENTRY == attr

    def test_get_set_fdb_aging_time(self):
        attr = pytest.tb.get_fdb_aging_time()
        assert AGING_TIME == attr

        pytest.tb.set_fdb_aging_time(300)
        attr = pytest.tb.get_fdb_aging_time()
        assert 300 == attr

    def test_ecmp_default_hash_seed(self):
        # const uint64_t NPL_LB_CRC_INITIAL_VEC = 0xffff -- default hash seed
        attr = pytest.tb.get_ecmp_default_hash()
        assert 0xffff == attr

    def test_lag_default_hash_seed(self):
        # m_spa_hash_seed(NPL_LB_CRC_INITIAL_VEC) -- default hash seed
        attr = pytest.tb.get_lag_default_hash()
        assert 0xffff == attr

    def test_switch_number_of_queues_getter(self):
        attr = pytest.tb.get_number_of_queues()
        assert NO_OF_QUEUES == attr

        attr = pytest.tb.get_number_of_unicast_queues()
        assert 0 == attr

        attr = pytest.tb.get_number_of_multicast_queues()
        assert 0 == attr

        attr = pytest.tb.get_number_of_cpu_queues()
        assert NO_OF_QUEUES == attr
