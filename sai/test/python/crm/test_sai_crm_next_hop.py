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
from sai_crm_next_hop import *


@pytest.mark.usefixtures("basic_route_v4_topology")
class Test_crm_v4_next_hop(Crm_next_hop_base):

    pytest.nsim_accurate = True

    def test_crm_ipv4_next_hop(self, finalizer):
        clean = self._clean(finalizer)
        entries = 30
        max_available = pytest.tb.get_ipv4_nexthop_entry_available()
        self._generate_nexthops(entries, "v4", clean)
        current_available = pytest.tb.get_ipv4_nexthop_entry_available()
        assert (max_available - current_available) == entries

    def test_crm_ipv4_next_hop_group(self, finalizer):
        clean = self._clean(finalizer)
        entries = 30
        max_available = pytest.tb.get_next_hop_group_entry_available()
        max_member_available = pytest.tb.get_next_hop_group_member_entry_available()

        self._generate_nexthops(entries, "v4", clean)

        for i in range(entries):
            self._generate_next_hop_group(clean)

        nh_itr = iter(clean.next_hops)
        for group in clean.groups:
            self._generate_next_hop_group_member(group, next(nh_itr), 1, clean)

        self._create_routes_based_on_groups(clean)

        current_available = pytest.tb.get_next_hop_group_entry_available()
        current_member_available = pytest.tb.get_next_hop_group_member_entry_available()
        assert (max_available - current_available) == entries
        assert (max_member_available - current_member_available) == entries


@pytest.mark.usefixtures("basic_route_v6_topology")
class Test_crm_v6_next_hop(Crm_next_hop_base):

    pytest.nsim_accurate = True

    def test_crm_ipv6_next_hop(self, finalizer):
        clean = self._clean(finalizer)
        entries = 30
        max_available = pytest.tb.get_ipv6_nexthop_entry()
        self._generate_nexthops(entries, "v6", clean)
        current_available = pytest.tb.get_ipv6_nexthop_entry()
        assert (max_available - current_available) == entries
