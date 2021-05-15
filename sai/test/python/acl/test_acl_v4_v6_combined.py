#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import acl_ipv4_tests as acl_ipv4_tests
import acl_ipv6_tests as acl_ipv6_tests


@pytest.mark.usefixtures("basic_route_v4_topology")
class Test_combined_v4_acl():
    def test_v4acl_ingress_v4_v6_combined_acl_table(self):
        aclTestInstance = acl_ipv4_tests.aclTests()
        aclTestInstance.ingress_v4_v6_acl_table_test()

    def test_v4acl_egress_v4_v6_combined_acl_table(self):
        aclTestInstance = acl_ipv4_tests.aclTests()
        aclTestInstance.egress_v4_v6_acl_table_test()

    def test_v4acl_switch_bound_ingress_v4_v6_combined_acl_table_add_delete_port(self):
        aclTestInstance = acl_ipv4_tests.aclTests()
        aclTestInstance.ingress_v4_v6_acl_table_test(switch_binding=True, add_delete_port=True)

    def test_v4acl_switch_bound_egress_v4_v6_combined_acl_table_add_delete_port(self):
        aclTestInstance = acl_ipv4_tests.aclTests()
        aclTestInstance.egress_v4_v6_acl_table_test(switch_binding=True, add_delete_port=True)

    def test_v4_and_v6_switch_bound_ingress_combined_acl_table_add_delete_port(self):
        '''
            Test installing V6 header field and other match fiele rule into V6 SDK table
            does not create a V4 SDK ACL table hit for v4 packet.
        '''
        aclTestInstance = acl_ipv4_tests.aclTests()
        aclTestInstance.ingress_v4_v6_acl_table_both_key_test(switch_binding=True, add_delete_port=True)


@pytest.mark.usefixtures("basic_route_v6_topology")
class Test_combined_v6_acl():
    def test_v6acl_ingress_v4_v6_combined_acl_table(self):
        aclTestInstance = acl_ipv6_tests.aclTests()
        aclTestInstance.ingress_v4_v6_acl_table_test()

    def test_v6acl_egress_v4_v6_acl_table(self):
        aclTestInstance = acl_ipv6_tests.aclTests()
        aclTestInstance.egress_v4_v6_acl_table_test()

    def test_v6acl_switch_bound_ingress_v4_v6_combined_acl_table_add_delete_port(self):
        aclTestInstance = acl_ipv6_tests.aclTests()
        aclTestInstance.ingress_v4_v6_acl_table_test(switch_binding=True, add_delete_port=True)

    def test_v6acl_switch_bound_egress_v4_v6_combined_acl_table_add_delete_port(self):
        aclTestInstance = acl_ipv6_tests.aclTests()
        aclTestInstance.egress_v4_v6_acl_table_test(switch_binding=True, add_delete_port=True)
