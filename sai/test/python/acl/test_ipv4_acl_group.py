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
from acl_group_tests import *


@pytest.mark.usefixtures("basic_route_v4_topology")
class Test_acl_group():

    def test_ingress_acl_table_group(self):
        group_tests = acl_group_tests()
        group_tests.ingress_acl_table_group_test()

    def test_egress_acl_table_group(self):
        group_tests = acl_group_tests()
        group_tests.egress_acl_table_group_test()


@pytest.mark.usefixtures("basic_route_v4_topology")
class Test_acl_group_with_switch_binding():

    def test_ingress_acl_table_group(self):
        group_tests = acl_group_tests()
        group_tests.ingress_acl_table_group_test(switch_acl_attachment=True)

    def test_egress_acl_table_group(self):
        group_tests = acl_group_tests()
        group_tests.egress_acl_table_group_test(switch_acl_attachment=True)


@pytest.mark.usefixtures("basic_route_v4_topology")
class Test_acl_group_with_switch_binding_rif_add_delete():

    def test_ingress_acl_table_group(self):
        group_tests = acl_group_tests()
        group_tests.ingress_acl_table_group_test(switch_acl_attachment=True, add_delete_port=True)

    def test_egress_acl_table_group(self):
        group_tests = acl_group_tests()
        group_tests.egress_acl_table_group_test(switch_acl_attachment=True, add_delete_port=True)
