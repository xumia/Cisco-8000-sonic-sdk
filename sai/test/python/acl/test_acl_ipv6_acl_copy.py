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
from acl_ipv6_tests import *


@pytest.mark.usefixtures("basic_route_v6_topology")
class Test_acl_copy():
    def test_ingress_ipv6_acl_copy(self):
        aclTestInstance = aclTests()
        aclTestInstance.ingress_ipv6_acl_copy()


@pytest.mark.usefixtures("basic_route_v6_topology")
class Test_switch_attachment_acl():
    def test_ingress_ipv6_acl_copy_switch_binding(self):
        aclTestInstance = aclTests()
        aclTestInstance.ingress_ipv6_acl_copy(switch_binding=True)
