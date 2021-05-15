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
from acl_ipv4_tests import *

# This test module covers following test cases to exercise and verify ACL UDK capabilities.
#   1. Ingress ACL test with single UDK field set all sourced from packet defined
#      at switch create time.
#   2. Ingress ACL test with two UDK field set for v4 traffic all sourced from packet defined
#      at switch create time. The second set is subset of first match field set.
#   3. Ingress ACL test with two UDK field set for v4 traffic all sourced from packet defined
#      at switch create time. The second set is superset of first match field set.
#


@pytest.mark.usefixtures("basic_route_v4_topology_with_udk_profiles")
class Test_acl_udk_with_switch_binding_rif_add_delete():
    def test_ingress_ipv4_acl_table(self):
        aclTestInstance = aclTests()
        aclTestInstance.ingress_ipv4_acl_table_udk_test(switch_binding=True, add_delete_port=True)
