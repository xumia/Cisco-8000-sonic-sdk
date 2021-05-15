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
from acl_udk_profiles import *

# This test module covers following test cases to exercise and verify ACL UDK capabilities.
#   1. Ingress ACL test with single UDK field set all sourced from packet defined
#      at switch create time. One or more packet fields that are not part of default
#      ACL match capability are added as UDF field.
#


@pytest.mark.usefixtures("basic_route_v4_topology_with_custom_udk_profiles")
class Test_acl_custom_udk_switch_binding():
    def test_ingress_ipv4_acl_table(self):
        udk_fields_used = pytest.tb.get_object_attr(pytest.tb.switch_id, SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST)
        assert len(set(udk_fields_used) - set(create_v4_custom_udk_acl_profiles()[0])) >= 0
        aclTestInstance = aclTests()
        aclTestInstance.ingress_ipv4_acl_table_custom_udk_test(switch_binding=True)
