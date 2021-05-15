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
from sai_test_utils import *
from acl_ipv4_tests import *

# This test module covers following test cases to exercise and verify ACL l3 dest route meta data capabilities.
#   1. Ingress ACL test with host route meta data and lpm route meta data configured as UDK fields
#      along with other set of acl fields sourced from packet at switch create time.


@pytest.mark.usefixtures("basic_route_v4_topology_with_l3_dest_user_meta_udk_acl")
@pytest.mark.skipif(not is_asic_env_gibraltar(), reason="The test applicable only on gibraltar and later asics")
class Test_acl_udk_user_meta_l3_neighbor():
    def test_ingress_ipv4_acl_l3_dest_user_meta_in_em(self):
        aclTestInstance = aclTests()
        aclTestInstance.ingress_ipv4_acl_udk_l3_dst_metadata_test_in_em()
