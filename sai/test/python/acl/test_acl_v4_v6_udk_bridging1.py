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
from sai_test_utils import *

# This test module covers following test cases to exercise and verify ACL UDK capabilities.
#   1. Ingress ACL test with UDK field set, all sourced from packet and defined
#      at switch create time. One or more packet fields that are not part of default
#      ACL field set are added as UDF field.
#   2. Five ACL profiles at switch create time are tested. Function create_l2_v4_v6_udk_acl_profiles()
#      returns one profile at a time until all 5 profiles are tested.
#        a) Profile 1 tests with L2, L3 (v4 hdr fields) and L4
#        b) Profile 2 tests with L2, L3 (v4 hdr fields and V6 header field) and L4
#           In this, SAI is expected to convert single SAI ACL table with both v4 and v6 fields
#           into two SDK tables. Each v4 and v6 table is looked up as both test cases use
#           both v4 and v6 packet.
#        c) Profile 3 with V6 header fields and TTL. This will ensure TTL is part of match criteria
#           when v6 packet is processed.
#        d) Profile 4 with V4 header fields and TTL. This will ensure TTL is part of match criteria
#           when v4 packet is processed.
#        e) Profile 5 with only TTL. This will ensure TTL is part of match criteria as well as
#           two SDK tables one for V4 and V6 (that uses HOP_LIMIT) are created. For respective
#           packets, TTL/HOP_LIMIT should influence match condition and packet processing.
#


# Note: With RTF each test scenarios with different UDK match profiles have to be run
#      as seperate instance because, RTF ACL does not allow dynamic ACL table
#      create, delete, followed by create again.

@pytest.mark.usefixtures("basic_switching_with_udk_profiles")
@pytest.mark.skipif(not is_asic_env_gibraltar(), reason="The test applicable only on gibraltar and later asics")
class Test_acl_custom_udk_bind_to_port():
    def test_ingress_mac_fwding_v4_v6_acl_udk(self):
        '''
            L2 fwding with RTF ACL using l2,L3, L4 fields. Both ACL match performed with v4 and v6 packets
            ACL attached to port.
        '''
        udk_fields_used = pytest.tb.get_object_attr(pytest.tb.switch_id, SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST)
        assert len(set(udk_fields_used) - set(create_v4_custom_udk_acl_profiles()[0])) >= 0
        aclTestInstance = aclTests()
        aclTestInstance.ingress_mac_fwding_v4_v6_acl_udk_test()
