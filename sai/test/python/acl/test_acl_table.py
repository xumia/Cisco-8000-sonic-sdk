#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
from acl_table_tests import *


@pytest.mark.usefixtures("basic_route_v4_one_port_topology")
class Test_acl_table():
    aclTable = acl_table_tests()

    def test_table_create_no_attrs(self):
        with expect_sai_error(SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING):
            table_obj = self.aclTable.create_table({})

    def test_table_create_no_stage(self):
        args = {}
        args[SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6] = True
        with expect_sai_error(SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING):
            table_obj = self.aclTable.create_table(args)

    def test_table_create_no_field(self):
        args = {}
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        with expect_sai_error(SAI_STATUS_FAILURE):
            table_obj = self.aclTable.create_table(args)

    def test_table_create_1_field_l4_sport(self):
        table_obj = self.aclTable.create_table_1_field(SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT)
        pytest.tb.remove_object(table_obj)

    def test_table_create_1_field_l4_dport(self):
        table_obj = self.aclTable.create_table_1_field(SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT)
        pytest.tb.remove_object(table_obj)

    def test_table_create_1_field_range_sport(self):
        types = [SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE]
        table_obj = self.aclTable.create_table_1_field(SAI_ACL_TABLE_ATTR_FIELD_ACL_RANGE_TYPE, types)

        # Verify that this doesn't imply SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT
        assert pytest.tb.get_object_attr(table_obj, SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT) == False

        pytest.tb.remove_object(table_obj)

    def test_table_create_1_field_range_dport(self):
        types = [SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE]
        table_obj = self.aclTable.create_table_1_field(SAI_ACL_TABLE_ATTR_FIELD_ACL_RANGE_TYPE, types)

        # Verify that this doesn't imply SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT
        assert pytest.tb.get_object_attr(table_obj, SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT) == False

        pytest.tb.remove_object(table_obj)

    def test_table_create_1_field_range_sport_dport(self):
        types = [SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE, SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE]
        table_obj = self.aclTable.create_table_1_field(SAI_ACL_TABLE_ATTR_FIELD_ACL_RANGE_TYPE, types)
        pytest.tb.remove_object(table_obj)

    def test_table_create_fields_sport_range_sport(self):
        args = {}
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        args[SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_ACL_RANGE_TYPE] = [SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE]
        table_obj = self.aclTable.create_table(args)
        pytest.tb.remove_object(table_obj)

    def test_table_create_fields_dport_range_dport(self):
        args = {}
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        args[SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_ACL_RANGE_TYPE] = [SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE]
        table_obj = self.aclTable.create_table(args)
        pytest.tb.remove_object(table_obj)
