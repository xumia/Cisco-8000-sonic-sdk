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
from acl_range_tests import *


@pytest.mark.usefixtures("basic_route_v4_one_port_topology")
class Test_acl_range():
    aclRange = acl_range_tests()

    def test_range_create_src_port(self):
        range_obj = self.aclRange.create_range(SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE, 0, 1)
        pytest.tb.remove_object(range_obj)

    def test_range_create_dst_port(self):
        range_obj = self.aclRange.create_range(SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE, 0, 1)
        pytest.tb.remove_object(range_obj)

    def test_range_create_multiple(self):
        types = [SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE, SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE]
        objs = [self.aclRange.create_range(types[i % len(types)], i * 3, i * 4) for i in range(7)]
        for range_obj in objs:
            pytest.tb.remove_object(range_obj)

    def test_range_create_no_type(self):
        with expect_sai_error(SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING):
            range_obj = self.aclRange.create_range(None, 0, 1)

    def test_range_create_no_limit(self):
        with expect_sai_error(SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING):
            range_obj = self.aclRange.create_range(SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE, None, None)

    def test_range_create_inverted_limit(self):
        with expect_sai_error(SAI_STATUS_INVALID_PARAMETER):
            range_obj = self.aclRange.create_range(SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE, 1, 0)

    def test_range_create_out_of_range_limit(self):
        with expect_sai_error(SAI_STATUS_INVALID_PARAMETER):
            range_obj = self.aclRange.create_range(SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE, 0, (1 << 16))

    def test_range_entry_create_no_range_in_table(self):
        aclTable = acl_table_tests()
        table_obj = aclTable.create_table_1_field(SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT)
        range_obj = self.aclRange.create_range(SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE, 0, 1)
        with expect_sai_error(SAI_STATUS_FAILURE):
            self.aclRange.create_range_drop_entry(table_obj, [range_obj])
        pytest.tb.remove_object(table_obj)
        pytest.tb.remove_object(range_obj)

    def test_range_entry_create_no_sport_range_in_table(self):
        table_obj = self.aclRange.create_range_table([SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE])
        range_obj = self.aclRange.create_range(SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE, 0, 1)
        with expect_sai_error(SAI_STATUS_FAILURE):
            self.aclRange.create_range_drop_entry(table_obj, [range_obj])
        pytest.tb.remove_object(table_obj)
        pytest.tb.remove_object(range_obj)

    def test_range_entry_create_no_dport_range_in_table(self):
        table_obj = self.aclRange.create_range_table([SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE])
        range_obj = self.aclRange.create_range(SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE, 0, 1)
        with expect_sai_error(SAI_STATUS_FAILURE):
            self.aclRange.create_range_drop_entry(table_obj, [range_obj])
        pytest.tb.remove_object(table_obj)
        pytest.tb.remove_object(range_obj)

    def test_range_1_sport(self):
        self.aclRange.create_and_exercise_sport_range(13, 13)

    def test_range_sports_lower(self):
        self.aclRange.create_and_exercise_sport_range(0, 0x003F)

    def test_range_sports_upper(self):
        self.aclRange.create_and_exercise_sport_range(0xFFE0, 0xFFFF)

    def test_range_sports_full(self):
        self.aclRange.create_and_exercise_sport_range(0, 0xFFFF)

    def test_range_sports(self):
        self.aclRange.create_and_exercise_sport_range(10042, 20915)

    def test_range_1_dport(self):
        self.aclRange.create_and_exercise_dport_range(9, 9)

    def test_range_dports_lower(self):
        self.aclRange.create_and_exercise_dport_range(0, 0x7FF)

    def test_range_dports_upper(self):
        self.aclRange.create_and_exercise_dport_range(0xFF80, 0xFFFF)

    def test_range_dports_full(self):
        self.aclRange.create_and_exercise_dport_range(0, 0xFFFF)

    def test_range_dports(self):
        self.aclRange.create_and_exercise_dport_range(54321, 55432)

    def test_range_1_sport_1_dport(self):
        self.aclRange.create_and_exercise_sport_dport_range((903, 903), (5000, 5000))

    def test_range_sports_dports(self):
        self.aclRange.create_and_exercise_sport_dport_range((42, 8899), (99, 1111))

    def test_range_sports_dports_edges(self):
        self.aclRange.create_and_exercise_sport_dport_range((0, 0xFF01), (0xFF00, 0xFFFF))

    def test_range_sports_dports_full(self):
        self.aclRange.create_and_exercise_sport_dport_range((0, 0xFFFF), (0, 0xFFFF))

    def test_range_removal_while_in_use(self):
        range_type = SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE
        range_obj = self.aclRange.create_range(range_type, 0, 1)
        table_obj = self.aclRange.create_range_table([range_type])
        entry_obj = self.aclRange.create_range_drop_entry(table_obj, [range_obj])

        with expect_sai_error(SAI_STATUS_OBJECT_IN_USE):
            pytest.tb.remove_object(range_obj)

        pytest.tb.remove_object(entry_obj)
        pytest.tb.remove_object(range_obj)
        pytest.tb.remove_object(table_obj)

    def test_range_removal_while_in_use_double_usage(self):
        range_type = SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE
        range_obj = self.aclRange.create_range(range_type, 0, 1)
        table_obj = self.aclRange.create_range_table([range_type])
        entry_obj_A = self.aclRange.create_range_drop_entry(table_obj, [range_obj])
        entry_obj_B = self.aclRange.create_range_drop_entry(table_obj, [range_obj])

        with expect_sai_error(SAI_STATUS_OBJECT_IN_USE):
            pytest.tb.remove_object(range_obj)

        pytest.tb.remove_object(entry_obj_A)

        with expect_sai_error(SAI_STATUS_OBJECT_IN_USE):
            pytest.tb.remove_object(range_obj)

        pytest.tb.remove_object(entry_obj_B)
        pytest.tb.remove_object(range_obj)
        pytest.tb.remove_object(table_obj)

    def test_range_entry_create_full_table_1_range(self):
        range_type = SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE
        range_obj = self.aclRange.create_range(range_type, 7, 0x8F1)
        table_obj = self.aclRange.create_range_table([range_type], size=10)

        with expect_sai_error(SAI_STATUS_TABLE_FULL):
            entry_obj = self.aclRange.create_range_drop_entry(table_obj, [range_obj])

        pytest.tb.remove_object(range_obj)
        pytest.tb.remove_object(table_obj)

    def test_range_entry_create_full_table_2_ranges(self):
        type_A = SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE
        type_B = SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE
        range_A = self.aclRange.create_range(type_A, 0, 0xF1)
        range_B = self.aclRange.create_range(type_B, 0, 0xF1)
        table_obj = self.aclRange.create_range_table([type_A, type_B], size=20)

        with expect_sai_error(SAI_STATUS_TABLE_FULL):
            entry_obj = self.aclRange.create_range_drop_entry(table_obj, [range_A, range_B])

        pytest.tb.remove_object(range_A)
        pytest.tb.remove_object(range_B)
        pytest.tb.remove_object(table_obj)
