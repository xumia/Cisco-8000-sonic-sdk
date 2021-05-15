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
import saicli as S
import sai_packet_utils as U
import sai_test_base as st_base
import sai_test_utils as st_utils
import sai_topology as topology
from sai_test_utils import *


class CleanupAcl:
    def __init__(self):
        self.acl_table = []
        self.acl_entry = []
        self.acl_counter = []
        self.acl_table_group = []

    def clean(self):
        pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_EGRESS_ACL, 0)
        pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, 0)
        for c in self.acl_counter:
            pytest.tb.remove_object(c)
        for e in self.acl_entry:
            pytest.tb.remove_object(e)
        for t in self.acl_table:
            pytest.tb.remove_object(t)
        for g in self.acl_table_group:
            pytest.tb.remove_object(g)


@pytest.mark.usefixtures("base_v4_topology")
@pytest.mark.skipif(True, reason="RTF does not support this test")
class Test_crm_acl_table():

    pytest.nsim_accurate = True

    def _clean(self, finalizer):
        clean = CleanupAcl()
        finalizer.add_cleanup(clean)
        return clean

    def _create_table(self, size, stage, clean):
        args = {}
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = stage
        args[SAI_ACL_TABLE_ATTR_SIZE] = size
        args[SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST] = [SAI_ACL_BIND_POINT_TYPE_SWITCH]
        args[SAI_ACL_TABLE_ATTR_FIELD_SRC_IP] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_DST_IP] = True
        table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)
        assert table is not None
        clean.acl_table.append(table)
        return table

    def _create_acl_entry(self, acl_table, src_ip, dst_ip, clean, counter = None):
        entry_args = {}
        entry_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, src_ip, "255.255.255.255"]
        entry_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_DROP]
        entry_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, dst_ip, "255.255.255.255"]
        if counter is not None:
            entry_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, counter]
        entry = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry_args)
        assert entry is not None
        clean.acl_entry.append(entry)
        return entry

    def _create_packet_counter(self, acl_table, clean):
        counter_args = {}
        counter_args[SAI_ACL_COUNTER_ATTR_TABLE_ID] = acl_table
        counter_args[SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT] = True
        counter = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_COUNTER, counter_args)
        assert counter is not None
        clean.acl_counter.append(counter)
        return counter

    def _create_table_group(self, stage, clean):
        args = {}
        args[SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE] = stage
        group = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP, args)
        clean.acl_table_group.append(group)
        return group

    def test_acl_table_crm(self, finalizer):
        clean = self._clean(finalizer)
        num_to_create = 2
        max_available = pytest.tb.get_acl_table_available()[0][2]
        pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, self._create_table(10, SAI_ACL_STAGE_INGRESS, clean))
        pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_EGRESS_ACL, self._create_table(10, SAI_ACL_STAGE_EGRESS, clean))
        cur_available = pytest.tb.get_acl_table_available()[0][2]
        assert (max_available - cur_available) == num_to_create

    def test_acl_entry_crm(self, finalizer):
        clean = self._clean(finalizer)
        num_to_create = 5
        table = self._create_table(10, SAI_ACL_STAGE_INGRESS, clean)
        pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, table)
        max_available = pytest.tb.get_acl_table_entry_available(table)
        for i in range(num_to_create):
            self._create_acl_entry(table, "10.1.1.{}".format(i), "10.1.2.{}".format(i), clean)
        cur_available = pytest.tb.get_acl_table_entry_available(table)
        assert (max_available - cur_available) == num_to_create

    def test_acl_table_counter_crm(self, finalizer):
        clean = self._clean(finalizer)
        num_counters_1 = 5
        num_counters_2 = 10
        table_1 = self._create_table(10, SAI_ACL_STAGE_INGRESS, clean)
        table_2 = self._create_table(10, SAI_ACL_STAGE_EGRESS, clean)
        pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, table_1)
        pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_EGRESS_ACL, table_2)
        max_available_1 = pytest.tb.get_acl_table_counter_available(table_1)
        max_available_2 = pytest.tb.get_acl_table_counter_available(table_2)
        for i in range(num_counters_1):
            self._create_packet_counter(table_1, clean)
        for i in range(num_counters_2):
            self._create_packet_counter(table_2, clean)
        cur_num_1 = pytest.tb.get_acl_table_counter_available(table_1)
        cur_num_2 = pytest.tb.get_acl_table_counter_available(table_2)
        assert (max_available_1 - cur_num_1) == num_counters_1
        assert (max_available_2 - cur_num_2) == num_counters_2

    def test_acl_table_group_crm(self, finalizer):
        clean = self._clean(finalizer)
        max_available = pytest.tb.get_acl_table_group_available()[0][2]
        group_1 = self._create_table_group(SAI_ACL_STAGE_INGRESS, clean)
        group_2 = self._create_table_group(SAI_ACL_STAGE_EGRESS, clean)
        pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, group_1)
        pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_EGRESS_ACL, group_2)
        cur_available = pytest.tb.get_acl_table_group_available()[0][2]
        assert (max_available - cur_available) == 2
