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


@pytest.mark.usefixtures("basic_route_v4_topology")
class TestTm:
    def test_qos_to_queue(self):
        sched_num, sched_list = pytest.tb.get_object_keys(SAI_OBJECT_TYPE_SCHEDULER)
        default_sched_oid = SAI_NULL_OBJECT_ID

        sched_obj_id = pytest.tb.create_scheduler(SAI_SCHEDULING_TYPE_STRICT)
        sched_obj_id2 = pytest.tb.create_scheduler(SAI_SCHEDULING_TYPE_WRR, 5)
        sched_obj_id3 = pytest.tb.create_scheduler(SAI_SCHEDULING_TYPE_WRR, 5, 100000, 1)

        sched_num, sched_list = pytest.tb.get_object_keys(SAI_OBJECT_TYPE_SCHEDULER)
        assert sched_num == 3
        for i in [sched_obj_id, sched_obj_id2, sched_obj_id3]:
            assert i in sched_list

        # verify scheduler parameters
        type = pytest.tb.get_object_attr(sched_obj_id, SAI_SCHEDULER_ATTR_SCHEDULING_TYPE)
        assert(type == SAI_SCHEDULING_TYPE_STRICT)
        type = pytest.tb.get_object_attr(sched_obj_id2, SAI_SCHEDULER_ATTR_SCHEDULING_TYPE)
        assert(type == SAI_SCHEDULING_TYPE_WRR)
        weight = pytest.tb.get_object_attr(sched_obj_id2, SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT)
        assert(weight == 5)
        pir_bps = pytest.tb.get_object_attr(sched_obj_id3, SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE)
        assert(pir_bps == 100000)
        pytest.tb.set_object_attr(sched_obj_id3, SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE, 110000)
        pir_bps = pytest.tb.get_object_attr(sched_obj_id3, SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE)
        assert(pir_bps == 110000)
        meter_type = pytest.tb.get_object_attr(sched_obj_id3, SAI_SCHEDULER_ATTR_METER_TYPE)
        assert(meter_type == 1)
        with expect_sai_error(SAI_STATUS_NOT_SUPPORTED):
            pytest.tb.set_object_attr(sched_obj_id3, SAI_SCHEDULER_ATTR_METER_TYPE, 0)

        queue_list = []
        queue_num, tmp_queue_list = pytest.tb.get_object_keys(SAI_OBJECT_TYPE_QUEUE)
        for i in range(queue_num):
            queue_list.append(tmp_queue_list[i])

        # Make it consistent. Warm boot might change q order
        queue_list.sort()

        # test setting schedulers for all port types
        for i in range(len(queue_list), 8):
            ret_sched_obj_id = pytest.tb.get_queue_attr(queue_list[i], SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID)
            assert(ret_sched_obj_id == default_sched_oid)
            pytest.tb.set_queue_attr(queue_list[i], SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID, sched_obj_id)
            ret_sched_obj_id = pytest.tb.get_queue_attr(queue_list[i], SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID)
            assert(ret_sched_obj_id == sched_obj_id)

        # cleanup of previous loop
        for i in range(len(queue_list), 8):
            pytest.tb.set_queue_attr(queue_list[i], SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID, default_sched_oid)

        offset = queue_num - 8
        # configure some schedulers
        pytest.tb.set_queue_attr(queue_list[offset + 7], SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID, sched_obj_id)
        pytest.tb.set_queue_attr(queue_list[offset + 1], SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID, sched_obj_id)
        pytest.tb.set_queue_attr(queue_list[offset + 2], SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID, sched_obj_id2)
        pytest.tb.set_queue_attr(queue_list[offset + 3], SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID, sched_obj_id2)

        pytest.tb.do_warm_boot()

        # test get attribute
        ret_sched_obj_id = pytest.tb.get_queue_attr(queue_list[offset + 7], SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID)
        assert(ret_sched_obj_id == sched_obj_id)
        ret_sched_obj_id2 = pytest.tb.get_queue_attr(queue_list[offset + 2], SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID)
        assert(ret_sched_obj_id2 == sched_obj_id2)

        # change scheduler attributes
        pytest.tb.set_object_attr(sched_obj_id2, SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT, 7)
        pytest.tb.set_object_attr(sched_obj_id, SAI_SCHEDULER_ATTR_SCHEDULING_TYPE, SAI_SCHEDULING_TYPE_WRR)

        # put back default
        pytest.tb.set_queue_attr(queue_list[offset + 7], SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID, default_sched_oid)
        pytest.tb.set_queue_attr(queue_list[offset + 2], SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID, default_sched_oid)

        # can't delete used schedulers
        with expect_sai_error(SAI_STATUS_OBJECT_IN_USE):
            pytest.tb.remove_object(sched_obj_id)
            pytest.tb.remove_object(sched_obj_id2)

        # put back all to default
        pytest.tb.set_queue_attr(queue_list[offset + 1], SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID, default_sched_oid)
        pytest.tb.set_queue_attr(queue_list[offset + 3], SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID, default_sched_oid)

        # assert all schedulers are set back to default
        for i in [7, 1, 2, 3]:
            ret_sched_obj_id = pytest.tb.get_queue_attr(queue_list[offset + i], SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID)
            assert(ret_sched_obj_id == default_sched_oid)

        # now should be able to delete
        pytest.tb.remove_object(sched_obj_id)
        pytest.tb.remove_object(sched_obj_id2)
