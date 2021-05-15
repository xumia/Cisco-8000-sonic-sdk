#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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


@pytest.mark.usefixtures("base_v4_topology")
class Test_port_attr():

    def test_admin_state(self):
        QUEUE_INDEX = 7
        queue_num, queue_list = pytest.tb.get_object_keys(SAI_OBJECT_TYPE_QUEUE)

        q_type = pytest.tb.get_queue_attr(queue_list[QUEUE_INDEX], SAI_QUEUE_ATTR_TYPE)
        q_port = pytest.tb.get_queue_attr(queue_list[QUEUE_INDEX], SAI_QUEUE_ATTR_PORT)
        q_index = pytest.tb.get_queue_attr(queue_list[QUEUE_INDEX], SAI_QUEUE_ATTR_INDEX)
        q_parent_snode = pytest.tb.get_queue_attr(queue_list[QUEUE_INDEX], SAI_QUEUE_ATTR_PARENT_SCHEDULER_NODE)
        q_sched_id = pytest.tb.get_queue_attr(queue_list[QUEUE_INDEX], SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID)
        q_wred_id = pytest.tb.get_queue_attr(queue_list[QUEUE_INDEX], SAI_QUEUE_ATTR_WRED_PROFILE_ID)

        assert(q_port == q_parent_snode)
        assert(q_index == QUEUE_INDEX & 0xFFFFF)
        assert(q_type == SAI_QUEUE_TYPE_ALL)
        assert(sai_object_type_query(q_port) == SAI_OBJECT_TYPE_PORT)
        assert(q_sched_id == SAI_NULL_OBJECT_ID or sai_object_type_query(q_sched_id) == SAI_OBJECT_TYPE_SCHEDULER)
        assert(sai_object_type_query(q_wred_id) == SAI_OBJECT_TYPE_WRED)
