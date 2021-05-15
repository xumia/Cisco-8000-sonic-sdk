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
from sai_test_utils import *


@pytest.mark.usefixtures("base_v4_topology")
@pytest.mark.skipif(is_sai_15x(), reason="Disabled on SAI 1.5.x")
class Test_buffer_pool_attr():
    # need to test negative cases first
    def test_invalid_buffer_pool_create(self):
        size_to_check = get_egress_dynamic_buffer_pool_size(pytest.tb.switch_id)

        with expect_sai_error(SAI_STATUS_NOT_SUPPORTED):
            buffer_pool_id2 = pytest.tb.obj_wrapper.create_object(
                SAI_OBJECT_TYPE_BUFFER_POOL, pytest.tb.switch_id, [
                    [
                        SAI_BUFFER_POOL_ATTR_TYPE, SAI_BUFFER_POOL_TYPE_INGRESS], [
                        SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE, SAI_BUFFER_POOL_THRESHOLD_MODE_DYNAMIC], [
                        SAI_BUFFER_POOL_ATTR_SIZE, size_to_check]], [
                            True, True], False)

        with expect_sai_error(SAI_STATUS_NOT_SUPPORTED):
            buffer_pool_id2 = pytest.tb.obj_wrapper.create_object(
                SAI_OBJECT_TYPE_BUFFER_POOL, pytest.tb.switch_id, [
                    [
                        SAI_BUFFER_POOL_ATTR_TYPE, SAI_BUFFER_POOL_TYPE_EGRESS], [
                        SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE, SAI_BUFFER_POOL_THRESHOLD_MODE_STATIC], [
                        SAI_BUFFER_POOL_ATTR_SIZE, size_to_check]], [
                            True, True], False)

        with expect_sai_error(SAI_STATUS_NOT_SUPPORTED):
            buffer_pool_id2 = pytest.tb.obj_wrapper.create_object(
                SAI_OBJECT_TYPE_BUFFER_POOL, pytest.tb.switch_id, [
                    [
                        SAI_BUFFER_POOL_ATTR_TYPE, SAI_BUFFER_POOL_TYPE_EGRESS], [
                        SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE, SAI_BUFFER_POOL_THRESHOLD_MODE_DYNAMIC], [
                        SAI_BUFFER_POOL_ATTR_SIZE, size_to_check * 2]], [
                            True, True], False)

    def test_buffer_pool_attr(self):
        size_to_check = get_egress_dynamic_buffer_pool_size(pytest.tb.switch_id)

        buffer_pool_id = pytest.tb.obj_wrapper.create_object(
            SAI_OBJECT_TYPE_BUFFER_POOL, pytest.tb.switch_id, [
                [
                    SAI_BUFFER_POOL_ATTR_TYPE, SAI_BUFFER_POOL_TYPE_EGRESS], [
                    SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE, SAI_BUFFER_POOL_THRESHOLD_MODE_DYNAMIC], [
                    SAI_BUFFER_POOL_ATTR_SIZE, size_to_check]], [
                        True, True], False)

        self.buffer_pool_stats_test(buffer_pool_id, size_to_check)
        # Only one buffer pool can be created
        with expect_sai_error(SAI_STATUS_INSUFFICIENT_RESOURCES):
            buffer_pool_id1 = pytest.tb.obj_wrapper.create_object(
                SAI_OBJECT_TYPE_BUFFER_POOL, pytest.tb.switch_id, [
                    [
                        SAI_BUFFER_POOL_ATTR_TYPE, SAI_BUFFER_POOL_TYPE_EGRESS], [
                        SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE, SAI_BUFFER_POOL_THRESHOLD_MODE_DYNAMIC], [
                        SAI_BUFFER_POOL_ATTR_SIZE, size_to_check]], [
                            True, True], False)

        assert pytest.tb.get_object_attr(buffer_pool_id, SAI_BUFFER_POOL_ATTR_SHARED_SIZE) == size_to_check
        assert pytest.tb.get_object_attr(buffer_pool_id, SAI_BUFFER_POOL_ATTR_TAM) == []
        assert pytest.tb.get_object_attr(buffer_pool_id, SAI_BUFFER_POOL_ATTR_XOFF_SIZE) == 0
        assert pytest.tb.get_object_attr(buffer_pool_id, SAI_BUFFER_POOL_ATTR_WRED_PROFILE_ID) == SAI_NULL_OBJECT_ID

        pytest.tb.obj_wrapper.remove_object(buffer_pool_id)

    def test_buffer_profile_attr(self):
        size_to_check = get_egress_dynamic_buffer_pool_size(pytest.tb.switch_id)

        buffer_pool_id = pytest.tb.obj_wrapper.create_object(
            SAI_OBJECT_TYPE_BUFFER_POOL, pytest.tb.switch_id, [
                [
                    SAI_BUFFER_POOL_ATTR_TYPE, SAI_BUFFER_POOL_TYPE_EGRESS], [
                    SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE, SAI_BUFFER_POOL_THRESHOLD_MODE_DYNAMIC], [
                    SAI_BUFFER_POOL_ATTR_SIZE, size_to_check]], [
                        True, True], False)

        buffer_profile_id = pytest.tb.obj_wrapper.create_object(
            SAI_OBJECT_TYPE_BUFFER_PROFILE, pytest.tb.switch_id, [
                [SAI_BUFFER_PROFILE_ATTR_POOL_ID, buffer_pool_id],
                [SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE, SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC],
                [SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE, 4096],
                [SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH, 64]
            ], [True, True], False
        )

        assert pytest.tb.get_object_attr(buffer_profile_id, SAI_BUFFER_PROFILE_ATTR_POOL_ID) == buffer_pool_id
        assert pytest.tb.get_object_attr(buffer_profile_id,
                                         SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE) == SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC
        assert pytest.tb.get_object_attr(buffer_profile_id, SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE) == 4096
        assert pytest.tb.get_object_attr(buffer_profile_id, SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH) == 64

        pytest.tb.set_object_attr(buffer_profile_id, SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE, 1024 * 1024, True)
        pytest.tb.set_object_attr(buffer_profile_id, SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH, 128, True)

        QUEUE_INDEX = 7
        queue_num, queue_list = pytest.tb.get_object_keys(SAI_OBJECT_TYPE_QUEUE)
        pytest.tb.set_object_attr(queue_list[QUEUE_INDEX], SAI_QUEUE_ATTR_BUFFER_PROFILE_ID, buffer_profile_id, True)
        pytest.tb.set_object_attr(queue_list[QUEUE_INDEX], SAI_QUEUE_ATTR_BUFFER_PROFILE_ID, SAI_NULL_OBJECT_ID, True)
        pytest.tb.remove_object(buffer_pool_id)
        pytest.tb.remove_object(buffer_profile_id)

    def buffer_pool_stats_test(self, buffer_pool, buffer_pool_size):
        # set refresh time to 1 sec
        pytest.tb.set_object_attr(pytest.tb.switch_id, SAI_SWITCH_ATTR_COUNTER_REFRESH_INTERVAL, 1)

        # This is just to test that refresh interval mechanism does not crash
        # actual values returned here are always 0 on nsim. Tested the values manually on HW
        pool_stats = pytest.tb.get_buffer_pool_stats(buffer_pool)
        pool_stats = pytest.tb.get_buffer_pool_stats(buffer_pool)
        time.sleep(2)
        pool_stats = pytest.tb.get_buffer_pool_stats(buffer_pool)

        pytest.tb.set_object_attr(pytest.tb.switch_id, SAI_SWITCH_ATTR_COUNTER_REFRESH_INTERVAL, 0)
