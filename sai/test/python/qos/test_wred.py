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
import sai_test_utils as st_utils


@pytest.mark.usefixtures("base_v4_topology")
class Test_sai_qos():

    @pytest.mark.skipif(is_asic_env_gibraltar(), reason="The test applicable only to Pacific")
    def test_wred(self):
        # test for creating WRED objects in pacific only
        st_utils.skipIf(pytest.tb.is_gb)

        # Can't add wred object with red drop probability != 100
        wred_bad_attr = {SAI_WRED_ATTR_GREEN_ENABLE: True,
                         SAI_WRED_ATTR_YELLOW_ENABLE: True,
                         SAI_WRED_ATTR_RED_ENABLE: True,
                         SAI_WRED_ATTR_RED_DROP_PROBABILITY: 90}
        with expect_sai_error(SAI_STATUS_INVALID_PARAMETER):
            pytest.tb.create_wred(wred_bad_attr)

        # Add wred object
        wred_attr = {SAI_WRED_ATTR_GREEN_ENABLE: True,
                     SAI_WRED_ATTR_YELLOW_ENABLE: True,
                     SAI_WRED_ATTR_RED_ENABLE: True,
                     SAI_WRED_ATTR_RED_DROP_PROBABILITY: 100,
                     SAI_WRED_ATTR_GREEN_DROP_PROBABILITY: 10,
                     SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY: 10,
                     SAI_WRED_ATTR_GREEN_MIN_THRESHOLD: 1024 * 1024,  # 1MB
                     SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD: 1024 * 1024,
                     SAI_WRED_ATTR_GREEN_MAX_THRESHOLD: 3 * 1024 * 1024,  # 3MB
                     SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD: 3 * 1024 * 1024}
        wred_obj_id = pytest.tb.create_wred(wred_attr, verify=[True, True])

        # set to queue
        queue_num, queue_list = pytest.tb.get_object_keys(SAI_OBJECT_TYPE_QUEUE)
        pytest.tb.set_queue_attr(queue_list[7],
                                 SAI_QUEUE_ATTR_WRED_PROFILE_ID,
                                 wred_obj_id)
        wred_obj_from_q = pytest.tb.get_queue_attr(queue_list[7], SAI_QUEUE_ATTR_WRED_PROFILE_ID)
        assert(wred_obj_from_q == wred_obj_id)

        pytest.tb.do_warm_boot()

        # try to remove. Should fail because it is in use
        with expect_sai_error(SAI_STATUS_OBJECT_IN_USE):
            pytest.tb.remove_object(wred_obj_id)

        # test set wred attributes
        pytest.tb.set_object_attr(wred_obj_id, SAI_WRED_ATTR_GREEN_ENABLE, False, True)

        pytest.tb.set_object_attr(wred_obj_id, SAI_WRED_ATTR_GREEN_MIN_THRESHOLD, 2 * 1024 * 1024, True)
        # test if green config is copied to yellow
        assert pytest.tb.get_object_attr(wred_obj_id, SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD) == 2 * 1024 * 1024

        pytest.tb.set_object_attr(wred_obj_id, SAI_WRED_ATTR_GREEN_MAX_THRESHOLD, 4 * 1024 * 1024, True)
        # test if green config is copied to yellow
        assert pytest.tb.get_object_attr(wred_obj_id, SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD) == 4 * 1024 * 1024

        # set red drop probablity < 100
        pytest.tb.set_object_attr(wred_obj_id, SAI_WRED_ATTR_RED_DROP_PROBABILITY, 80)
        # request ignored, drop probablity set to 100
        assert pytest.tb.get_object_attr(wred_obj_id, SAI_WRED_ATTR_RED_DROP_PROBABILITY) == 100

        # put default wred back on queue
        pytest.tb.set_queue_attr(queue_list[7],
                                 SAI_QUEUE_ATTR_WRED_PROFILE_ID,
                                 SAI_NULL_OBJECT_ID)
        # remove should succeed now
        pytest.tb.remove_object(wred_obj_id)

    @pytest.mark.skipif(not is_asic_env_gibraltar(), reason="The test applicable only on gibraltar")
    def test_wred_gb(self):
        # Can't add wred object with red drop probability != 100
        wred_bad_attr = {SAI_WRED_ATTR_GREEN_ENABLE: True,
                         SAI_WRED_ATTR_YELLOW_ENABLE: True,
                         SAI_WRED_ATTR_RED_ENABLE: True,
                         SAI_WRED_ATTR_RED_DROP_PROBABILITY: 90}
        with expect_sai_error(SAI_STATUS_INVALID_PARAMETER):
            pytest.tb.create_wred(wred_bad_attr)

        # green and yellow can have different values in gb
        # Add wred object
        wred_attr = {SAI_WRED_ATTR_GREEN_ENABLE: True,
                     SAI_WRED_ATTR_YELLOW_ENABLE: True,
                     SAI_WRED_ATTR_RED_ENABLE: True,
                     SAI_WRED_ATTR_RED_DROP_PROBABILITY: 100,
                     SAI_WRED_ATTR_GREEN_DROP_PROBABILITY: 10,
                     SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY: 20,
                     SAI_WRED_ATTR_GREEN_MIN_THRESHOLD: 1024 * 1024,  # 1MB
                     SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD: 2 * 1024 * 1024,  # 2MB
                     SAI_WRED_ATTR_GREEN_MAX_THRESHOLD: 3 * 1024 * 1024,  # 3MB
                     SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD: 3 * 1024 * 1024}  # 3MB
        wred_obj_id = pytest.tb.create_wred(wred_attr, verify=[True, True])

        # set to queue
        queue_num, queue_list = pytest.tb.get_object_keys(SAI_OBJECT_TYPE_QUEUE)
        pytest.tb.set_queue_attr(queue_list[7],
                                 SAI_QUEUE_ATTR_WRED_PROFILE_ID,
                                 wred_obj_id)
        wred_obj_from_q = pytest.tb.get_queue_attr(queue_list[7], SAI_QUEUE_ATTR_WRED_PROFILE_ID)
        assert(wred_obj_from_q == wred_obj_id)

        pytest.tb.do_warm_boot()

        # try to remove. Should fail because it is in use
        with expect_sai_error(SAI_STATUS_OBJECT_IN_USE):
            pytest.tb.remove_object(wred_obj_id)

        # test set wred attributes
        pytest.tb.set_object_attr(wred_obj_id, SAI_WRED_ATTR_GREEN_ENABLE, False, True)
        pytest.tb.set_object_attr(wred_obj_id, SAI_WRED_ATTR_GREEN_MIN_THRESHOLD, 2 * 1024 * 1024, True)
        pytest.tb.set_object_attr(wred_obj_id, SAI_WRED_ATTR_GREEN_MAX_THRESHOLD, 4 * 1024 * 1024, True)

        # set red drop probablity < 100
        pytest.tb.set_object_attr(wred_obj_id, SAI_WRED_ATTR_RED_DROP_PROBABILITY, 80)
        # request ignored, drop probablity set to 100
        assert pytest.tb.get_object_attr(wred_obj_id, SAI_WRED_ATTR_RED_DROP_PROBABILITY) == 100

        # put default wred back on queue
        pytest.tb.set_queue_attr(queue_list[7],
                                 SAI_QUEUE_ATTR_WRED_PROFILE_ID,
                                 SAI_NULL_OBJECT_ID)
        # remove should succeed now
        pytest.tb.remove_object(wred_obj_id)

    @pytest.mark.skipif(not is_asic_env_gibraltar(), reason="The test applicable only on gibraltar")
    def test_ecn_wred_gb(self):
        pytest.tb.set_switch_attribute(SAI_SWITCH_ATTR_ECN_ECT_THRESHOLD_ENABLE, True)

        # ECN will have both drop and marking profile. Need to give the min max threshold for the drop as well.
        # Add wred object
        wred_attr = {SAI_WRED_ATTR_ECN_MARK_MODE: SAI_ECN_MARK_MODE_ALL,
                     SAI_WRED_ATTR_GREEN_ENABLE: True,
                     SAI_WRED_ATTR_YELLOW_ENABLE: True,
                     SAI_WRED_ATTR_RED_ENABLE: True,
                     SAI_WRED_ATTR_RED_DROP_PROBABILITY: 100,
                     SAI_WRED_ATTR_GREEN_DROP_PROBABILITY: 10,
                     SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY: 20,
                     SAI_WRED_ATTR_GREEN_MIN_THRESHOLD: 1024 * 1024,  # 1MB
                     SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD: 2 * 1024 * 1024,  # 2MB
                     SAI_WRED_ATTR_GREEN_MAX_THRESHOLD: 3 * 1024 * 1024,  # 3MB
                     SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD: 3 * 1024 * 1024,  # 3MB
                     SAI_WRED_ATTR_ECN_RED_MARK_PROBABILITY: 100,
                     SAI_WRED_ATTR_ECN_GREEN_MARK_PROBABILITY: 10,
                     SAI_WRED_ATTR_ECN_YELLOW_MARK_PROBABILITY: 20,
                     SAI_WRED_ATTR_ECN_GREEN_MIN_THRESHOLD: 1024 * 1024,  # 1MB
                     SAI_WRED_ATTR_ECN_YELLOW_MIN_THRESHOLD: 2 * 1024 * 1024,  # 2MB
                     SAI_WRED_ATTR_ECN_GREEN_MAX_THRESHOLD: 3 * 1024 * 1024,  # 3MB
                     SAI_WRED_ATTR_ECN_YELLOW_MAX_THRESHOLD: 3 * 1024 * 1024}  # 3MB
        wred_obj_id = pytest.tb.create_wred(wred_attr, verify=[True, True])

        # set to queue
        queue_num, queue_list = pytest.tb.get_object_keys(SAI_OBJECT_TYPE_QUEUE)
        pytest.tb.set_queue_attr(queue_list[7],
                                 SAI_QUEUE_ATTR_WRED_PROFILE_ID,
                                 wred_obj_id)
        wred_obj_from_q = pytest.tb.get_queue_attr(queue_list[7], SAI_QUEUE_ATTR_WRED_PROFILE_ID)
        assert(wred_obj_from_q == wred_obj_id)

        pytest.tb.do_warm_boot()

        # try to remove. Should fail because it is in use
        with expect_sai_error(SAI_STATUS_OBJECT_IN_USE):
            pytest.tb.remove_object(wred_obj_id)

        # test set wred attributes
        pytest.tb.set_object_attr(wred_obj_id, SAI_WRED_ATTR_ECN_GREEN_MIN_THRESHOLD, 2 * 1024 * 1024, True)
        pytest.tb.set_object_attr(wred_obj_id, SAI_WRED_ATTR_ECN_GREEN_MAX_THRESHOLD, 4 * 1024 * 1024, True)
        pytest.tb.set_object_attr(wred_obj_id, SAI_WRED_ATTR_ECN_GREEN_MARK_PROBABILITY, 60, True)

        # put default wred back on queue
        pytest.tb.set_queue_attr(queue_list[7],
                                 SAI_QUEUE_ATTR_WRED_PROFILE_ID,
                                 SAI_NULL_OBJECT_ID)
        # remove should succeed now
        pytest.tb.remove_object(wred_obj_id)
