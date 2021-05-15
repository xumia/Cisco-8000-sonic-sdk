#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import decor
import unittest
from leaba import sdk
import sim_utils
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_device_voq_cgm(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(1)

    def tearDown(self):
        self.device.tearDown()

    def test_get_cgm_sms_voqs_deque_congestion_level_mark_ecn_probability(self):
        all_levels = 16

        try:
            for lvl in range(all_levels):
                p = self.device.get_cgm_sms_voqs_deque_congestion_level_mark_ecn_probability(lvl)

                # test initialize
                if lvl == all_levels - 1:
                    self.assertTrue(p == 1)
                    pass
                else:
                    self.assertTrue(p == 0)
                    pass

            # test get/set/clear
            for lvl in range(all_levels):
                prob = lvl / 16.0

                self.device.set_cgm_sms_voqs_deque_congestion_level_mark_ecn_probability(lvl, prob)

                p = self.device.get_cgm_sms_voqs_deque_congestion_level_mark_ecn_probability(lvl)

                # probablity will be converted to integers in SDK
                # Programmed value might be different from the set value;
                self.assertTrue(prob - p < 1 / 32)

                self.device.clear_cgm_sms_voqs_deque_congestion_level_mark_ecn_probability(lvl)

                p = self.device.get_cgm_sms_voqs_deque_congestion_level_mark_ecn_probability(lvl)

                self.assertTrue(p == 0)

        except sdk.BaseException as STATUS:
            self.assertTrue(STATUS.args[0] == sdk.la_status_e_E_NOTIMPLEMENTED)

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_cgm_sms_voqs_age_time_units(self):
        try:
            self.device.get_cgm_sms_voqs_age_time_granularity()
        except sdk.BaseException as STATUS:
            self.assertEqual(STATUS.args[0], sdk.la_status_e_E_NOTINITIALIZED)

        try:
            val = 100
            self.device.set_cgm_sms_voqs_age_time_granularity(val)
        except sdk.BaseException as STATUS:
            self.assertEqual(STATUS.args[0], sdk.la_status_e_E_INVAL)

        val = 1000
        self.device.set_cgm_sms_voqs_age_time_granularity(val)

        res = self.device.get_cgm_sms_voqs_age_time_granularity()
        self.assertEqual(val, res)

    @unittest.skipIf(decor.is_pacific(), "Not supported on pacific.")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test fails on AR")
    def test_voq_cgm_setting_sms_all_evicted_bytes_quantization(self):
        bytes_in_buf = 384
        num_thresholds = self.device.get_limit(sdk.limit_type_e_DEVICE__SMS_NUM_EVICTED_BUFF_QUANTIZATION_CONFIGURABLE_THRESHOLDS)

        thresholds = sdk.la_voq_cgm_quantization_thresholds()
        for i in range(0, num_thresholds):
            thresholds.thresholds.append(100 * i * bytes_in_buf)

        # Set/get check
        expected_lst = [None] * num_thresholds
        for i in range(0, num_thresholds):
            expected_lst[i] = int(round(thresholds.thresholds[i] / bytes_in_buf) * bytes_in_buf)

        self.device.set_cgm_sms_evicted_bytes_quantization(thresholds)

        res_thresholds = self.device.get_cgm_sms_evicted_bytes_quantization()
        for i in range(0, num_thresholds):
            self.assertEqual(thresholds.thresholds[i], res_thresholds.thresholds[i])

        # Invalid check
        invalid_thresholds = sdk.la_voq_cgm_quantization_thresholds()
        for i in reversed(range(num_thresholds)):
            invalid_thresholds.thresholds.append(100 * i * bytes_in_buf)
        try:
            self.device.set_cgm_sms_evicted_bytes_quantization(thresholds)
        except sdk.BaseException as STATUS:
            self.assertEqual(STATUS.args[0], sdk.la_status_e_E_INVAL)

        # Out-of-range check
        out_of_range_thresholds = sdk.la_voq_cgm_quantization_thresholds()
        for i in range(0, num_thresholds - 1):
            out_of_range_thresholds.thresholds.append(100 * i * bytes_in_buf)
        try:
            self.device.set_cgm_sms_evicted_bytes_quantization(thresholds)
        except sdk.BaseException as STATUS:
            self.assertEqual(STATUS.args[0], sdk.la_status_e_E_OUTOFRANGE)

        res_thresholds = self.device.get_cgm_sms_evicted_bytes_quantization()
        for i in range(0, num_thresholds):
            self.assertEqual(thresholds.thresholds[i], res_thresholds.thresholds[i])


if __name__ == '__main__':
    unittest.main()
