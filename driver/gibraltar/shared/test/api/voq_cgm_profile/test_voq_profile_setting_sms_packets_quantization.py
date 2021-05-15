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
import decor
from voq_cgm_profile_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_hw_gibraltar(), "SKIP-GB-HW")
class voq_profile_setting_sms_packets_quantization(voq_cgm_profile_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_voq_profile_setting_sms_packets_quantization(self):
        try:
            res_lst = self.voq_cgm_profile.get_sms_packets_quantization()
        except sdk.BaseException as STATUS:
            self.assertEqual(STATUS.args[0], sdk.la_status_e_E_NOTFOUND)

        expected_lst = []
        for i in range(0, sdk.la_voq_cgm_profile.SMS_NUM_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS):
            expected_lst.append(100 * i)
        thresholds = sdk.sms_packets_quantization_thresholds()
        thresholds.thresholds = expected_lst

        # Set/get check
        self.voq_cgm_profile.set_sms_packets_quantization(thresholds)
        res_thresholds = self.voq_cgm_profile.get_sms_packets_quantization()
        res_lst = res_thresholds.thresholds
        self.assertEqual(expected_lst, res_lst)

        # Monotone check
        invalid_lst = list(expected_lst)
        invalid_lst[-1] = 0
        thresholds.thresholds = invalid_lst
        try:
            self.voq_cgm_profile.set_sms_packets_quantization(thresholds)
        except sdk.BaseException as STATUS:
            self.assertEqual(STATUS.args[0], sdk.la_status_e_E_INVAL)

        # Out-of-range check
        invalid_lst[-1] = 1 << 30
        thresholds.thresholds = invalid_lst
        try:
            self.voq_cgm_profile.set_sms_packets_quantization(thresholds)
        except sdk.BaseException as STATUS:
            self.assertEqual(STATUS.args[0], sdk.la_status_e_E_OUTOFRANGE)

        thresholds = self.voq_cgm_profile.get_sms_packets_quantization()
        res_lst = res_thresholds.thresholds
        self.assertEqual(expected_lst, res_lst)


if __name__ == '__main__':
    unittest.main()
