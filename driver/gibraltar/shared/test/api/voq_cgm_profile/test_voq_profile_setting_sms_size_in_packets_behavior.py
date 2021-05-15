#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
class voq_profile_setting_sms_size_in_packets_behavior(voq_cgm_profile_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_voq_profile_setting_sms_size_in_packets_behavior(self):
        try:
            (res_color, res_mark, res_evict_to_hbm) = self.voq_cgm_profile.get_sms_size_in_packets_behavior(0, 0, 0)
            self.fail()
        except sdk.BaseException:
            pass

        for color in [sdk.la_qos_color_e_GREEN, sdk.la_qos_color_e_YELLOW, sdk.la_qos_color_e_NONE]:
            self.voq_cgm_profile.set_sms_size_in_packets_behavior(0, 0, 0, color, True, True)
            (res_color, res_mark, res_evict_to_hbm) = self.voq_cgm_profile.get_sms_size_in_packets_behavior(0, 0, 0)
            self.assertEqual(res_color, color)

        for mark in [True, False]:
            self.voq_cgm_profile.set_sms_size_in_packets_behavior(0, 0, 0, sdk.la_qos_color_e_GREEN, mark, True)
            (res_color, res_mark, res_evict_to_hbm) = self.voq_cgm_profile.get_sms_size_in_packets_behavior(0, 0, 0)
            self.assertEqual(res_mark, mark)

        for evict_to_hbm in [True, False]:
            self.voq_cgm_profile.set_sms_size_in_packets_behavior(0, 0, 0, sdk.la_qos_color_e_GREEN, True, evict_to_hbm)
            (res_color, res_mark, res_evict_to_hbm) = self.voq_cgm_profile.get_sms_size_in_packets_behavior(0, 0, 0)
            self.assertEqual(res_evict_to_hbm, evict_to_hbm)

        for i in range(0, sdk.LA_CGM_NUM_SMS_PACKETS_QUANTIZATION_REGIONS):
            self.voq_cgm_profile.set_sms_size_in_packets_behavior(
                i, 0, 0, sdk.la_qos_color_e_GREEN, True, evict_to_hbm)

        try:
            self.voq_cgm_profile.set_sms_size_in_packets_behavior(
                sdk.LA_CGM_NUM_SMS_PACKETS_QUANTIZATION_REGIONS, 0, 0, sdk.la_qos_color_e_GREEN, True, evict_to_hbm)
            self.fail()
        except sdk.BaseException:
            pass

        for i in range(0, sdk.la_voq_cgm_profile.SMS_NUM_PACKETS_QUANTIZATION_REGIONS):
            self.voq_cgm_profile.set_sms_size_in_packets_behavior(0, i, 0, sdk.la_qos_color_e_GREEN, True, evict_to_hbm)

        try:
            self.voq_cgm_profile.set_sms_size_in_packets_behavior(
                0, sdk.la_voq_cgm_profile.SMS_NUM_PACKETS_QUANTIZATION_REGIONS, 0, sdk.la_qos_color_e_GREEN, True, evict_to_hbm)
            self.fail()
        except sdk.BaseException:
            pass

        for i in range(0, sdk.la_voq_cgm_profile.SMS_NUM_AGE_QUANTIZATION_REGIONS):
            self.voq_cgm_profile.set_sms_size_in_packets_behavior(0, 0, i, sdk.la_qos_color_e_GREEN, True, evict_to_hbm)

        try:
            self.voq_cgm_profile.set_sms_size_in_packets_behavior(
                0, 0, sdk.la_voq_cgm_profile.SMS_NUM_AGE_QUANTIZATION_REGIONS, sdk.la_qos_color_e_GREEN, True, evict_to_hbm)
            self.fail()
        except sdk.BaseException:
            pass


if __name__ == '__main__':
    unittest.main()
