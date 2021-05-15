#!/usr/bin/env python3
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

import decor
import unittest
from leaba import sdk
import sim_utils
from voq_cgm_profile_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_hw_gibraltar(), "SKIP-GB-HW")
class voq_profile_setting_sms_dequeue_size_in_packets_behavior(voq_cgm_profile_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_voq_profile_setting_sms_dequeue_size_in_packets_behavior(self):
        for mark in [True, False]:
            self.voq_cgm_profile.set_sms_dequeue_size_in_packets_behavior(0, mark)
            res_mark = self.voq_cgm_profile.get_sms_dequeue_size_in_packets_behavior(0)
            self.assertEqual(res_mark, mark)

        for i in range(0, sdk.LA_CGM_NUM_SMS_PACKETS_QUANTIZATION_REGIONS):
            self.voq_cgm_profile.set_sms_dequeue_size_in_packets_behavior(i, True)
            res_mark = self.voq_cgm_profile.get_sms_dequeue_size_in_packets_behavior(i)
            self.assertEqual(res_mark, True)

        with self.assertRaises(sdk.OutOfRangeException):
            self.voq_cgm_profile.set_sms_dequeue_size_in_packets_behavior(
                sdk.LA_CGM_NUM_SMS_PACKETS_QUANTIZATION_REGIONS, True)


if __name__ == '__main__':
    unittest.main()
