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
import math
from voq_cgm_profile_base import *

WRED_EMA_WEIGHT_WIDTH = 4


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_hw_gibraltar(), "SKIP-GB-HW")
class voq_profile_setting_averaging_configuration(voq_cgm_profile_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_voq_profile_setting_averaging_configuration(self):
        try:
            (res_ema, res_thresholds) = self.voq_cgm_profile.get_averaging_configuration()
            self.fail()
        except sdk.BaseException:
            pass

        lst = []
        for i in range(0, sdk.la_voq_cgm_profile.WRED_NUM_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS):
            lst.append(i * 1000)
        thresholds = sdk.wred_blocks_quantization_thresholds()
        thresholds.thresholds = lst

        # Set/get EMA check
        for ema in [0.125, 0, 0.5, 1]:
            self.voq_cgm_profile.set_averaging_configuration(ema, thresholds)
            (res_ema, res_thresholds) = self.voq_cgm_profile.get_averaging_configuration()

            if (ema == 0):
                expected_ema = (1 << WRED_EMA_WEIGHT_WIDTH) - 1
            else:
                expected_ema = - math.log(ema, 2)

            res = - math.log(res_ema, 2)
            assert(abs(expected_ema - res) < 1e-4), "ema coefficient value was not quantized correct: res ema=%f , expected ema=%f , res val=%f , expected val=%f" % (res_ema, ema, res, expected_ema)

        # Out-of-range check
        for ema in [-1, 2]:
            try:
                self.voq_cgm_profile.set_averaging_configuration(ema, thresholds)
                self.fail()
            except sdk.BaseException:
                pass

        # Set/get thresholds check
        self.voq_cgm_profile.set_averaging_configuration(0, thresholds)
        (res_ema, res_thresholds) = self.voq_cgm_profile.get_averaging_configuration()
        res_lst = res_thresholds.thresholds
        self.assertEqual(lst, res_lst)

        # Monotone check
        invalid_lst = list(lst)
        invalid_lst[-1] = 0
        thresholds.thresholds = invalid_lst
        try:
            self.voq_cgm_profile.set_averaging_configuration(0, thresholds)
            self.fail()
        except sdk.BaseException:
            pass

        # Out-of-range check
        invalid_lst[-1] = 1 << 30
        thresholds.thresholds = invalid_lst
        try:
            self.voq_cgm_profile.set_averaging_configuration(0, thresholds)
            self.fail()
        except sdk.BaseException:
            pass


if __name__ == '__main__':
    unittest.main()
