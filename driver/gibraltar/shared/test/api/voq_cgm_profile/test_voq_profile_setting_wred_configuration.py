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
import decor
from leaba import sdk
from voq_cgm_profile_base import *

MIN_QUANT = 2 ** (-7)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_hw_gibraltar(), "SKIP-GB-HW")
class voq_profile_setting_wred_configuration(voq_cgm_profile_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_voq_profile_setting_wred_configuration(self):

        try:
            (res_action, res_probabilties) = self.voq_cgm_profile.get_wred_configuration()
            self.fail()
        except sdk.BaseException:
            pass

        lst = []
        expected_lst = []
        for i in range(0, sdk.la_voq_cgm_profile.WRED_NUM_BLOCKS_QUANTIZATION_REGIONS):
            lst.append(i * (1 / sdk.la_voq_cgm_profile.WRED_NUM_BLOCKS_QUANTIZATION_REGIONS))
        probabilities = sdk.wred_regions_probabilties()
        probabilities.probabilities = lst

        for action in [sdk.la_voq_cgm_profile.wred_action_e_PASS,
                       sdk.la_voq_cgm_profile.wred_action_e_MARK_ECN,
                       sdk.la_voq_cgm_profile.wred_action_e_DROP]:
            self.voq_cgm_profile.set_wred_configuration(action, probabilities)
            (res_action, res_probabilities) = self.voq_cgm_profile.get_wred_configuration()
            self.assertEqual(res_action, action)

        # Set/get check probabilities
        self.voq_cgm_profile.set_wred_configuration(sdk.la_voq_cgm_profile.wred_action_e_PASS, probabilities)
        (res_action, res_probabilties) = self.voq_cgm_profile.get_wred_configuration()
        res_lst = res_probabilities.probabilities
        for i in range(0, sdk.la_voq_cgm_profile.WRED_NUM_BLOCKS_QUANTIZATION_REGIONS):
            assert(abs(lst[i] - res_lst[i]) < MIN_QUANT), "WRED probabilities were not quantized correct"

        # Out-of-range check
        invalid_lst = list(lst)
        invalid_lst[0] = -1
        probabilities.probabilities = invalid_lst

        try:
            self.voq_cgm_profile.set_wred_configuration(sdk.la_voq_cgm_profile.wred_action_e_PASS, probabilities)
            self.fail()
        except sdk.BaseException:
            pass

        invalid_lst[0] = 1.1
        probabilities.probabilities = invalid_lst
        try:
            status = self.voq_cgm_profile.set_wred_configuration(sdk.la_voq_cgm_profile.wred_action_e_PASS, probabilities)
            self.fail()
        except sdk.BaseException:
            pass


if __name__ == '__main__':
    unittest.main()
