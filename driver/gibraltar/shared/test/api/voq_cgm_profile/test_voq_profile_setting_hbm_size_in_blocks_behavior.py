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
class voq_profile_setting_hbm_size_in_blocks_behavior(voq_cgm_profile_base):

    @unittest.skipIf(decor.is_pacific(), "Test is not yet enabled on Pacific")
    #@unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_voq_profile_setting_hbm_size_in_blocks_drop_behavior(self):
        self.key = sdk.la_cgm_hbm_size_in_blocks_key(1, 1, 1)
        drop_val = sdk.la_cgm_hbm_size_in_blocks_drop_val()
        for drop_color in [sdk.la_qos_color_e_GREEN, sdk.la_qos_color_e_YELLOW, sdk.la_qos_color_e_NONE]:
            drop_val.drop_color_level = drop_color
            self.voq_cgm_profile.set_hbm_size_in_blocks_drop_behavior(self.key, drop_val)
            out_drop_val = sdk.la_cgm_hbm_size_in_blocks_drop_val()
            self.voq_cgm_profile.get_hbm_size_in_blocks_drop_behavior(self.key, out_drop_val)
            self.assertEqual(drop_val.drop_color_level, out_drop_val.drop_color_level)

    @unittest.skipIf(decor.is_pacific(), "Test is not yet enabled on Pacific")
    #@unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_voq_profile_setting_hbm_size_in_blocks_mark_behavior(self):
        self.key = sdk.la_cgm_hbm_size_in_blocks_key(1, 1, 1)
        mark_val = sdk.la_cgm_hbm_size_in_blocks_mark_ecn_val()
        for mark_ecn_color in [sdk.la_qos_color_e_GREEN, sdk.la_qos_color_e_YELLOW, sdk.la_qos_color_e_NONE]:
            mark_val.mark_ecn_color_level = mark_ecn_color
            self.voq_cgm_profile.set_hbm_size_in_blocks_mark_ecn_behavior(self.key, mark_val)
            out_mark_val = sdk.la_cgm_hbm_size_in_blocks_mark_ecn_val()
            self.voq_cgm_profile.get_hbm_size_in_blocks_mark_ecn_behavior(self.key, out_mark_val)
            self.assertEqual(mark_val.mark_ecn_color_level, out_mark_val.mark_ecn_color_level)

        self.key = sdk.la_cgm_hbm_size_in_blocks_key(0, 1, 1)
        for mark_ecn_color in [sdk.la_qos_color_e_GREEN, sdk.la_qos_color_e_YELLOW, sdk.la_qos_color_e_RED]:
            mark_val = sdk.la_cgm_hbm_size_in_blocks_mark_ecn_val(mark_ecn_color)
            with self.assertRaises(sdk.InvalException):
                self.voq_cgm_profile.set_hbm_size_in_blocks_mark_ecn_behavior(self.key, mark_val)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    # This test case should be removed once legacy pacific APIs are not supported.
    def test_voq_profile_setting_hbm_size_in_blocks_behavior_pacific(self):
        try:
            (res_color, res_mark) = self.voq_cgm_profile.get_hbm_size_in_blocks_behavior(0, 0)
            self.fail()
        except sdk.BaseException:
            pass

        for color in [sdk.la_qos_color_e_GREEN, sdk.la_qos_color_e_YELLOW, sdk.la_qos_color_e_NONE]:
            self.voq_cgm_profile.set_hbm_size_in_blocks_behavior(0, 0, color, True)
            (res_color, res_mark) = self.voq_cgm_profile.get_hbm_size_in_blocks_behavior(0, 0)
            self.assertEqual(res_color, color)

        for mark in [True, False]:
            self.voq_cgm_profile.set_hbm_size_in_blocks_behavior(0, 0, sdk.la_qos_color_e_GREEN, mark)
            (res_color, res_mark) = self.voq_cgm_profile.get_hbm_size_in_blocks_behavior(0, 0)
            self.assertEqual(res_mark, mark)

        for i in range(0, sdk.LA_CGM_NUM_HBM_BLOCKS_BY_VOQ_QUANTIZATION_REGIONS - 1):
            self.voq_cgm_profile.set_hbm_size_in_blocks_behavior(i, 0, sdk.la_qos_color_e_GREEN, True)
            (res_color, res_mark) = self.voq_cgm_profile.get_hbm_size_in_blocks_behavior(i, 0)
            self.assertEqual(res_color, sdk.la_qos_color_e_GREEN)

        try:
            self.voq_cgm_profile.set_hbm_size_in_blocks_behavior(
                sdk.LA_CGM_NUM_HBM_BLOCKS_BY_VOQ_QUANTIZATION_REGIONS - 1, 0, sdk.la_qos_color_e_GREEN, True)
            self.fail()
        except sdk.BaseException:
            pass

        for i in range(0, sdk.LA_CGM_NUM_HBM_POOL_FREE_BLOCKS_QUANTIZATION_REGIONS):
            self.voq_cgm_profile.set_hbm_size_in_blocks_behavior(0, i, sdk.la_qos_color_e_GREEN, True)
            (res_color, res_mark) = self.voq_cgm_profile.get_hbm_size_in_blocks_behavior(0, i)
            self.assertEqual(res_color, sdk.la_qos_color_e_GREEN)

        try:
            self.voq_cgm_profile.set_hbm_size_in_blocks_behavior(
                0, sdk.LA_CGM_NUM_HBM_POOL_FREE_BLOCKS_QUANTIZATION_REGIONS, sdk.la_qos_color_e_GREEN, True)
            self.fail()
        except sdk.BaseException:
            pass


if __name__ == '__main__':
    unittest.main()
