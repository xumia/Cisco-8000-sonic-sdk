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
from resource_handler_base import *

import decor
import unittest
from leaba import sdk


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class voq_cgm_profiles(resource_handler_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_voq_cgm_profiles(self):
        LOW_WATERMARK = 0
        HIGH_WATERMARK = 0
        rd = sdk.la_resource_descriptor()
        rd.m_resource_type = sdk.la_resource_descriptor.type_e_VOQ_CGM_PROFILE
        res = self.device.get_resource_usage(rd)
        self.assertEqual(res.used, 0)
        self.assertEqual(res.state, 0)

        thresholds = sdk.la_resource_thresholds()
        thresholds.low_watermark = LOW_WATERMARK
        thresholds.high_watermark = HIGH_WATERMARK
        rt = [thresholds]
        self.device.set_resource_notification_thresholds(rd.m_resource_type, rt)
        res_thresholds = self.device.get_resource_notification_thresholds(rd.m_resource_type)

        self.assertEqual(res_thresholds[0].low_watermark, LOW_WATERMARK)
        self.assertEqual(res_thresholds[0].high_watermark, HIGH_WATERMARK)

        self.voq_cgm_profile = self.device.create_voq_cgm_profile()
        res = self.device.get_resource_usage(rd)
        self.assertEqual(res.used, 1)
        self.assertEqual(res.state, 1)


if __name__ == '__main__':
    unittest.main()
