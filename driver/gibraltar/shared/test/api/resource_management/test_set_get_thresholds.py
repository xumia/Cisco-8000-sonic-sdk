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
class set_get_thresholds(resource_handler_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_get_thresholds(self):
        resource_type = sdk.la_resource_descriptor.type_e_VOQ_CGM_PROFILE
        res = self.device.get_resource_notification_thresholds(resource_type)
        self.assertEqual(len(res), 0)

        rt1 = sdk.la_resource_thresholds()
        rt1.high_watermark = 0.3
        rt1.low_watermark = 0.2
        rt2 = sdk.la_resource_thresholds()
        rt2.high_watermark = 0.6
        rt2.low_watermark = 0.5
        rt3 = sdk.la_resource_thresholds()
        rt3.high_watermark = 0.9
        rt3.low_watermark = 0.8
        rt = [rt1, rt2, rt3]
        res = self.device.set_resource_notification_thresholds(resource_type, rt)
        res = self.device.get_resource_notification_thresholds(resource_type)
        self.assertEqual(len(res), len(rt))
        for i in range(len(res)):
            self.assertEqual(res[i].high_watermark, rt[i].high_watermark)
            self.assertEqual(res[i].low_watermark, rt[i].low_watermark)


if __name__ == '__main__':
    unittest.main()
