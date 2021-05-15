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

import unittest
from leaba import sdk
import sim_utils
import topology as T
from tm_transmit_scheduler_base import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ifg_scheduler(tm_transmit_scheduler_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ifg_scheduler(self):
        slice_id = T.get_device_slice(2)
        ifg_id = 0
        slice_id_inval = 7

        rate = 10 * GIGA  # 10 Gbps
        rate_get = 0

        burst = 16  # 16 - Max accumulated number of credits in the generator
        burst_get = 0

        try:
            self.device.get_ifg_scheduler(slice_id_inval, ifg_id)
            self.assertFail()
        except sdk.BaseException:
            pass

        try:
            self.device.get_ifg_scheduler(slice_id_inval, ifg_id)
            self.assertFail()
        except sdk.BaseException:
            pass

        ts = self.device.get_ifg_scheduler(slice_id, ifg_id)
        self.assertNotEqual(ts, None)


if __name__ == '__main__':
    unittest.main()
