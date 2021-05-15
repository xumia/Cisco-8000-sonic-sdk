#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import sim_utils
import unittest
from leaba import sdk
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class la_assert_unit_test(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(1)

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_la_assert(self):

        for i in range(sdk.dassert.level_e_CRITICAL, sdk.dassert.level_e_NUM_LEVELS, 1):

            print("get_settings(", i, ")")
            s = sdk.la_assert_get_settings(i)

            print("invert.")
            s_inv = sdk.settings()
            s_inv.skip = s.skip
            s_inv.terminate = s.terminate
            s_inv.backtrace = s.backtrace
            s_inv.proc_maps = s.proc_maps
            s_inv.skip = not s_inv.skip
            s_inv.terminate = not s_inv.terminate
            s_inv.backtrace = not s_inv.backtrace
            s_inv.proc_maps = not s_inv.proc_maps

            print("set")
            sdk.la_assert_set_settings(i, s_inv)

            print("get")
            s_read = sdk.la_assert_get_settings(i)

            print("compare")
            self.assertEqual(s_inv.skip, s_read.skip), "Error in testing la_assert interface, did not read back set value."
            self.assertEqual(s_inv.terminate, s_read.terminate), "Error in testing la_assert interface, did not read back set value."
            self.assertEqual(s_inv.backtrace, s_read.backtrace), "Error in testing la_assert interface, did not read back set value."
            self.assertEqual(s_inv.proc_maps, s_read.proc_maps), "Error in testing la_assert interface, did not read back set value."


if __name__ == '__main__':
    unittest.main()
