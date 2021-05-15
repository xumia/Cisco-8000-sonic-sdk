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

from leaba import sdk
import decor
import unittest

#import training_next_hop_utils


@unittest.skipIf(decor.is_hw_device(), "Skip for HW device.")
class profiler_database(unittest.TestCase):

    def setUp(self):
        self.device = sdk.la_create_device('/dev/testdev', 0)
        self.device.initialize(sdk.la_device.init_phase_e_DEVICE)
        # self.device.initialize_slice_id_manager()

    def tearDown(self):
        sdk.la_destroy_device(self.device)

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_profile_database(self):

        db = sdk.la_profile_database.get_instance()

        # after this the database should be empty
        db.reset()
        db.report()

        for i in self.device.get_used_slices():
            self.device.set_slice_mode(i, sdk.la_slice_mode_e_NETWORK)

        db.report()
        db.reset()
        for i in range(10):
            self.device.set_slice_mode(0, sdk.la_slice_mode_e_NETWORK)

        db.report()

    # Invoked once per class instance
    @classmethod
    def tearDownClass(cls):
        sdk.la_profile_database.get_instance().report()


if __name__ == '__main__':
    unittest.main()
