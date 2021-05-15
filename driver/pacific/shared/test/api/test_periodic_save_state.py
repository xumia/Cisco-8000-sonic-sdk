#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

from packet_test_utils import *
import os
import unittest
from leaba import sdk
import topology as T
import time
import glob
import tempfile
import shutil
import decor


@unittest.skip("Disabled because of occasional failure")
class periodic_save_state(unittest.TestCase):

    def setUp(self):
        import sim_utils

        self.device = sim_utils.create_device(1)
        self.topology = T.topology(self, self.device)
        self.options = sdk.save_state_options()

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_perioidc_save_state_output(self):
        save_period = 2000  # ms
        test_iteration_period = 2  # s
        file_prefix = tempfile.mkdtemp(prefix="")
        expected_number_of_files = 2
        maximum_time = 60
        test_succeeded = True

        self.options.include_status = True
        self.device.set_periodic_save_state_parameters(self.options, file_prefix)
        self.device.set_int_property(sdk.la_device_property_e_MAX_NUMBER_OF_PERIODIC_SAVE_STATE_FILES, 10)
        self.device.set_periodic_save_state_period(save_period)
        test_start_time = time.time()

        time.sleep(test_iteration_period)

        while True:
            time.sleep(test_iteration_period)
            time_diff_in_sec = time.time() - test_start_time
            number_of_dump_files = len(glob.glob(file_prefix + "_device_*"))

            if(time_diff_in_sec > maximum_time and number_of_dump_files < expected_number_of_files):
                # now stop the task and remove all of the old files.
                test_succeeded = False
                break

            if(number_of_dump_files >= expected_number_of_files):
                break

        # now stop the task and remove all of the old files.
        self.device.set_periodic_save_state_period(0)
        shutil.rmtree(file_prefix)

        assert(test_succeeded)
        return


if __name__ == '__main__':
    unittest.main()
