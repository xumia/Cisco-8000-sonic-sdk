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

from packet_test_utils import *
import sim_utils
import unittest
import time
import topology as T
from leaba import sdk


class la_assert_unit_test(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(1)
        self.topology = T.topology(self, self.device)
        self.ldev = self.device.get_ll_device()
        self.device_tree = sim_utils.get_device_tree(self.ldev)

    def tearDown(self):
        self.device.tearDown()

    def get_current_exec_period(self, sample_time):
        heartbeat_start = self.device.get_heartbeat()

        start_time = time.time()
        time.sleep(sample_time)
        elapsed_time_ms = (time.time() - start_time) * 1000

        heartbeat_end = self.device.get_heartbeat()

        return [elapsed_time_ms / (heartbeat_end.slow - heartbeat_start.slow),
                elapsed_time_ms / (heartbeat_end.fast - heartbeat_start.fast)]

    def test_fast_slow_poll_conf_api(self):
        # let the system settle down. Let the polling cbs start.
        time.sleep(0.5)

        new_slow_period = 110
        new_fast_period = 70

        margin_of_error = 0.2

        self.device.set_int_property(sdk.la_device_property_e_POLL_INTERVAL_MILLISECONDS, new_slow_period)
        self.device.set_int_property(sdk.la_device_property_e_POLL_FAST_INTERVAL_MILLISECONDS, new_fast_period)

        measured_period_of_execution = self.get_current_exec_period(1)

        self.assertGreater(measured_period_of_execution[0], new_slow_period - new_slow_period * margin_of_error)
        self.assertLess(measured_period_of_execution[0], new_slow_period + new_slow_period * margin_of_error)

        self.assertGreater(measured_period_of_execution[1], new_fast_period - new_fast_period * margin_of_error)
        self.assertLess(measured_period_of_execution[1], new_fast_period + new_fast_period * margin_of_error)

        match = False
        for i in range(10):
            heartbeat_slow_api = self.device.get_heartbeat().slow
            heartbeat_slow_css = self.ldev.read_memory(
                self.device_tree.sbif.css_mem_even,
                sdk.la_css_memory_layout_e_HEARTBEAT_SLOW // 4)
            if(heartbeat_slow_api == heartbeat_slow_css):
                match = True
                break

        self.assertTrue(match, "heartbeat returned from api call doesn't match heartbeat in css memory")

        time.sleep(10)


if __name__ == '__main__':
    unittest.main()
