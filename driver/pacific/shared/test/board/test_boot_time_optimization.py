#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import uut_provider
import os
import time
import decor

device_id = 0

verbose = 1

IMPROVEMENT_ACCEPTANCE_THRESHOLD = 20  # seconds

BLACKTIP_UTILS_PATH = "/cad/leaba/BSP/current/blacktip"
BLACKTIP_POWER_CYCLE_SCRIPT = BLACKTIP_UTILS_PATH + "/device_power_cycle.sh"


@unittest.skip("Test fails port sanity")
@unittest.skipUnless(decor.is_hw_gibraltar(), "TODO: Test for Pacific and implement for other ASICs")
class boot_time_optimization(unittest.TestCase):
    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_CREATED:
            device.set_bool_property(sdk.la_device_property_e_ENABLE_BOOT_OPTIMIZATION, True)

    @staticmethod
    def device_power_cycle():
        if os.path.exists(BLACKTIP_POWER_CYCLE_SCRIPT) is None:
            return False
        import subprocess
        rc = subprocess.run(BLACKTIP_POWER_CYCLE_SCRIPT, shell=True)
        assert(rc.returncode == 0)
        return True

    @staticmethod
    def print_msg(message):
        if verbose > 0:
            print("{} : {}".format(__file__, message))

    def setUp(self):
        boot_time_optimization.print_msg("Power-cycling device..")
        ret = boot_time_optimization.device_power_cycle()
        self.assertTrue(ret)
        boot_time_optimization.print_msg("Power cycle completed")

    def create_device(self):
        db = sdk.la_profile_database.get_instance()
        db.reset()
        device = sim_utils.create_device(device_id, device_config_func=boot_time_optimization.device_config_func)

        db.report()

        return device

    def do_create_destory_device(self):
        start = time.time()
        device = self.create_device()
        elapsed = time.time() - start

        boot_optimization_enabled = device.get_bool_property(sdk.la_device_property_e_ENABLE_BOOT_OPTIMIZATION)
        self.assertTrue(boot_optimization_enabled)

        sdk.la_destroy_device(device)

        return elapsed

    def test_cold_boot_optimization(self):
        hot_boot_and_destroy_duration = self.do_create_destory_device()
        cold_boot_and_destroy_duration = self.do_create_destory_device()

        diff = hot_boot_and_destroy_duration - cold_boot_and_destroy_duration

        boot_time_optimization.print_msg(
            "Hot boot duration = {:.2f} s. Cold boot duration = {:.2f} s. Difference = {:.2f} s (Improvement acceptance threshold = {:.2f} s)".format(
                hot_boot_and_destroy_duration, cold_boot_and_destroy_duration, diff, IMPROVEMENT_ACCEPTANCE_THRESHOLD))

        self.assertTrue(diff >= IMPROVEMENT_ACCEPTANCE_THRESHOLD)


if __name__ == '__main__':
    unittest.main()
