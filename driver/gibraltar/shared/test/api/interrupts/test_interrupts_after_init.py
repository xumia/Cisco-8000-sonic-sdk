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

import unittest
from leaba import sdk
import decor
import interrupt_utils
import lldcli
import time

verbose = 0


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipUnless(decor.is_hw_device(), "Requires HW device")
class testcase(unittest.TestCase):

    def setUp(self):
        device_id = 0
        import sim_utils
        self.device = sim_utils.create_device(device_id)
        self.critical_fd, self.normal_fd = self.device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)

        if verbose >= 1:
            sdk.la_set_logging_level(self.device.get_id(), sdk.la_logger_component_e_INTERRUPT, sdk.la_logger_level_e_DEBUG)

    def tearDown(self):
        if verbose >= 1:
            sdk.la_set_logging_level(self.device.get_id(), sdk.la_logger_component_e_INTERRUPT, sdk.la_logger_level_e_DEBUG)

        self.device.close_notification_fds()
        self.device.tearDown()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_interrupts_after_init(self):
        # Sleep long enough so that non-wired interrupts will have a chance to be polled.
        time.sleep(1.5)
        crit, norm = interrupt_utils.read_notifications(self.critical_fd, self.normal_fd, .1)
        self.assertEqual(len(crit) + len(norm), 0)

        # Toggle PROCESS_INTERRUPTS, this also toggles the MSI mask
        self.device.set_bool_property(sdk.la_device_property_e_PROCESS_INTERRUPTS, False)
        time.sleep(1.5)
        self.device.set_bool_property(sdk.la_device_property_e_PROCESS_INTERRUPTS, True)

        time.sleep(1.5)
        crit, norm = interrupt_utils.read_notifications(self.critical_fd, self.normal_fd, .1)
        if len(crit) + len(norm) > 0:
            print('ERROR: got unexpected interrupts after initialize(TOPOLOGY)')
            interrupt_utils.dump_notifications(self.device_tree, crit, norm)
        self.assertEqual(len(crit) + len(norm), 0)


if __name__ == '__main__':
    unittest.main()
