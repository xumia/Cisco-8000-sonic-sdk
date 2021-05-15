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
from resource_handler_base import *
import unittest
import decor
import interrupt_utils
import os


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Auto restoring of notification pipes after WB not supported.")
class interrupt(resource_handler_base):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_raise_interrupt(self):
        # Open file descriptors for monitoring RESOURCE_MONITOR notifications.
        self.fd_critical, self.fd_resource = self.device.open_notification_fds(1 << sdk.la_notification_type_e_RESOURCE_MONITOR)

        # Setup thresholds.
        self.ts0 = sdk.la_resource_thresholds()
        self.ts1 = sdk.la_resource_thresholds()
        self.ts2 = sdk.la_resource_thresholds()
        self.ts = [self.ts0, self.ts1, self.ts2]

        # Configure valid thresholds.
        self.ts0.low_watermark = 0.2
        self.ts0.high_watermark = 0.3
        self.ts1.low_watermark = 0.4
        self.ts1.high_watermark = 0.5
        self.ts2.low_watermark = 0.6
        self.ts2.high_watermark = 0.8
        self.device.set_resource_notification_thresholds(sdk.la_resource_descriptor.type_e_TC_PROFILE, self.ts)

        # Vefiry initial state.
        ASIC_PL = os.getenv('ASIC') and os.getenv('ASIC').startswith('ASIC4')
        if ASIC_PL:
            self.num_init_tc_profiles_used = 0
        else:
            self.num_init_tc_profiles_used = 1  # Device creates default tc_profile on init for MCG counter support
        rd = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_TC_PROFILE)
        self.assertEqual(rd[0].state, 0)
        self.assertEqual(rd[0].used, self.num_init_tc_profiles_used)

        self.tc_profiles = []
        self.max_tc_profiles = self.device.get_limit(sdk.limit_type_e_DEVICE__NUM_TC_PROFILES)

        self._test_utilization_increasing()
        self._test_utilization_decreasing()
        self._test_bounce_utilization()
        self._test_invalid_threshold_config()

        self.device.close_notification_fds()

    def _test_invalid_threshold_config(self):
        self.ts0.low_watermark = 0.2
        self.ts0.high_watermark = 0.3
        self.ts1.low_watermark = 0.5
        self.ts1.high_watermark = 0.6
        self.ts2.low_watermark = 0.8
        self.ts2.high_watermark = 0.9
        self.ts = [self.ts1, self.ts0, self.ts2]           # Thresholds must be in increasing order.
        # Verify threshold validation.
        with self.assertRaises(sdk.InvalException):
            self.device.set_resource_notification_thresholds(sdk.la_resource_descriptor.type_e_TC_PROFILE, self.ts)

        self.ts = [self.ts0, self.ts1, self.ts2]
        self.ts1.low_watermark = 0.4
        self.ts1.high_watermark = 0.9        # Invalid threshold, cannot overlap.
        self.ts2.low_watermark = 0.8
        self.ts2.high_watermark = 0.9
        # Verify threshold validation.
        with self.assertRaises(sdk.InvalException):
            self.device.set_resource_notification_thresholds(sdk.la_resource_descriptor.type_e_TC_PROFILE, self.ts)

        self.ts1.high_watermark = 0.5
        self.ts2.high_watermark = 0.7        # Invalid threshold, high < low.
        # Verify threshold validation.
        with self.assertRaises(sdk.InvalException):
            self.device.set_resource_notification_thresholds(sdk.la_resource_descriptor.type_e_TC_PROFILE, self.ts)

    def _test_utilization_increasing(self):
        # Loop through all thresholds and verify resource notification is received
        # when utilization goes above high_threshold.
        for threshold in range(len(self.ts)):
            rd = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_TC_PROFILE)
            num_tc_profiles_to_create = int(self.max_tc_profiles * self.ts[threshold].high_watermark + 1) - rd[0].used
            for i in range(num_tc_profiles_to_create):
                self.tc_profiles.append(self.device.create_tc_profile())

            self._read_and_verify_notifications(1, threshold + 1)

    def _test_utilization_decreasing(self):
        # Loop through all thresholds and verify resource notification is received
        # when utilization goes below low_threshold.
        for threshold in reversed(range(len(self.ts))):
            rd = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_TC_PROFILE)
            num_tc_profiles_to_delete = rd[0].used - int(self.max_tc_profiles * self.ts[threshold].low_watermark + 1)

            for i in range(num_tc_profiles_to_delete):
                self.device.destroy(self.tc_profiles.pop())

            self._read_and_verify_notifications(0, 0)

            self.device.destroy(self.tc_profiles.pop())

            self._read_and_verify_notifications(1, threshold)

    def _test_bounce_utilization(self):
        # Bounce utilization above<->below low_watermark while keeping state the same.
        rd = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_TC_PROFILE)
        num_tc_profiles_to_create = int(self.max_tc_profiles * self.ts[0].low_watermark + 1) - rd[0].used
        for i in range(num_tc_profiles_to_create):
            self.tc_profiles.append(self.device.create_tc_profile())

        for i in range(num_tc_profiles_to_create):
            self.device.destroy(self.tc_profiles.pop())

        self._read_and_verify_notifications(0, 0)

        # Cause state to transition to state == 1.
        rd = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_TC_PROFILE)
        num_tc_profiles_to_create = int(self.max_tc_profiles * self.ts[0].high_watermark + 1) - rd[0].used
        for i in range(num_tc_profiles_to_create):
            self.tc_profiles.append(self.device.create_tc_profile())

        self._read_and_verify_notifications(1, 1)

        # Bounce utilization above<->below high_watermark while keeping state == 1.
        rd = self.device.get_resource_usage(sdk.la_resource_descriptor.type_e_TC_PROFILE)
        num_tc_profiles_to_delete = rd[0].used - (int(self.max_tc_profiles * self.ts[0].low_watermark) + 1)
        for i in range(num_tc_profiles_to_delete):
            self.device.destroy(self.tc_profiles.pop())

        for i in range(num_tc_profiles_to_delete):
            self.tc_profiles.append(self.device.create_tc_profile())

        self._read_and_verify_notifications(0, 0)

    def _read_and_verify_notifications(self, num_expected_notifications, expected_state):
        # Read and verify Resource utilization notifications.
        crit, norm = interrupt_utils.read_notifications(self.fd_critical, self.fd_resource, .1)
        desc_list = crit + norm
        self.assertEqual(len(desc_list), num_expected_notifications)
        if num_expected_notifications == 0:
            return

        desc = desc_list[0]
        self.assertEqual(desc.type, sdk.la_notification_type_e_RESOURCE_MONITOR)
        self.assertEqual(desc.u.resource_monitor.resource_usage.desc.m_resource_type, sdk.la_resource_descriptor.type_e_TC_PROFILE)
        self.assertEqual(desc.u.resource_monitor.resource_usage.state, expected_state)
        num_used_tc_profiles = len(self.tc_profiles) + self.num_init_tc_profiles_used
        self.assertEqual(desc.u.resource_monitor.resource_usage.used, num_used_tc_profiles)


if __name__ == '__main__':
    unittest.main()
