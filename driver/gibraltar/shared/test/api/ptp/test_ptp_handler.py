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
from leaba import debug


class test_ptp_handler(unittest.TestCase):

    def setUp(self):
        import sim_utils
        self.device = sim_utils.create_device(0)
        self.dd = debug.debug_device(self.device)
        self.ptp_handler = self.device.get_ptp_handler()

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipUnless(decor.is_gibraltar() and decor.is_hw_device(), "Test is only enabled on Gibraltar")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ptp_handler_gibraltar(self):
        # Enable pads before starting tests
        # need to enable pads, SW tells CPU to send signal to DEVICE_TIME_LOAD_PAD
        pads_config = sdk.ptp_pads_config()
        pads_config.device_time_load_enable = True
        pads_config.device_time_sync_ck_enable = True

        pads_config.device_time_load_delay = 0
        pads_config.device_time_sync_ck_delay = 0

        # trigger LOAD_TIME_EVENTS using CPU triggers
        self.ptp_handler.enable_load_event_generation(True)

        # run tests
        self.check_config_registers(pads_config)
        self.check_network_time()
        self.check_time_unit()
        self.adjust_device_time()

    @unittest.skipUnless(decor.is_pacific() and decor.is_hw_device(), "Test is only enabled on Pacific")
    def test_ptp_handler_pacific(self):
        # We cannot test anything that uses the DEVICE_TIME_LOAD signal
        pads_config = sdk.ptp_pads_config()
        pads_config.device_time_load_enable = True
        pads_config.device_time_sync_ck_enable = False

        pads_config.device_time_load_delay = 15
        pads_config.device_time_sync_ck_delay = 7

        # verify config registers
        self.check_config_registers(pads_config)

    def adjust_device_time(self):
        sw_tuning_config = sdk.ptp_sw_tuning_config()
        sw_tuning_config.increment = True
        sw_tuning_config.period = 1
        sw_tuning_config.repeat = 10

        self.ptp_handler.adjust_device_time(sw_tuning_config)

    def check_time_unit(self):
        # [frequency, clock_comp_val, clock_comp_period]
        frequencies_to_check_in_hz = [
            [int(1 * 1e9), 0, 0],
            [int(1.2 * 1e9), 1, 3],
            [int(1.35 * 1e9), 26, 27],
            [int(1.15 * 1e9), 5, 23]
        ]
        time_unit = sdk.ptp_time_unit()

        for frequency_settings in frequencies_to_check_in_hz:
            time_unit.frequency = frequency_settings[0]
            time_unit.clock_frac_comp_val = frequency_settings[1]
            time_unit.clock_frac_comp_period = frequency_settings[2]

            self.ptp_handler.load_new_time_unit(time_unit)

            # get time unit
            current_time_unit = self.ptp_handler.get_time_unit()

            # check values
            self.assertEqual(current_time_unit.frequency, time_unit.frequency,
                             "PTP time unit component 'frequency' does not match loaded value")
            self.assertEqual(current_time_unit.clock_frac_comp_val, time_unit.clock_frac_comp_val,
                             "PTP time unit component 'clock_frac_comp_val' does not match loaded value")
            self.assertEqual(current_time_unit.clock_frac_comp_period, time_unit.clock_frac_comp_period,
                             "PTP time unit component 'clock_frac_comp_period' does not match loaded value")

    def check_network_time(self):
        ph = self.ptp_handler

        # network time
        time_to_load = sdk.ptp_time()

        time_to_load.time_of_day = 35  # seconds
        time_to_load.device_time = 0  # ns

        # We are assuming that the function pair below will execute within 1 second
        # load network time
        ph.load_new_time(time_to_load)
        # get network time
        captured_time = ph.capture_time()

        # device time updates too quickly, won't test
        self.assertEqual(captured_time.time_of_day, time_to_load.time_of_day, "Time-Of-Day does not match expected value")

    def check_config_registers(self, pad_config):
        ph = self.ptp_handler

        ph.set_pad_config(pad_config)

        # offset by 2 ns
        offset_subns = 2 * (2 ** 20)

        # set config registers and execute commands
        ph.set_load_time_offset(offset_subns)

        # get all config values
        r_pad_config = ph.get_pad_config()
        r_offset_subns = ph.get_load_time_offset()

        # verify
        self.assertEqual(
            r_pad_config.device_time_load_enable,
            pad_config.device_time_load_enable,
            "Configured pad enabled does not match expected value")
        self.assertEqual(
            r_pad_config.device_time_sync_ck_enable,
            pad_config.device_time_sync_ck_enable,
            "Configured pad enabled does not match expected value")

        self.assertEqual(
            r_pad_config.device_time_load_delay,
            pad_config.device_time_load_delay,
            "Configured delay value does not match expected value")
        self.assertEqual(
            r_pad_config.device_time_sync_ck_delay,
            pad_config.device_time_sync_ck_delay,
            "Configured delay value does not match expected value")

        self.assertEqual(r_offset_subns, offset_subns, "Configured time offset does not match expected value")


if __name__ == '__main__':
    unittest.main()
