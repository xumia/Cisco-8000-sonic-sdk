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

DEBUG_MODE = 0

import time


@unittest.skipUnless(decor.is_pacific() and (decor.is_hw_device()), "Fast Tune can be tested only on HW Pacific.")
class mac_port_fast_tune(unittest.TestCase):
    slice_id = 2
    ifg_id = 0
    speed = sdk.la_mac_port.port_speed_e_E_100G
    fc_mode = sdk.la_mac_port.fc_mode_e_NONE
    fec_mode = sdk.la_mac_port.fec_mode_e_RS_KR4
    first_serdes_id = 8
    last_serdes_id = 11
    serdes_count = (last_serdes_id - first_serdes_id) + 1
    AVAGO_LSB = 2
    AVAGO_TUNING_EFFORT = 0x306

    def setUp(self):
        import sim_utils
        self.device = sim_utils.create_device(0)

    def tearDown(self):
        self.device.tearDown()

    def set_fast_tune(self, value):
        for serdes in range(self.first_serdes_id, self.last_serdes_id + 1):
            rx_fast_tune_mode = sdk.la_mac_port.serdes_param_mode_e_FIXED
            rx_fast_tune_val = value
            self.port.set_serdes_parameter(
                serdes % self.serdes_count,
                sdk.la_mac_port.serdes_param_stage_e_ACTIVATE,
                sdk.la_mac_port.serdes_param_e_RX_FAST_TUNE,
                rx_fast_tune_mode,
                rx_fast_tune_val)
            out_rx_fast_tune_mode, out_rx_fast_tune_val = self.port.get_serdes_parameter(
                serdes % self.serdes_count, sdk.la_mac_port.serdes_param_stage_e_ACTIVATE, sdk.la_mac_port.serdes_param_e_RX_FAST_TUNE)
            self.assertEqual(rx_fast_tune_mode, out_rx_fast_tune_mode)
            self.assertEqual(rx_fast_tune_val, out_rx_fast_tune_val)

    def check_avago_aapl_fast_tune(self, value):
        # AAPL is available only for Pacific, import here
        import aaplcli

        for serdes in range(self.first_serdes_id, self.last_serdes_id + 1):
            tune_val = value
            avago_serdes = serdes + 1
            aapl = self.device.get_ifg_aapl_handler(self.slice_id, self.ifg_id)
            out_tune_val = aaplcli.avago_serdes_mem_rd(aapl, avago_serdes, self.AVAGO_LSB, self.AVAGO_TUNING_EFFORT)
            self.assertEqual(tune_val, out_tune_val)

    @unittest.skipUnless(decor.is_pacific() and decor.is_hw_device(), "Fast Tune can be tested only on HW Pacific.")
    def test_mac_port_fast_tune(self):
        if DEBUG_MODE:
            sdk.la_set_logging_level(self.device.get_id(), sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(self.device.get_id(), sdk.la_logger_component_e_MAC_PORT, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(self.device.get_id(), sdk.la_logger_component_e_API, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(self.device.get_id(), sdk.la_logger_component_e_SERDES, sdk.la_logger_level_e_DEBUG)

        self.port = self.device.create_mac_port(
            self.slice_id,
            self.ifg_id,
            self.first_serdes_id,
            self.last_serdes_id,
            self.speed,
            self.fc_mode,
            self.fec_mode)

        # Getters that are expected to return status other than LA_STATUS_SUCCESS
        with self.assertRaises(sdk.NotFoundException):
            self.port.get_serdes_parameter(self.first_serdes_id - 8, sdk.la_mac_port.serdes_param_stage_e_ACTIVATE,
                                           sdk.la_mac_port.serdes_param_e_RX_FAST_TUNE)

        # Enable Fast Tune, 1
        self.set_fast_tune(1)

        # Activate
        self.port.activate()

        # Check Avago AAPL is set to fast tune, 16
        self.check_avago_aapl_fast_tune(16)

        # Stop
        self.port.stop()

        # Disable Fast Tune, 0
        self.set_fast_tune(0)

        # Sleep 1 second to avoid SBus Master ... PRBS reconfigure timed out
        time.sleep(1)

        # Activate
        self.port.activate()

        # Check Avago AAPL is set to full tune, 1
        self.check_avago_aapl_fast_tune(1)

        # Stop
        self.port.stop()

        self.assertTrue(True)


if __name__ == '__main__':
    unittest.main()
