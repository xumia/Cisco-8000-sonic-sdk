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
import os
import json
from mac_port_base import *

verbose = 0

SLICE_ID = 2
IFG_ID = 0
FIRST_SERDES_ID = 8
LAST_SERDES_ID = 11
PRBS_SETUP_DELAY = 10


@unittest.skipIf(decor.is_hw_asic3(), "This test is not yet enabled on GR-HW")
@unittest.skipUnless(decor.is_pacific() or decor.is_gibraltar() or decor.is_asic3(), "Test is not yet enabled for this ASIC")
class mac_port_setters(mac_port_base):
    def setUp(self):

        super().setUp()

        speed = sdk.la_mac_port.port_speed_e_E_100G
        fc_mode = sdk.la_mac_port.fc_mode_e_NONE
        fec_mode = sdk.la_mac_port.fec_mode_e_RS_KR4

        if verbose >= 1:
            sdk.la_set_logging_level(self.dev_id, sdk.la_logger_component_e_API, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(self.dev_id, sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(self.dev_id, sdk.la_logger_component_e_MAC_PORT, sdk.la_logger_level_e_DEBUG)

        self.device.create_mac_port(SLICE_ID, IFG_ID, FIRST_SERDES_ID, LAST_SERDES_ID, speed, fc_mode, fec_mode)

    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW.")
    def test_mac_port_setters(self):
        port = self.device.get_mac_port(SLICE_ID, IFG_ID, FIRST_SERDES_ID)

        set_vals = {}
        # set_an_enabled
        val = port.get_an_enabled()
        set_vals['an_enabled'] = not val
        port.set_an_enabled(set_vals['an_enabled'])

        # set_link_management_enabled
        val = port.get_link_management_enabled()
        set_vals['link_management'] = not val
        port.set_link_management_enabled(set_vals['link_management'])

        self.verify_mac_port_state(port, set_vals)

    # set_serdes_test_mode
    @unittest.skipUnless(decor.is_hw_device(), "Run only in HW.")
    def test_serdes_mode(self):
        port = self.device.get_mac_port(SLICE_ID, IFG_ID, FIRST_SERDES_ID)
        if self.device.ll_device.is_pacific():
            # Certain serial TX/RX checkers for pacific do not support certain test modes
            for test_mode in range(sdk.la_mac_port.serdes_test_mode_e_PRBS9, sdk.la_mac_port.serdes_test_mode_e_PRBS16):
                port.set_serdes_continuous_tuning_enabled(False)
                port.set_serdes_test_mode(sdk.la_serdes_direction_e_TX, test_mode)
                set_mode_tx = port.get_serdes_test_mode(sdk.la_serdes_direction_e_TX)
                self.assertEqual(test_mode, set_mode_tx, "Serdes TX mode does not match expected value.")
                port.set_serdes_continuous_tuning_enabled(False)
                port.set_serdes_test_mode(sdk.la_serdes_direction_e_RX, sdk.la_mac_port.serdes_test_mode_e_NONE)
                port.set_serdes_test_mode(sdk.la_serdes_direction_e_RX, test_mode)
                set_mode_rx = port.get_serdes_test_mode(sdk.la_serdes_direction_e_RX)
                self.assertEqual(test_mode, set_mode_rx, "Serdes RX mode does not match expected value.")
        if self.device.ll_device.is_gibraltar():
            # Serial RX checker does not support checking PRBS9_4 and PRBS58
            na = [sdk.la_mac_port.serdes_test_mode_e_PRBS9_4, sdk.la_mac_port.serdes_test_mode_e_PRBS58]
            for test_mode in range(sdk.la_mac_port.serdes_test_mode_e_NONE, sdk.la_mac_port.serdes_test_mode_e_LAST):
                port.set_serdes_test_mode(sdk.la_serdes_direction_e_TX, test_mode)
                set_mode_tx = port.get_serdes_test_mode(sdk.la_serdes_direction_e_TX)
                self.assertEqual(test_mode, set_mode_tx, "Serdes TX mode does not match expected value.")
                if test_mode not in na:
                    port.set_serdes_test_mode(sdk.la_serdes_direction_e_RX, sdk.la_mac_port.serdes_test_mode_e_NONE)
                    port.set_serdes_test_mode(sdk.la_serdes_direction_e_RX, test_mode)
                    set_mode_rx = port.get_serdes_test_mode(sdk.la_serdes_direction_e_RX)
                    self.assertEqual(test_mode, set_mode_rx, "Serdes RX mode does not match expected value.")

    # To-do: working with traffic
    # set_serdes_signal_control
    @unittest.skipUnless(decor.is_gibraltar(), "Test is enabled on SRM")
    def test_serdes_signal(self):
        port = self.device.get_mac_port(SLICE_ID, IFG_ID, FIRST_SERDES_ID)

        for direction, control in [(sdk.la_serdes_direction_e_RX, sdk.la_serdes_direction_e_TX),
                                   (sdk.la_mac_port.serdes_ctrl_e_DISABLE_SQUELCH, sdk.la_mac_port.serdes_ctrl_e_ENABLE_SQUELCH)]:
            port.set_serdes_signal_control(0, direction, control)

    # To-do: add verifying save state to mac_port_base.py
    def verify_mac_port_state(self, port, set_vals):
        # save_state is not yet implemented in GR
        if(decor.is_asic3()):
            self.assertEqual(port.get_an_enabled(), set_vals['an_enabled'],
                             "MAC port's auto-negotiation mode does not match expected value.")
            self.assertEqual(
                port.get_link_management_enabled(),
                set_vals['link_management'],
                "MAC port's auto-negotiation mode does not match expected value.")
            return
        state = self.save_mac_port_state(port)
        keys = list(state.keys())
        root_key = keys[0]
        self.assertEqual(state[root_key]['mac_port_soft_state']['an_enabled'], set_vals['an_enabled'],
                         "MAC port's auto-negotiation mode does not match expected value.")
        self.assertEqual(
            state[root_key]['mac_port_soft_state']['link_management'],
            set_vals['link_management'],
            "MAC port's auto-negotiation mode does not match expected value.")


if __name__ == '__main__':
    unittest.main()
