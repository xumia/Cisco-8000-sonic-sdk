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

import os
import unittest
from leaba import sdk
import decor
import re
import topology as T
from mac_port_base import *

DEBUG_MODE = 0


@unittest.skipUnless(decor.is_pacific(), "LC-56 is only valid for Pacific.")
@unittest.skipIf(decor.is_matilda(), "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
class lc_56_create_fabric_mac_port(unittest.TestCase):
    port1_slice_id = 0
    port1_ifg_id = 0
    port1_first_serdes_id = 16
    port1_last_serdes_id = 17

    port2_slice_id = 2
    port2_ifg_id = 1
    port2_first_serdes_id = 16
    port2_last_serdes_id = 17

    speed = sdk.la_mac_port.port_speed_e_E_100G
    fc_mode = sdk.la_mac_port.fc_mode_e_NONE
    fec_mode = sdk.la_mac_port.fec_mode_e_RS_KR4
    loopback_mode = sdk.la_mac_port.loopback_mode_e_NONE

    def setUp(self):
        import sim_utils
        self.device = sim_utils.create_device(0, slice_modes=sim_utils.LINECARD_3N_3F_DEV, initialize=False)
        self.device.initialize(sdk.la_device.init_phase_e_DEVICE)

        for sid in range(3):
            self.device.set_slice_mode(sid, sdk.la_slice_mode_e_NETWORK)
            self.device.set_slice_mode(sid + 3, sdk.la_slice_mode_e_CARRIER_FABRIC)

        if DEBUG_MODE:
            sdk.la_set_logging_level(self.device.get_id(), sdk.la_logger_component_e_RECONNECT, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(self.device.get_id(), sdk.la_logger_component_e_MAC_PORT, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(self.device.get_id(), sdk.la_logger_component_e_API, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(self.device.get_id(), sdk.la_logger_component_e_SERDES, sdk.la_logger_level_e_XDEBUG)

    def tearDown(self):
        if self.device is not None:
            self.device.tearDown()
            self.device = None

    def mac_port_1_check(self):
        try:
            mac_port_1 = self.device.get_mac_port(self.port1_slice_id, self.port1_ifg_id, self.port1_first_serdes_id)
            self.assertEqual(mac_port_1.get_slice(), self.port1_slice_id)
            self.assertEqual(mac_port_1.get_ifg(), self.port1_ifg_id)
            self.assertEqual(mac_port_1.get_first_serdes_id(), self.port1_first_serdes_id)
            self.assertEqual(mac_port_1.get_num_of_serdes(), 2)
        except sdk.BaseException as STATUS:
            self.assertEqual(STATUS.args[0], sdk.la_status_e_E_NOTFOUND)

    def mac_port_2_check(self):
        try:
            mac_port_2 = self.device.get_mac_port(self.port2_slice_id, self.port2_ifg_id, self.port2_first_serdes_id)
            self.assertEqual(mac_port_2.get_slice(), self.port2_slice_id)
            self.assertEqual(mac_port_2.get_ifg(), self.port2_ifg_id)
            self.assertEqual(mac_port_2.get_first_serdes_id(), self.port2_first_serdes_id)
            self.assertEqual(mac_port_2.get_num_of_serdes(), 2)
        except sdk.BaseException as STATUS:
            self.assertEqual(STATUS.args[0], sdk.la_status_e_E_NOTFOUND)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_lc_56_false(self):
        self.device.set_bool_property(sdk.la_device_property_e_LC_56_FABRIC_PORT_MODE, False)
        self.device.initialize(sdk.la_device.init_phase_e_TOPOLOGY)

        # Create Fabric port on 0/0/16 - expect fail
        with self.assertRaises(sdk.InvalException):
            fabric_mac_port_1 = self.device.create_fabric_mac_port(
                self.port1_slice_id,
                self.port1_ifg_id,
                self.port1_first_serdes_id,
                self.port1_last_serdes_id,
                self.speed,
                self.fc_mode)

        # Create Fabric port on 2/1/16 - expect fail
        with self.assertRaises(sdk.InvalException):
            fabric_mac_port_2 = self.device.create_fabric_mac_port(
                self.port2_slice_id,
                self.port2_ifg_id,
                self.port2_first_serdes_id,
                self.port2_last_serdes_id,
                self.speed,
                self.fc_mode)

        # Create Network on 0/0/16 - expect ok
        network_mac_port_1 = self.device.create_mac_port(
            self.port1_slice_id,
            self.port1_ifg_id,
            self.port1_first_serdes_id,
            self.port1_last_serdes_id,
            self.speed,
            self.fc_mode,
            self.fec_mode)
        network_mac_port_1.set_loopback_mode(self.loopback_mode)

        self.mac_port_1_check()

        # Create Network port on 2/1/16 - expect ok
        network_mac_port_2 = self.device.create_mac_port(
            self.port2_slice_id,
            self.port2_ifg_id,
            self.port2_first_serdes_id,
            self.port2_last_serdes_id,
            self.speed,
            self.fc_mode,
            self.fec_mode)
        network_mac_port_2.set_loopback_mode(self.loopback_mode)

        self.mac_port_2_check()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_lc_56_true(self):
        self.device.set_bool_property(sdk.la_device_property_e_LC_56_FABRIC_PORT_MODE, True)
        self.device.initialize(sdk.la_device.init_phase_e_TOPOLOGY)

        # Create Network port on 0/0/16 - expect fail
        with self.assertRaises(sdk.InvalException):
            network_mac_port_1 = self.device.create_mac_port(
                self.port1_slice_id,
                self.port1_ifg_id,
                self.port1_first_serdes_id,
                self.port1_last_serdes_id,
                self.speed,
                self.fc_mode,
                self.fec_mode)

        # Create Network port on 2/1/16 - expect fail
        with self.assertRaises(sdk.InvalException):
            network_mac_port_2 = self.device.create_mac_port(
                self.port2_slice_id,
                self.port2_ifg_id,
                self.port2_first_serdes_id,
                self.port2_last_serdes_id,
                self.speed,
                self.fc_mode,
                self.fec_mode)

        # Create Fabric port on 0/0/16 - expect ok
        fabric_mac_port_1 = self.device.create_fabric_mac_port(
            self.port1_slice_id,
            self.port1_ifg_id,
            self.port1_first_serdes_id,
            self.port1_last_serdes_id,
            self.speed,
            self.fc_mode)
        fabric_mac_port_1.set_loopback_mode(self.loopback_mode)
        fabric_port_1 = self.device.create_fabric_port(fabric_mac_port_1)

        self.mac_port_1_check()

        # Create Fabric port on 2/1/16 - expect ok
        fabric_mac_port_2 = self.device.create_fabric_mac_port(
            self.port2_slice_id,
            self.port2_ifg_id,
            self.port2_first_serdes_id,
            self.port2_last_serdes_id,
            self.speed,
            self.fc_mode)
        fabric_mac_port_2.set_loopback_mode(self.loopback_mode)
        fabric_port_2 = self.device.create_fabric_port(fabric_mac_port_2)

        self.mac_port_2_check()


if __name__ == '__main__':
    unittest.main()
