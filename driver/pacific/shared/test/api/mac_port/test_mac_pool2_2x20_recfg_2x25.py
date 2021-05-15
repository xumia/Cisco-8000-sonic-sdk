#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import packet_test_utils
import re
from mac_port_base import *


# This test will re-configure mac port API from 2x20G (at serdes lane 16,17) to 2x25G.
# It will verify the register configuration (mac_pool2 register) or error will be asserted.

@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class mac_pool2_2x20_recfg_2x25(mac_port_base):

    @unittest.skipIf(not decor.is_pacific_A0(), "Test is enabled only on Pacific A0")
    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mac_pool2_2x20_recfg_2x25(self):
        slice_id = 0
        ifg_id = 0
        first_serdes_id = 0
        serdes_count = 2
        ports_per_ifg = 9
        speed = sdk.la_mac_port.port_speed_e_E_40G
        fec_modes = [sdk.la_mac_port.fec_mode_e_NONE]
        fc_modes = [sdk.la_mac_port.fc_mode_e_NONE]

        RECONFIG_PORT = 8
        RECONFIG_SPEED = sdk.la_mac_port.port_speed_e_E_50G
        RECONFIG_FC = sdk.la_mac_port.fc_mode_e_NONE
        RECONFIG_FEC = sdk.la_mac_port.fec_mode_e_NONE

        self.mac_port_setup(slice_id, ifg_id, first_serdes_id, serdes_count, ports_per_ifg, speed, fc_modes, fec_modes)

        if not self.slices_changed_from_default:
            packet_test_utils.compare_regs_mems(self, self.device, os.path.join(
                self.expected_dir, EXPECTED_JSON_FILENAME), 'mac_pool2_2x20_recfg_2x25__chk_2x20')

        self.mac_ports[RECONFIG_PORT].stop()

        self.mac_ports[RECONFIG_PORT].reconfigure(serdes_count,
                                                  RECONFIG_SPEED,
                                                  RECONFIG_FC,
                                                  RECONFIG_FC,
                                                  RECONFIG_FEC)

        if not self.slices_changed_from_default:
            packet_test_utils.compare_regs_mems(self, self.device, os.path.join(
                self.expected_dir, EXPECTED_JSON_FILENAME), 'mac_pool2_2x20_recfg_2x25__chk_2x25')

        out_speed = self.mac_ports[RECONFIG_PORT].get_speed()
        self.assertEqual(out_speed, RECONFIG_SPEED)

        out_fc = self.mac_ports[RECONFIG_PORT].get_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR)
        self.assertEqual(out_fc, RECONFIG_FC)

        out_fec = self.mac_ports[RECONFIG_PORT].get_fec_mode()
        self.assertEqual(out_fec, RECONFIG_FEC)

        out_lb_mode = self.mac_ports[RECONFIG_PORT].get_loopback_mode()
        self.assertEqual(out_lb_mode, sdk.la_mac_port.loopback_mode_e_NONE)


if __name__ == '__main__':
    unittest.main()
