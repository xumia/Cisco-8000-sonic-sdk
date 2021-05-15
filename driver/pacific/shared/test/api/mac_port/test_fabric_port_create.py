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
import sim_utils
import mac_port_helper
import topology as T


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "WB fails for FE mode")
@unittest.skipIf(decor.is_matilda(), "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
class fabric_mac_port_create(unittest.TestCase):
    fabric_mac_ports = []

    def tearDown(self):
        self.mph.teardown()
        self.device.tearDown()

    def create_device(self, mode):
        self.device_id = 0
        self.mph = mac_port_helper.mac_port_helper()
        self.device = sim_utils.create_device(self.device_id, slice_modes=mode)
        self.mph.init(self.device)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_fabric_port_create_lc(self):
        self.create_device(sim_utils.LINECARD_3N_3F_DEV)
        for slice in [3, 4, 5]:
            for ifg in range(2):
                for first_serdes in range(int(self.device.get_num_of_serdes(slice, ifg) / 2)):
                    self.fabric_mac_ports.append(
                        self.mph.create_fabric_mac_port(
                            slice,
                            ifg,
                            first_serdes * 2,
                            2,
                            sdk.la_mac_port.port_speed_e_E_100G,
                            sdk.la_mac_port.fc_mode_e_NONE,
                            sdk.la_mac_port.loopback_mode_e_SERDES))

    @unittest.skipIf(decor.is_asic4(), "FE mode is not supported on PL")
    @unittest.skipIf(decor.is_asic5(), "FE mode is not supported on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_fabric_port_create_fe(self):
        self.create_device(sim_utils.FABRIC_ELEMENT_DEV)
        if self.mph.ll_device.is_gibraltar():
            max_serdes = [10, 8, 10, 8, 8, 10, 10, 8, 8, 10, 8, 10]
        else:
            max_serdes = [9] * 12
        for ifg in range(12):
            for first_serdes in range(max_serdes[ifg]):
                self.fabric_mac_ports.append(
                    self.mph.create_fabric_mac_port(
                        int(ifg / 2),
                        ifg % 2,
                        first_serdes * 2,
                        2,
                        sdk.la_mac_port.port_speed_e_E_100G,
                        sdk.la_mac_port.fc_mode_e_NONE,
                        sdk.la_mac_port.loopback_mode_e_SERDES))


if __name__ == '__main__':
    unittest.main()
