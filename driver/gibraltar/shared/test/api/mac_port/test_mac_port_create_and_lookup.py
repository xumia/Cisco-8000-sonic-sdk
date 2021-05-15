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
import topology as T
import re
from mac_port_base import *
import topology as T


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class mac_port_create_and_lookup(unittest.TestCase):

    def setUp(self):
        import sim_utils
        self.device = sim_utils.create_device(0)

    def tearDown(self):
        self.device.tearDown()

    def test_mac_port_create_and_lookup(self):
        slice_id = T.get_device_slice(2)
        ifg_id = 0
        num_serdes = 4 if decor.is_asic5() else 2
        speed = sdk.la_mac_port.port_speed_e_E_100G
        if T.is_matilda_model(self.device):
            speed = sdk.la_mac_port.port_speed_e_E_50G

        fc_mode = sdk.la_mac_port.fc_mode_e_NONE
        fec_mode = sdk.la_mac_port.fec_mode_e_RS_KR4
        first_serdes = T.get_device_first_serdes(8)
        last_serdes = first_serdes + num_serdes * 4 - 1

        # Create 4 mac ports, sharing the same mac_pool8[1]
        for first_serdes_id in range(first_serdes, last_serdes, num_serdes):
            last_serdes_id = first_serdes_id + num_serdes - 1
            self.device.create_mac_port(slice_id, ifg_id, first_serdes_id, last_serdes_id, speed, fc_mode, fec_mode)

        for i in self.device.get_used_slices():
            ifg_count = 1 if decor.is_asic5() else 2
            for j in range(ifg_count):
                serdes_source = self.device.get_serdes_source(i, j)
                max_count = len(serdes_source)
                for k in range(max_count):
                    try:
                        mac_port = self.device.get_mac_port(i, j, k)
                        self.assertEqual(mac_port.get_slice(), slice_id)
                        self.assertEqual(mac_port.get_ifg(), ifg_id)
                        self.assertTrue(mac_port.get_first_serdes_id() >= first_serdes)
                        self.assertTrue(mac_port.get_first_serdes_id() < last_serdes)
                    except sdk.BaseException as STATUS:
                        self.assertEqual(STATUS.args[0], sdk.la_status_e_E_NOTFOUND)

                try:
                    mac_port = self.device.get_mac_port(i, j, max_count)
                    self.assertEqual(mac_port.get_slice(), slice_id)
                    self.assertEqual(mac_port.get_ifg(), ifg_id)
                except sdk.BaseException as STATUS:
                    self.assertEqual(STATUS.args[0], sdk.la_status_e_E_OUTOFRANGE)


if __name__ == '__main__':
    unittest.main()
