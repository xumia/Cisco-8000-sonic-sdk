#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import unittest
from leaba import sdk
from ipv4_lpts.ipv4_lpts_base import *
import topology as T
import ip_test_base
import packet_test_utils as U
import warm_boot_test_utils as wb
import os


wb.support_warm_boot()


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip in auto-WB sanity")
@unittest.skipUnless(decor.is_pacific() or decor.is_gibraltar(), "WB is currently supported by GB and PAC only")
class warm_boot_lpts_meters(ipv4_lpts_base):

    def setUp(self):
        super().setUp()

        METER_SET_SIZE = 1
        self.meter1 = T.create_meter_set(self, self.device, is_aggregate=True, set_size=METER_SET_SIZE)
        self.meter2 = T.create_meter_set(self, self.device, is_aggregate=True, set_size=METER_SET_SIZE)
        self.meter3 = T.create_meter_set(self, self.device, is_aggregate=True, set_size=METER_SET_SIZE)

        wb.warm_boot(self.device.device)
        self.lpts = self.create_lpts_instance(self.meter1, self.meter2, self.meter3)
        wb.warm_boot(self.device.device)
        self.setup_forus_dest()

        self.warm_boot_file_name = wb.get_warm_boot_file_name()

    def tearDown(self):
        super().tearDown()
        if os.path.exists(self.warm_boot_file_name):
            os.remove(self.warm_boot_file_name)

    def test_warm_boot_lpts_meters(self):
        wb.warm_boot(self.device.device)
        packet_count, byte_count = self.meter2.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packet_count, 0)
        self.assertEqual(byte_count, 0)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_UC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_UC, PUNT_SLICE, PUNT_IFG, PUNT_PIF_FIRST)

        wb.warm_boot(self.device.device)
        packet_count, byte_count = self.meter2.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packet_count, 1)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_MC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_MC, PUNT_SLICE, PUNT_IFG, PUNT_PIF_FIRST)

        wb.warm_boot(self.device.device)
        packet_count, byte_count = self.meter3.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packet_count, 1)

    def test_warm_boot_lpts_meters_sdk_down_kernel_module_up(self):
        wb.warm_boot(self.device.device)
        packet_count, byte_count = self.meter2.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packet_count, 0)
        self.assertEqual(byte_count, 0)

        py_objs_metadata = wb.warm_boot_disconnect(self.device.device, self.warm_boot_file_name)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_UC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_UC, PUNT_SLICE, PUNT_IFG, PUNT_PIF_FIRST)

        wb.warm_boot_reconnect(py_objs_metadata, self.warm_boot_file_name)

        packet_count, byte_count = self.meter2.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packet_count, 1)

        py_objs_metadata = wb.warm_boot_disconnect(self.device.device, self.warm_boot_file_name)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_MC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_MC, PUNT_SLICE, PUNT_IFG, PUNT_PIF_FIRST)

        wb.warm_boot_reconnect(py_objs_metadata, self.warm_boot_file_name)

        packet_count, byte_count = self.meter3.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packet_count, 1)


if __name__ == '__main__':
    unittest.main()
