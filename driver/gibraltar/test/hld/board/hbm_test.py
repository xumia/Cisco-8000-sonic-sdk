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
from leaba import debug
import lldcli
import aaplcli

HBM_FW_VER = 0x554
HBM_FW_BUILD = 0x2002


class test_hbm(unittest.TestCase):

    def setUp(self):
        sdk.set_error_mode(sdk.error_mode_e_EXCEPTION)
        lldcli.set_error_mode(lldcli.error_mode_e_EXCEPTION)

        self.device_id = 0
        self.device_name = '/dev/uio0'
        self.device = sdk.la_create_device(self.device_name, self.device_id)
        self.device.set_bool_property(sdk.la_device_property_e_ENABLE_HBM, True)
        self.device.initialize(sdk.la_device.init_phase_e_DEVICE)

        self.ll_device = self.device.get_ll_device()
        self.pacific_tree = self.ll_device.get_pacific_tree()
        self.debug_device = debug.debug_device(self.device)

    def tearDown(self):
        sdk.la_destroy_device(self.device)

    def test_hbm_init(self):
        ahlo = self.device.get_hbm_aapl_handler(0)
        ahhi = self.device.get_hbm_aapl_handler(1)
        hbml = self.device.get_hbm_handler(0)
        hbmh = self.device.get_hbm_handler(1)

        tmp_lo = self.device.get_temperature(sdk.la_temperature_sensor_e_PACIFIC_HBM_SENSOR_1)
        tmp_hi = self.device.get_temperature(sdk.la_temperature_sensor_e_PACIFIC_HBM_SENSOR_2)

        self.assertNotEqual(tmp_lo, 0)
        self.assertNotEqual(tmp_hi, 0)

        # Test low-level access
        fw_ver = aaplcli.avago_spico_int(ahlo, 0xfd, 0, 0)
        self.assertEqual(fw_ver, HBM_FW_VER)

        fw_ver = aaplcli.avago_spico_int(ahhi, 0xfd, 0, 0)
        self.assertEqual(fw_ver, HBM_FW_VER)

        # Test HBM handler API
        fw_ver = hbml.get_firmware_version_id()
        self.assertEqual(fw_ver, HBM_FW_VER)
        fw_ver = hbmh.get_firmware_version_id()
        self.assertEqual(fw_ver, HBM_FW_VER)

        fw_build = hbml.get_firmware_build_id()
        self.assertEqual(fw_build, HBM_FW_BUILD)
        fw_build = hbmh.get_firmware_build_id()
        self.assertEqual(fw_build, HBM_FW_BUILD)

    def print_hbm_error_counters(self):
        hbm_error_counters = self.debug_device.get_hbm_error_counters()
        for intf in range(len(hbm_error_counters)):
            print('HBM interface {}'.format(intf))
            hbm_intf_error_counters = hbm_error_counters[intf]
            for hbm_errors_info in hbm_intf_error_counters:
                print(
                    'HBM {channel} errors: write {write_parity}, addr {addr_parity}, read {read_parity}, 1b {1bit_ecc}, 2b {1bit_ecc}'.format(
                        **hbm_errors_info))


if __name__ == '__main__':
    # unittest.main()
    tc = test_hbm()
    tc.setUp()

    tc.test_hbm_init()
