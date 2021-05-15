#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import lldcli
import os
import decor


def is_hw_device():
    return os.getenv('SDK_DEVICE_NAME') is not None


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class testcase(unittest.TestCase):

    # Invoked once per class instance, a good place for expensive initializations
    # cls.ll_device and friends are accessible as self.ll_device
    @classmethod
    def setUpClass(cls):
        device_path = os.getenv('SDK_DEVICE_NAME')
        if not device_path:
            device_path = '/dev/testdev'

        device_id = 0
        cls.ll_device = lldcli.ll_device_create(device_id, device_path)
        assert cls.ll_device is not None, "ll_device_create failed"

        cls.ll_device.reset()

    # Invoked once per class instance
    @classmethod
    def tearDownClass(cls):
        # Device has an open "client" connection with socket_device which is a "server".
        # First, take the "client" down, then the "server".
        cls.ll_device = None

    @unittest.skipUnless(is_hw_device(), "Skip for simulated device")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_good_bad_mix_hw(self):
        self.ll_device.reset_access_engines()

        # Issue a bad write, addr==0xffffffff is out of range.
        self.ll_device.write_register_raw(0x10, 0xffffffff, 1, 1)

        # AE fifo contains a bad command, any command issued after that is expected to fail.
        expected_read_ok = False
        self.good_read(expected_read_ok, "Good read #1 after a bad write")
        self.good_read(expected_read_ok, "Good read #2 after a bad write")

        # Check that the access engine is back to normal after "reset".
        self.ll_device.reset_access_engines()
        expected_read_ok = True
        self.good_read(expected_read_ok, "Good read #3 after a bad write + ae reset")
        self.good_read(expected_read_ok, "Good read #4 after a bad write + ae reset")

    @unittest.skipIf(is_hw_device(), "Skip for HW device")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_good_bad_mix_simulated(self):
        self.ll_device.reset_access_engines()

        # Issue a bad write, addr==0xffffffff is out of range.
        self.ll_device.write_register_raw(0x10, 0xffffffff, 1, 1)

        # No AE state on simulated device, all the following commands are expected to succeed.
        expected_read_ok = True
        self.good_read(expected_read_ok, "Good read #1 after a bad write")
        self.ll_device.reset_access_engines()
        self.good_read(expected_read_ok, "Good read #2 after a bad write + ae reset")

    def good_read(self, expected_read_ok, message):
        try:
            self.ll_device.read_register_raw(0x10, 0, 1)
            read_ok = True
        except BaseException as status:
            read_ok = False

        self.assertEqual(read_ok, expected_read_ok, message)


if __name__ == '__main__':
    unittest.main()
