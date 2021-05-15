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


# note: this is a temporary test that tests a simple serialization in lld.
# once a proper testing is done for serialization, this test can be removed.

from leaba import sdk
import unittest
import lldcli
import cpu2jtagcli
import os
import decor


@unittest.skipUnless(decor.is_asic3(), "This test is currently supported on Asic3 only!")
class cpu2jtag_test(unittest.TestCase):

    CPU2JTAG_ID = 0x124bc215

    def setUp(self):
        device_path = os.getenv('SDK_DEVICE_NAME')

        device_id = 0
        self.ll_device = lldcli.ll_device_create(device_id, device_path)
        self.assertNotEqual(self.ll_device, None, "ll_device_create failed")

        self.tree = self.ll_device.get_asic3_tree()

        self.assertNotEqual(self.tree, None, "Failed to get device tree")

        self.ll_device.reset()

        self.ll_device.reset_access_engines()

        self.tap = None

    def tearDown(self):
        self.ll_device = None
        self.tree = None
        self.tap = None

    def test_cpu2jtag(self):
        self.tap = cpu2jtagcli.cpu2jtag_create(self.ll_device)
        # These numbers are not currently used since TCK is hardcoded to 2
        core_freq_khz, tck_freq_mhz = 100 * 1000, 8333
        self.tap.enable(core_freq_khz, tck_freq_mhz)

        self.ll_device.write_register(self.tree.top_regfile.force_sel_main_tap, 0x2)
        self.tap.load_ir_dr(0x33, 30, 0)
        jtag_id = self.tap.load_ir_dr(0x34, 32, 0)
        self.assertEqual(jtag_id, self.CPU2JTAG_ID, "Assertion failed, wrong cpu2jtag ID!")


if __name__ == '__main__':
    unittest.main()
