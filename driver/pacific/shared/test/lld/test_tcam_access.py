#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

from leaba import sdk
import unittest
import lldcli
import sim_utils
import decor


class tcam_access_test(unittest.TestCase):
    def setUp(self):
        self.device = sim_utils.create_device(0, initialize=False)
        self.ll_device = self.device.get_ll_device()
        self.ll_device.set_shadow_read_enabled(False)

        self.device_tree = self.ll_device.get_gibraltar_tree()
        self.key_mask_tcam = self.device_tree.npuh.fi.fi_core_tcam

    def tearDown(self):
        self.device.tearDown()
        self.ll_device = None
        self.device_tree = None
        self.key_mask_tcam = None

    @unittest.skipUnless(decor.is_gibraltar(), "Test is enabled only on Gibraltar")
    def test_tcam_acess(self):
        tcam_line = 2
        key = 0x0800
        mask = 0x1800

        self.ll_device.write_tcam(self.key_mask_tcam, tcam_line, key, mask)

        (read_key, read_mask, read_valid) = self.ll_device.read_tcam(self.key_mask_tcam, tcam_line)

        self.assertTrue(read_valid, "Expected true, but got false")
        self.assertEqual(read_key, key, "Expected {}, but got {}".format(key, read_key))
        self.assertEqual(read_mask, mask, "Expected {}, but got {}".format(mask, read_mask))

        self.ll_device.invalidate_tcam(self.key_mask_tcam, tcam_line)

        (read_key, read_mask, read_valid) = self.ll_device.read_tcam(self.key_mask_tcam, tcam_line)

        self.assertFalse(read_valid, "Expected false, but got true")

        print("Test succesfully finished!")


if __name__ == '__main__':
    unittest.main()
