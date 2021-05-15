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

import os
import lld_utils
import lld_serialize_base
import unittest
import test_lldcli
import lldcli
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipUnless(lld_utils.is_warm_boot_supported(), "Warm Boot not supported!")
class lld_serialize_device_tree(lld_serialize_base.lld_serialize_base):

    def setUp(self):
        super().setUp()
        self.ll_device.set_shadow_read_enabled(True)
        self.serial_file = lld_utils.get_warm_boot_file_name()

    def tearDown(self):
        if os.path.exists(self.serial_file):
            os.remove(self.serial_file)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_lld_serialize_device_tree(self):
        self.pre_serial_state_file = "/tmp/dt_pre.{}.txt".format(self.timestamp)
        self.post_serial_state_file = "/tmp/dt_post.{}.txt".format(self.timestamp)

        device_tree = self.ll_device.get_device_tree_downcast()
        self.write_registers_and_verify(self.ll_device, device_tree)
        self.write_memories_and_verify(self.ll_device, device_tree)

        print("Dumping device tree to file {}...".format(self.pre_serial_state_file))
        lld_utils.dump_device_tree(device_tree, self.ll_device, self.pre_serial_state_file)

        # serializing the ll_device
        print("Saving LLD to serialization file {}...".format(self.serial_file))
        test_lldcli.ll_device_serialize_save(self.ll_device, self.serial_file)

        # destroy ll_device
        del self.ll_device

        # loading the lld from the serialization file
        print("Loading LLD from serialization file {}...".format(self.serial_file))
        self.ll_device = test_lldcli.ll_device_serialize_load(self.serial_file)
        self.ll_device.post_restore(self.device_path)

        device_tree = self.ll_device.get_device_tree_downcast()
        print("Dumping device tree to file {}...".format(self.post_serial_state_file))
        lld_utils.dump_device_tree(device_tree, self.ll_device, self.post_serial_state_file)

        print("Comparing files {} and {}...".format(self.pre_serial_state_file, self.post_serial_state_file))
        with open(self.pre_serial_state_file, 'r') as fd1, open(self.post_serial_state_file, 'r') as fd2:
            self.assertEqual(fd1.read(), fd2.read(),
                             "Files {} and {} differ!".format(self.pre_serial_state_file, self.post_serial_state_file))


if __name__ == '__main__':
    unittest.main()
