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
import decor
import lld_serialize_base
import unittest
import lld_utils
import lldcli
import test_lldcli


@unittest.skipUnless(lld_utils.is_warm_boot_supported(), "Warm Boot not supported!")
class lld_serialize_device_reconnect(lld_serialize_base.lld_serialize_base):

    def setUp(self):
        super().setUp(create_simulator=True)
        self.ll_device.set_shadow_read_enabled(False)
        self.ll_device.set_flush_after_write(True)
        self.file_name = lld_utils.get_warm_boot_file_name()

    def tearDown(self):
        if os.path.exists(self.file_name):
            os.remove(self.file_name)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_lld_serialize_device_reconnect(self):
        device_tree = self.ll_device.get_device_tree_downcast()
        self.write_registers_and_verify(self.ll_device, device_tree)
        self.write_memories_and_verify(self.ll_device, device_tree)

        # serializing the ll_device
        print("Saving LLD to serialization file {}...".format(self.file_name))
        test_lldcli.ll_device_serialize_save(self.ll_device, self.file_name)

        # destroy ll_device
        del self.ll_device

        # loading the lld from the serialization file
        print("Loading LLD from serialization file {}...".format(self.file_name))
        self.ll_device = test_lldcli.ll_device_serialize_load(self.file_name)

        if not decor.is_hw_device():
            self.connect_to_simulator()
        self.ll_device.post_restore(self.device_path)

        device_tree = self.ll_device.get_device_tree_downcast()
        self.read_registers_and_verify(self.ll_device, device_tree)
        self.read_memories_and_verify(self.ll_device, device_tree)


if __name__ == '__main__':
    unittest.main()
