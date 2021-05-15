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


import unittest
import lldcli
import test_lldcli
import os
import lld_utils
import time
import decor


def is_hw_device():
    return os.getenv('SDK_DEVICE_NAME') is not None


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class testcase(unittest.TestCase):

    # Invoked once per class instance, a good place for expensive initializations
    # cls.ll_device and friends are accessible as self.ll_device
    def setUp(self):
        device_path = '/dev/testdev'

        device_id = 0
        self.ll_device = lldcli.ll_device_create(device_id, device_path)
        assert self.ll_device is not None, "ll_device_create failed"

        self.ll_device.reset()

        self.file_name = lld_utils.get_warm_boot_file_name()

    # Invoked once per class instance
    def tearDown(self):
        # Device has an open "client" connection with socket_device which is a "server".
        # First, take the "client" down, then the "server".
        self.ll_device = None

        if os.path.exists(self.file_name):
            os.remove(self.file_name)

    @unittest.skipIf(test_lldcli.is_clang_compilation(), "Skip if is compiled with clang - currently not working properly")
    @unittest.skipIf(not test_lldcli.is_serialization_supported(), "Skip if serialization not supported")
    @unittest.skipIf(is_hw_device(), "Skip for HW device")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_serialize(self):

        # reading the reg value
        original_value = self.ll_device.read_register(self.ll_device.get_device_tree_downcast().sbif.i2c_cfg_reg)

        # modifying the reg's value
        value_to_write = original_value + 2
        self.ll_device.write_register(self.ll_device.get_device_tree_downcast().sbif.i2c_cfg_reg, value_to_write)

        # serializing the ll_device
        print("using file name " + self.file_name, flush=True)
        start_time = time.time()
        test_lldcli.ll_device_serialize_save(self.ll_device, self.file_name)
        end_time = time.time()
        print("test_cereal save took %s seconds" % (end_time - start_time), flush=True)

        # clearing ll_device
        self.ll_device = None

        # loading the lld from the serialization file
        start_time = time.time()
        self.ll_device = test_lldcli.ll_device_serialize_load(self.file_name)
        end_time = time.time()
        print("test_cereal load took %s seconds" % (end_time - start_time), flush=True)

        # verifying the register now contains the serialized value
        self.assertEqual(self.ll_device.read_register(self.ll_device.get_device_tree_downcast().sbif.i2c_cfg_reg), value_to_write)


if __name__ == '__main__':
    unittest.main()
