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
import os
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class d2d_iface_test(unittest.TestCase):

    NUM_SLICES = 8
    ASIC7_D2D_START_UNIT_IDS = (14, 142, 270, 398, 526, 654, 782, 910)
    NUM_D2D_UNIT_IDS = 25

    def setUp(self):
        device_path = os.getenv('SDK_DEVICE_NAME')
        device_id = 0
        self.ll_device = lldcli.ll_device_create(device_id, device_path)
        self.d2d = lldcli.d2d_iface_create(self.ll_device)
        self.assertNotEqual(self.ll_device, None, "ll_device_create failed")

        self.tree = self.ll_device.get_asic3_tree()

        self.assertNotEqual(self.tree, None, "Failed to get device tree")

        self.ll_device.reset()

        self.ll_device.reset_access_engines()

    def tearDown(self):
        self.ll_device = None
        self.tree = None

    @unittest.skipUnless(decor.is_asic3(), "This test is currently supported on Asic3 only!")
    def test_d2d_iface(self):
        self.d2d.initialize()
        self.d2d_test()

    def d2d_test(self):
        for slice_id in range(self.NUM_SLICES):
            out_ids = self.d2d.get_all_unit_ids(slice_id)

            for unit_id_idx in range(self.NUM_D2D_UNIT_IDS):
                assert_val = self.ASIC7_D2D_START_UNIT_IDS[slice_id] + unit_id_idx

                self.assertEqual(out_ids[unit_id_idx], assert_val, "Assertion failed: expected {} but got {}".format(
                    out_ids[unit_id_idx], assert_val))

            # Read unit_valid_reg
            valid_reg = self.d2d.get_all_unit_ids_valid(slice_id)

            assert_val = pow(2, self.NUM_D2D_UNIT_IDS) - 1

            self.assertEqual(valid_reg, assert_val, "Assertion failed: expected {} but got {}".format(valid_reg, assert_val))

        # Check setting valid/invalid unit id
        for slice_id in range(self.NUM_SLICES):
            for unit_id_idx in range(self.NUM_D2D_UNIT_IDS):
                self.d2d.set_unit_id_valid(slice_id, self.ASIC7_D2D_START_UNIT_IDS[slice_id] + unit_id_idx, False)
                bit_valid = self.d2d.get_unit_id_valid(slice_id, self.ASIC7_D2D_START_UNIT_IDS[slice_id] + unit_id_idx)

                self.assertFalse(bit_valid, "Assertion failed: expected {} but got {}".format(False, bit_valid))

                self.d2d.set_unit_id_valid(slice_id, self.ASIC7_D2D_START_UNIT_IDS[slice_id] + unit_id_idx, True)
                bit_valid = self.d2d.get_unit_id_valid(slice_id, self.ASIC7_D2D_START_UNIT_IDS[slice_id] + unit_id_idx)

                self.assertTrue(bit_valid, "Assertion failed: expected {} but got {}".format(True, bit_valid))

            # Check all unit ids valid read/write
            self.d2d.set_all_unit_ids_valid(slice_id, 0xAAAAAAAA)
            valid_reg = self.d2d.get_all_unit_ids_valid(slice_id)

            self.assertEqual(valid_reg, 0xAAAAAAAA, "Assertion failed: expected {} but got {}".format(valid_reg, assert_val))

            # Check unit ids list write/read
            unit_ids_list = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                             14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
            self.d2d.set_all_unit_ids(slice_id, unit_ids_list)
            out_ids_list = self.d2d.get_all_unit_ids(slice_id)

            self.assertEqual(out_ids_list, unit_ids_list, "Assertion failed: Lists are not the same!")


if __name__ == '__main__':
    unittest.main()
