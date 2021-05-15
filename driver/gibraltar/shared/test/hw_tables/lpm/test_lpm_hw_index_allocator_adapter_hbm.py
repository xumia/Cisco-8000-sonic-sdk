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

import os
import unittest
import hw_tablescli
import lldcli
import decor

ASIC_GB = os.getenv('ASIC') and os.getenv('ASIC').startswith('GIBRALTAR')

NAME = "MY ADAPTER"
NUM_OF_SRAM_BUCKETS = 4096
NUM_OF_SRAM_LINES = NUM_OF_SRAM_BUCKETS // 2
DEVICE_PATH = "/dev/testdev"

NUM_BUCKETS_PER_SRAM_LINE = 2
NUM_OF_HBM_BUCKETS = 200
BUCKET_NUM_FIXED_ENTRIES = 2
BUCKET_NUM_SHARED_ENTRIES = 4


class hw_index_allocator_adapter_hbm(unittest.TestCase):
    def setUp(self):
        self.ll_device = lldcli.ll_device_create(0, DEVICE_PATH)
        self.hw_index_allocator = hw_tablescli.lpm_hw_index_allocator_adapter_hbm(
            NAME, self.ll_device, NUM_OF_SRAM_LINES, NUM_OF_HBM_BUCKETS)

    def tearDown(self):
        self.hw_index_allocator = None

    @unittest.skipIf(decor.is_asic3(), "Test is not enabled on GR, HBM doesn't exists in GR")
    def test_allocate_hw_index_for_bucket(self):
        num_sram = self.hw_index_allocator.get_number_of_free_indices_in_sram()
        self.assertEqual(num_sram, NUM_OF_SRAM_LINES)

        total = self.hw_index_allocator.get_number_of_free_indices()
        self.assertEqual(total, NUM_OF_SRAM_LINES + NUM_OF_HBM_BUCKETS)

        # Allocating in SRAM
        sram_hw_index = self.hw_index_allocator.allocate_hw_index_for_bucket(hw_tablescli.l2_bucket_location_e_SRAM)
        self.hw_index_allocator.commit()
        num_sram = self.hw_index_allocator.get_number_of_free_indices_in_sram()
        total = self.hw_index_allocator.get_number_of_free_indices()
        self.assertEqual(num_sram, NUM_OF_SRAM_LINES - 1)
        self.assertEqual(total, NUM_OF_SRAM_LINES + NUM_OF_HBM_BUCKETS - 1)

        hbm_hw_index = self.hw_index_allocator.allocate_hw_index_for_bucket(hw_tablescli.l2_bucket_location_e_HBM)
        self.hw_index_allocator.commit()
        num_sram = self.hw_index_allocator.get_number_of_free_indices_in_sram()
        total = self.hw_index_allocator.get_number_of_free_indices()
        self.assertEqual(num_sram, NUM_OF_SRAM_LINES - 1)
        self.assertEqual(total, NUM_OF_SRAM_LINES + NUM_OF_HBM_BUCKETS - 2)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_allocate_specific_hw_index_for_bucket(self):
        occ = hw_tablescli.occupancy_data()
        hw_index = 20
        is_free = self.hw_index_allocator.is_hw_index_free(hw_index)
        self.assertTrue(is_free)
        self.hw_index_allocator.allocate_specific_hw_index_for_bucket(occ, hw_index)
        self.hw_index_allocator.commit()
        is_free = self.hw_index_allocator.is_hw_index_free(hw_index)
        self.assertFalse(is_free)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_release_hw_index(self):
        occ = hw_tablescli.occupancy_data()
        hw_index = self.hw_index_allocator.allocate_hw_index_for_bucket(occ)
        self.hw_index_allocator.commit()
        is_free = self.hw_index_allocator.is_hw_index_free(hw_index)
        self.assertFalse(is_free)

        self.hw_index_allocator.release_hw_index(hw_index)
        self.hw_index_allocator.commit()
        is_free = self.hw_index_allocator.is_hw_index_free(hw_index)
        self.assertTrue(is_free)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_oor(self):
        occ = hw_tablescli.occupancy_data()
        for idx in range(NUM_OF_SRAM_LINES):
            self.hw_index_allocator.allocate_hw_index_for_bucket(occ)
        self.hw_index_allocator.commit()

        num_sram = self.hw_index_allocator.get_number_of_free_indices_in_sram()
        self.assertEqual(num_sram, 0)
        total = self.hw_index_allocator.get_number_of_free_indices()
        self.assertEqual(total, NUM_OF_HBM_BUCKETS)

        with self.assertRaises(hw_tablescli.ResourceException):
            self.hw_index_allocator.allocate_hw_index_for_bucket(hw_tablescli.l2_bucket_location_e_SRAM)

        for idx in range(NUM_OF_HBM_BUCKETS):
            self.hw_index_allocator.allocate_hw_index_for_bucket(occ)
        self.hw_index_allocator.commit()
        total = self.hw_index_allocator.get_number_of_free_indices()
        self.assertEqual(total, 0)

        with self.assertRaises(hw_tablescli.ResourceException):
            self.hw_index_allocator.allocate_hw_index_for_bucket(occ)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_notify_hw_index_occupancy_changed(self):
        occ = hw_tablescli.occupancy_data()
        hw_index = self.hw_index_allocator.allocate_hw_index_for_bucket(hw_tablescli.l2_bucket_location_e_SRAM)
        self.hw_index_allocator.commit()

        self.hw_index_allocator.notify_hw_index_occupancy_changed(hw_index, occ)
        self.hw_index_allocator.commit()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_withdraw(self):
        occ = hw_tablescli.occupancy_data()
        num_hw_index_to_allocate = 10
        for idx in range(num_hw_index_to_allocate):
            self.hw_index_allocator.allocate_hw_index_for_bucket(hw_tablescli.l2_bucket_location_e_SRAM)
            self.hw_index_allocator.allocate_hw_index_for_bucket(hw_tablescli.l2_bucket_location_e_HBM)
        self.hw_index_allocator.commit()

        num_sram = self.hw_index_allocator.get_number_of_free_indices_in_sram()
        self.assertEqual(num_sram + num_hw_index_to_allocate, NUM_OF_SRAM_LINES)

        total = self.hw_index_allocator.get_number_of_free_indices()
        self.assertEqual(total, NUM_OF_SRAM_LINES + NUM_OF_HBM_BUCKETS - (2 * num_hw_index_to_allocate))

        # Withdraw
        for idx in range(num_hw_index_to_allocate):
            self.hw_index_allocator.allocate_hw_index_for_bucket(hw_tablescli.l2_bucket_location_e_SRAM)
            self.hw_index_allocator.allocate_hw_index_for_bucket(hw_tablescli.l2_bucket_location_e_HBM)
        self.hw_index_allocator.withdraw()

        num_sram = self.hw_index_allocator.get_number_of_free_indices_in_sram()
        self.assertEqual(num_sram + num_hw_index_to_allocate, NUM_OF_SRAM_LINES)

        total = self.hw_index_allocator.get_number_of_free_indices()
        self.assertEqual(total, NUM_OF_SRAM_LINES + NUM_OF_HBM_BUCKETS - (2 * num_hw_index_to_allocate))


if __name__ == '__main__':
    unittest.main()
