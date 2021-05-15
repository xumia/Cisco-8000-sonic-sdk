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
import hw_tablescli
import decor


FIRST_INDEX = 4096
NUM_INDEXES = 1000
STEP = 2


class hw_index_allocator_singles(unittest.TestCase):
    def setUp(self):
        self.hw_index_allocator = hw_tablescli.lpm_hw_index_singles_allocator(
            "INDEX ALLOCATOR CORE=0 LEVEL=0", FIRST_INDEX, NUM_INDEXES, STEP)

    def tearDown(self):
        self.hw_index_allocator = None

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_allocate_hw_index_for_bucket(self):
        num_indexes = self.hw_index_allocator.get_number_of_free_indices()
        self.assertEqual(num_indexes, NUM_INDEXES)

        # Allocating index
        hw_index = self.hw_index_allocator.allocate_hw_index_for_bucket(0)
        self.hw_index_allocator.commit()
        num_indexes = self.hw_index_allocator.get_number_of_free_indices()
        self.assertEqual(num_indexes, NUM_INDEXES - 1)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_allocate_specific_hw_index_for_bucket(self):
        hw_index = FIRST_INDEX + 20
        is_free = self.hw_index_allocator.is_hw_index_free(hw_index)
        self.assertTrue(is_free)
        self.hw_index_allocator.allocate_specific_hw_index_for_bucket(0, hw_index)
        self.hw_index_allocator.commit()
        is_free = self.hw_index_allocator.is_hw_index_free(hw_index)
        self.assertFalse(is_free)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_release_hw_index(self):
        hw_index = self.hw_index_allocator.allocate_hw_index_for_bucket(3)
        self.hw_index_allocator.commit()
        is_free = self.hw_index_allocator.is_hw_index_free(hw_index)
        self.assertFalse(is_free)

        self.hw_index_allocator.release_hw_index(hw_index)
        self.hw_index_allocator.commit()
        is_free = self.hw_index_allocator.is_hw_index_free(hw_index)
        self.assertTrue(is_free)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_oor(self):
        for idx in range(NUM_INDEXES):
            self.hw_index_allocator.allocate_hw_index_for_bucket(4)
        self.hw_index_allocator.commit()

        with self.assertRaises(hw_tablescli.ResourceException):
            self.hw_index_allocator.allocate_hw_index_for_bucket(5)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_withdraw(self):
        num_hw_index_to_allocate = 10
        for idx in range(num_hw_index_to_allocate):
            self.hw_index_allocator.allocate_hw_index_for_bucket(6)
        self.hw_index_allocator.commit()
        num_indexes = self.hw_index_allocator.get_number_of_free_indices()
        self.assertEqual(num_indexes, NUM_INDEXES - num_hw_index_to_allocate)

        # Withdraw
        for idx in range(num_hw_index_to_allocate):
            self.hw_index_allocator.allocate_hw_index_for_bucket(1)
        self.hw_index_allocator.withdraw()
        num_indexes = self.hw_index_allocator.get_number_of_free_indices()
        self.assertEqual(num_indexes, NUM_INDEXES - num_hw_index_to_allocate)


if __name__ == '__main__':
    unittest.main()
