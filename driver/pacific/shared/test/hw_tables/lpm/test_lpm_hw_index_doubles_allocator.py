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

import unittest
import hw_tablescli
import decor

FIRST_LINE = 0
NUM_LINES = 1000
NUM_INDEXES = NUM_LINES * 2
STEP = 1
NUM_FIXED_ENTRIES_PER_BUCKET = 0
NUM_SHARED_ENTRIES_PER_DOUBLE_BUCKET = 18


class test_lpm_hw_index_doubles_allocator(unittest.TestCase):

    def setUp(self):
        self.hw_index_allocator = hw_tablescli.lpm_hw_index_doubles_allocator(
            "INDEX ALLOCATOR",
            FIRST_LINE,
            NUM_LINES,
            NUM_FIXED_ENTRIES_PER_BUCKET,
            NUM_SHARED_ENTRIES_PER_DOUBLE_BUCKET
        )

    def tearDown(self):
        self.hw_index_allocator = None

    def check_bucket_size(self, hw_index, expected_size):
        current_size = self.hw_index_allocator.get_hw_index_size(hw_index)
        self.assertEqual(current_size, expected_size)

    def test_allocate_hw_index_for_bucket(self):
        num_indexes = self.hw_index_allocator.get_number_of_free_indices()
        self.assertEqual(num_indexes, NUM_INDEXES)

        # Allocating index
        hw_index = self.hw_index_allocator.allocate_hw_index_for_bucket(0)
        self.hw_index_allocator.commit()
        num_indexes = self.hw_index_allocator.get_number_of_free_indices()
        self.assertEqual(num_indexes, NUM_INDEXES - 1)
        self.hw_index_allocator.sanity()

    def test_release_hw_index(self):
        num_indexes = self.hw_index_allocator.get_number_of_free_indices()
        self.assertEqual(num_indexes, NUM_INDEXES)

        # Allocate index
        hw_index = self.hw_index_allocator.allocate_hw_index_for_bucket(0)
        self.hw_index_allocator.commit()
        self.assertFalse(self.hw_index_allocator.is_hw_index_free(hw_index))

        # Release index
        self.hw_index_allocator.release_hw_index(hw_index)
        self.hw_index_allocator.commit()
        self.assertTrue(self.hw_index_allocator.is_hw_index_free(hw_index))
        self.hw_index_allocator.sanity()

    def test_allocate_specific_hw_index_for_buckets(self):
        occupancy_data = 4
        hw_index = FIRST_LINE + 50

        # Allocate specific indexes
        self.hw_index_allocator.allocate_specific_hw_index_for_bucket(occupancy_data, hw_index)
        self.assertFalse(self.hw_index_allocator.is_hw_index_free(hw_index))
        neighbour_hw_index = hw_index ^ 1
        self.hw_index_allocator.allocate_specific_hw_index_for_bucket(occupancy_data, neighbour_hw_index)
        self.assertFalse(self.hw_index_allocator.is_hw_index_free(neighbour_hw_index))
        self.check_bucket_size(hw_index, occupancy_data)
        self.check_bucket_size(neighbour_hw_index, occupancy_data)
        self.hw_index_allocator.commit()
        self.hw_index_allocator.sanity()

    def test_oor(self):
        for hw_index in range(NUM_INDEXES):
            hw_index = self.hw_index_allocator.allocate_hw_index_for_bucket(8)
        self.hw_index_allocator.commit()
        self.hw_index_allocator.sanity()

        with self.assertRaises(hw_tablescli.ResourceException):
            self.hw_index_allocator.allocate_hw_index_for_bucket(8)

    def test_withdraw(self):
        num_indexes_to_allocate = 20
        for index in range(num_indexes_to_allocate):
            hw_index = self.hw_index_allocator.allocate_hw_index_for_bucket(1)
            self.assertFalse(self.hw_index_allocator.is_hw_index_free(hw_index))
            self.hw_index_allocator.release_hw_index(hw_index)

        num_indexes = self.hw_index_allocator.get_number_of_free_indices()
        self.assertEqual(num_indexes, NUM_INDEXES)
        self.hw_index_allocator.withdraw()
        num_indexes = self.hw_index_allocator.get_number_of_free_indices()
        self.assertEqual(num_indexes, NUM_INDEXES)
        self.hw_index_allocator.sanity()

    def test_notify_hw_index_size_changed_no_neighbour(self):
        bucket_size = 2
        hw_index = self.hw_index_allocator.allocate_hw_index_for_bucket(bucket_size)
        self.assertFalse(self.hw_index_allocator.is_hw_index_free(hw_index))
        self.check_bucket_size(hw_index, bucket_size)
        bucket_size += 2
        self.hw_index_allocator.notify_hw_index_size_changed(hw_index, bucket_size)
        self.check_bucket_size(hw_index, bucket_size)
        self.hw_index_allocator.commit()

    def test_notify_hw_index_size_changed_with_neighbour(self):
        # Allocate two indexes
        allocated_size = 2
        neighbour_size = 4
        hw_index = self.hw_index_allocator.allocate_hw_index_for_bucket(allocated_size)
        neighbour_hw_index = hw_index ^ 1
        self.hw_index_allocator.allocate_specific_hw_index_for_bucket(neighbour_size, neighbour_hw_index)
        self.assertFalse(self.hw_index_allocator.is_hw_index_free(hw_index))
        self.assertFalse(self.hw_index_allocator.is_hw_index_free(neighbour_hw_index))
        self.hw_index_allocator.commit()
        new_size = 3
        self.hw_index_allocator.notify_hw_index_size_changed(hw_index, new_size)
        self.check_bucket_size(hw_index, new_size)
        self.hw_index_allocator.notify_hw_index_size_changed(neighbour_hw_index, new_size)
        self.check_bucket_size(neighbour_hw_index, new_size)

        # Withdraw notify
        self.hw_index_allocator.withdraw()
        self.check_bucket_size(hw_index, allocated_size)
        self.check_bucket_size(neighbour_hw_index, neighbour_size)
        self.hw_index_allocator.sanity()


if __name__ == '__main__':
    unittest.main()
