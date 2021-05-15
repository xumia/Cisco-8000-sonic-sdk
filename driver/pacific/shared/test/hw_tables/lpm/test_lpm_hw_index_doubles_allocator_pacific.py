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

FIRST_INDEX = 0
NUM_HW_LINES = 1000
NUM_INDEXES = 2 * NUM_HW_LINES
NUM_FIXED_ENTRIES_PER_BUCKET = 5
NUM_SHARED_ENTRIES_PER_DOUBLE_BUCKET = 14


class test_hw_index_allocator_doubles_pacific(unittest.TestCase):
    def setUp(self):
        self.hw_index_allocator = hw_tablescli.lpm_hw_index_doubles_allocator_pacific(
            "INDEX ALLOCATOR CORE=0 LEVEL=0",
            NUM_HW_LINES,
            NUM_FIXED_ENTRIES_PER_BUCKET,
            NUM_SHARED_ENTRIES_PER_DOUBLE_BUCKET)

    def tearDown(self):
        self.hw_index_allocator = None

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_allocate_hw_index_for_bucket(self):
        num_indexes = self.hw_index_allocator.get_number_of_free_indices()
        self.assertEqual(num_indexes, NUM_INDEXES)

        # Allocating index
        occ = hw_tablescli.occupancy_data()
        hw_index = self.hw_index_allocator.allocate_hw_index_for_bucket(occ)
        self.hw_index_allocator.commit()
        num_indexes = self.hw_index_allocator.get_number_of_free_indices()
        self.assertEqual(num_indexes, NUM_INDEXES - 1)
        self.hw_index_allocator.sanity()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_allocate_specific_hw_index_for_bucket(self):
        occ = hw_tablescli.occupancy_data()
        hw_index = FIRST_INDEX + 20
        is_free = self.hw_index_allocator.is_hw_index_free(hw_index)
        self.assertTrue(is_free)
        self.hw_index_allocator.allocate_specific_hw_index_for_bucket(occ, hw_index)
        self.hw_index_allocator.commit()
        is_free = self.hw_index_allocator.is_hw_index_free(hw_index)
        self.assertFalse(is_free)
        self.hw_index_allocator.sanity()

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
        self.hw_index_allocator.sanity()

    def compare_bucket_occupancy_to_resource_occupancy(self, input_occupancy_data, output_occupancy):
        expected_occupancy = self.hw_index_allocator.bucket_occupancy_to_shared_entries_descriptor(input_occupancy_data)
        self.assertEqual(expected_occupancy.num_shared_entries, output_occupancy.num_shared_entries)
        if (expected_occupancy.num_shared_entries > 0):
            self.assertEqual(expected_occupancy.line_state, output_occupancy.line_state)

    def compare_occupancies(self, expected_occupancy, output_occupancy):
        self.assertEqual(expected_occupancy.num_shared_entries, output_occupancy.num_shared_entries)
        if (expected_occupancy.num_shared_entries > 0):
            self.assertEqual(expected_occupancy.line_state, output_occupancy.line_state)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_notify_hw_index_occupancy_changed_no_neighbour(self):
        occ = hw_tablescli.occupancy_data()
        hw_index = self.hw_index_allocator.allocate_hw_index_for_bucket(occ)
        self.hw_index_allocator.commit()
        self._test_notify_hw_index_occupancy_changed(hw_index)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_notify_hw_index_occupancy_changed_undetermined_neighbour(self):
        occ = hw_tablescli.occupancy_data()
        hw_index = self.hw_index_allocator.allocate_hw_index_for_bucket(occ)

        neighbour_index = hw_index ^ 1
        self.hw_index_allocator.allocate_specific_hw_index_for_bucket(occ, neighbour_index)
        self.hw_index_allocator.commit()
        self._test_notify_hw_index_occupancy_changed(hw_index)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_notify_hw_index_occupancy_changed_singles_neighbour(self):
        occ = hw_tablescli.occupancy_data()
        hw_index = self.hw_index_allocator.allocate_hw_index_for_bucket(occ)

        occ.single_entries = NUM_FIXED_ENTRIES_PER_BUCKET + 1
        neighbour_index = hw_index ^ 1
        self.hw_index_allocator.allocate_specific_hw_index_for_bucket(occ, neighbour_index)
        self.hw_index_allocator.commit()
        self._test_notify_hw_index_occupancy_changed(hw_index)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_notify_hw_index_occupancy_changed_doubles_neighbour(self):
        occ = hw_tablescli.occupancy_data()
        hw_index = self.hw_index_allocator.allocate_hw_index_for_bucket(occ)

        occ.double_entries = 1
        neighbour_index = hw_index ^ 1
        self.hw_index_allocator.allocate_specific_hw_index_for_bucket(occ, neighbour_index)
        self.hw_index_allocator.commit()
        self._test_notify_hw_index_occupancy_changed(hw_index)

    def _test_notify_hw_index_occupancy_changed(self, hw_index_to_change):
        occ = hw_tablescli.occupancy_data()
        occ.single_entries = 0
        occ.double_entries = 0
        neighbour_index = hw_index_to_change ^ 1
        neighbour_state = self.hw_index_allocator.get_hw_index_occupancy(neighbour_index)
        last_num_singles = NUM_FIXED_ENTRIES_PER_BUCKET + NUM_SHARED_ENTRIES_PER_DOUBLE_BUCKET
        last_num_doubles = NUM_SHARED_ENTRIES_PER_DOUBLE_BUCKET / 2
        if (neighbour_state.line_state == hw_tablescli.lpm_hw_index_doubles_allocator_pacific.shared_entries_type_e_SINGLE_ENTRIES):
            last_num_singles -= neighbour_state.num_shared_entries
            last_num_doubles = 0

        if (neighbour_state.line_state == hw_tablescli.lpm_hw_index_doubles_allocator_pacific.shared_entries_type_e_DOUBLE_ENTRIES):
            last_num_doubles -= neighbour_state.num_shared_entries
            last_num_singles = NUM_FIXED_ENTRIES_PER_BUCKET

        for num_singles in range(last_num_singles):
            occ.single_entries = num_singles

            prev_occ = self.hw_index_allocator.get_hw_index_occupancy(hw_index_to_change)
            self.hw_index_allocator.notify_hw_index_occupancy_changed(hw_index_to_change, occ)
            self.hw_index_allocator.withdraw()
            neighbour_occ = self.hw_index_allocator.get_hw_index_occupancy(neighbour_index)
            self.compare_occupancies(neighbour_occ, neighbour_state)
            res_occ = self.hw_index_allocator.get_hw_index_occupancy(hw_index_to_change)
            self.compare_occupancies(prev_occ, res_occ)

            self.hw_index_allocator.notify_hw_index_occupancy_changed(hw_index_to_change, occ)
            self.hw_index_allocator.commit()
            neighbour_occ = self.hw_index_allocator.get_hw_index_occupancy(neighbour_index)
            self.compare_occupancies(neighbour_occ, neighbour_state)
            res_occ = self.hw_index_allocator.get_hw_index_occupancy(hw_index_to_change)
            self.compare_bucket_occupancy_to_resource_occupancy(occ, res_occ)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_oor(self):
        occ = hw_tablescli.occupancy_data()
        for idx in range(NUM_INDEXES):
            self.hw_index_allocator.allocate_hw_index_for_bucket(occ)
        self.hw_index_allocator.commit()
        self.hw_index_allocator.sanity()

        with self.assertRaises(hw_tablescli.ResourceException):
            self.hw_index_allocator.allocate_hw_index_for_bucket(occ)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_withdraw(self):
        occ = hw_tablescli.occupancy_data()
        num_hw_index_to_allocate = 10
        for idx in range(num_hw_index_to_allocate):
            self.hw_index_allocator.allocate_hw_index_for_bucket(occ)
        self.hw_index_allocator.commit()
        num_indexes = self.hw_index_allocator.get_number_of_free_indices()
        self.assertEqual(num_indexes, NUM_INDEXES - num_hw_index_to_allocate)

        # Withdraw
        for idx in range(num_hw_index_to_allocate):
            self.hw_index_allocator.allocate_hw_index_for_bucket(occ)
        self.hw_index_allocator.withdraw()
        num_indexes = self.hw_index_allocator.get_number_of_free_indices()
        self.assertEqual(num_indexes, NUM_INDEXES - num_hw_index_to_allocate)
        self.hw_index_allocator.sanity()


if __name__ == '__main__':
    unittest.main()
