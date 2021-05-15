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

import hw_tablescli
import unittest
import em_test_utils as etu
import gzip
import random
import time
import decor


ENTRY_WIDTH = 160
ADDRESS_LENGTH = 140

RANDOM_TRIAL_COUNT = 20
NUM_OF_RANDOM_FAILING_TRIALS = 50

PROBLEMATIC_KEY = 503751351653289722
FILE_PATH = "shared/test/hw_tables/lpm/inputs/customer_tables/lpm_data.RJIL_CHNNSMJRCSR003_show_cef_all_ipv6_04.02.19.txt.gz"


class test_em_performance(unittest.TestCase):
    def setUp(self):
        widths = [ADDRESS_LENGTH]
        self.em = etu.create_em(etu.NUM_OF_BANKS, etu.NUM_OF_BANK_ENTRIES,
                                etu.NUM_OF_CAM_ENTRIES, ENTRY_WIDTH, widths)
        self.core = hw_tablescli.em_core(None, self.em, etu.MOVING_DEPTH)

    def tearDown(self):
        self.em = None
        self.core = None

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_random(self):
        """
        Measures the time that random inserts take
        :return: None
        """
        self.core = hw_tablescli.em_core(None, self.em, etu.MOVING_DEPTH)
        capacity = etu.NUM_OF_BANKS * etu.NUM_OF_BANK_ENTRIES + etu.NUM_OF_CAM_ENTRIES
        total_time = 0
        random_generator = etu.random_em_generator(3548421)
        print("\nTesting performance of {} random tests with seed {}".format(RANDOM_TRIAL_COUNT, random_generator.seed))

        # Performs the same test several times
        for trial in range(RANDOM_TRIAL_COUNT):

            # Reinitialize the core
            self.core = hw_tablescli.em_core(None, self.em, etu.MOVING_DEPTH)
            start_time = time.time()

            # Inserts many random entries to the EM (to fill 90% of the capacity) and measures the average time
            for i in range(int(0.9 * capacity)):
                key = random_generator.random_em_key(ADDRESS_LENGTH)
                payload = random_generator.random_em_payload(ENTRY_WIDTH - ADDRESS_LENGTH)
                self.core.insert(key, payload)
            end_time = time.time()
            total_time += 1000 * (end_time - start_time)

        print("Average time: {} ms".format(int(total_time / RANDOM_TRIAL_COUNT)))

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_failing_randomness(self):
        """
        Runs this test many times: start from a random key, and perform consecutive inserts until fail.
        For each test records the achieved utilization and creates an histogram of the utilization
        :return: None
        """
        self.core = hw_tablescli.em_core(None, self.em, etu.MOVING_DEPTH)

        capacity = etu.NUM_OF_BANKS * etu.NUM_OF_BANK_ENTRIES + etu.NUM_OF_CAM_ENTRIES
        division = 10
        jump = 100 / division
        histogram = [0 for _ in range(division + 1)]
        random_generator = etu.random_em_generator(786548)

        print("\nTesting utilization when inserting consecutive keys, starting from a random key. Using seed {}".format(random_generator.seed))

        for j in range(NUM_OF_RANDOM_FAILING_TRIALS):
            self.core = hw_tablescli.em_core(None, self.em, etu.MOVING_DEPTH)
            initial = random_generator.random_em_key(ADDRESS_LENGTH).get_value()
            count = 0
            if (j % 10) == 0:
                print("Step #{}".format(j))
            for i in range(capacity):
                key = etu.create_em_key(initial + i, ADDRESS_LENGTH)
                payload = etu.create_em_payload(i + 1, ENTRY_WIDTH - ADDRESS_LENGTH)
                try:
                    self.core.insert(key, payload)
                    count += 1
                except hw_tablescli.ResourceException:
                    break
            utilization = (count / capacity) * 100
            if utilization <= 50:
                print(
                    "Consecutive inserts starting from key: %lu until fail, resulted in utilization of %.2f%%." %
                    (initial, utilization))

            histogram[int(utilization / jump + 0.5)] += 100 / NUM_OF_RANDOM_FAILING_TRIALS
        print("A histogram of [Utilization : Percent of tests that achieved the utilization]")
        print(histogram)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_problematic_key(self):
        """
        Tests the utilization achieved on consecutive entries starting from a specific problematic key.
        :return: None
        """
        self.core = hw_tablescli.em_core(None, self.em, etu.MOVING_DEPTH)
        print("\nTesting utilization when inserting consecutive keys, starting from a constant key ({})".format(PROBLEMATIC_KEY))

        capacity = etu.NUM_OF_BANKS * etu.NUM_OF_BANK_ENTRIES + etu.NUM_OF_CAM_ENTRIES
        count = 0
        for i in range(capacity):
            key = etu.create_em_key(PROBLEMATIC_KEY + i, ADDRESS_LENGTH)
            payload = etu.create_em_payload(i + 1, ENTRY_WIDTH - ADDRESS_LENGTH)
            try:
                self.core.insert(key, payload)
                count += 1
            except hw_tablescli.ResourceException:
                break
        utilization = (count / capacity) * 100
        print("Count = %d, Utilization = %.2f" % (count, utilization))

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_with_entries_from_file(self):
        """
        Tests the utilization when inserting entries from a specific file.
        :return: None
        """
        self.core = hw_tablescli.em_core(None, self.em, etu.MOVING_DEPTH)
        entries = self.entries_from_file(
            FILE_PATH)
        print("\nTesting utilization when inserting {} entries from file \"{}\"".format(len(entries), FILE_PATH))
        total_capacity = etu.NUM_OF_BANK_ENTRIES * etu.NUM_OF_BANKS + etu.NUM_OF_CAM_ENTRIES
        count = 0
        failed = False
        for key, payload in entries:
            try:
                self.core.insert(key, payload)
                count += 1
            except hw_tablescli.ResourceException:
                if not failed:
                    failed = True
                    print("On first fail: Inserted: %d, Utilization: %.2f%%" % (count, count / total_capacity * 100))
            except hw_tablescli.InvalException:
                print(key.get_value(), key.get_width(), payload.get_value(), key.get_width())
                break
            if count % 1000 == 0:
                print("#{}".format(count))
        print("At the end: Inserted: %d, Utilization: %.2f%%" % (count, count / total_capacity * 100))

    @staticmethod
    def entries_from_file(path):
        """
        Extracts the entries from a given .gz file.
        :param path: The path of the file
        :return: The list of entries
        """
        entries = []
        file = gzip.open(path)
        prev_keys = set()
        payload_value = 0
        for line in file:
            payload_value += 2
            parts = str(line).split(' ')
            value, width = int(parts[1], 16), int(parts[2])

            # If the address isn't full adds the two possible completion of the prefix to a full address
            if width == 139:
                width += 1
                payload0 = etu.create_em_payload(payload_value, ENTRY_WIDTH - width)
                payload1 = etu.create_em_payload(payload_value + 1, ENTRY_WIDTH - width)
                key0 = etu.create_em_key(value << 1, width)
                key1 = etu.create_em_key((value << 1) + 1, width)
                test_em_performance.insert_entry_if_new(key0, payload0, prev_keys, entries)
                test_em_performance.insert_entry_if_new(key1, payload1, prev_keys, entries)
            elif width == 140:
                key = etu.create_em_key(value, width)
                payload = etu.create_em_payload(payload_value, ENTRY_WIDTH - width)
                test_em_performance.insert_entry_if_new(key, payload, prev_keys, entries)

        file.close()
        return entries

    @staticmethod
    def insert_entry_if_new(key, payload, prev_keys, entries):
        if (key.get_value(), key.get_width()) not in prev_keys:
            entries.append((key, payload))
            prev_keys.add((key.get_value(), key.get_width()))


if __name__ == '__main__':
    unittest.main()
