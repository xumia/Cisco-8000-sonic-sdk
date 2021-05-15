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
import random
import time
import em_test_utils as etu

ENTRY_WIDTH = 100
KEY_WIDTH1 = 80
KEY_WIDTH2 = 40


class test_em(unittest.TestCase):
    def setUp(self):
        em = etu.create_em(etu.NUM_OF_BANKS, etu.NUM_OF_BANK_ENTRIES, etu.NUM_OF_CAM_ENTRIES, ENTRY_WIDTH,
                           [KEY_WIDTH1,
                            KEY_WIDTH2])
        self.core = hw_tablescli.em_core(None, em, etu.MOVING_DEPTH)

    def tearDown(self):
        self.core = None

    def main(self):
        # Inserts random entries (checks for duplicates)
        max_entries_in_em = etu.NUM_OF_BANKS * etu.NUM_OF_BANK_ENTRIES + etu.NUM_OF_CAM_ENTRIES
        nine_tenths_out_of_max = int(0.9 * max_entries_in_em)
        keys = set()
        entries_to_insert = []
        random_generator = etu.random_em_generator(2938723)
        for i in range(max_entries_in_em + nine_tenths_out_of_max):
            key_width = KEY_WIDTH1 if random.randint(0, 1) == 1 else KEY_WIDTH2
            payload_width = ENTRY_WIDTH - key_width
            payload = etu.create_em_payload(i + 1, payload_width)
            key = random_generator.random_em_key(key_width)
            while key.get_value() in keys:
                key = random_generator.random_em_key(key_width)
            keys.add(key.get_value())
            entries_to_insert.append((key, payload))

        # Inserts the first 90% of the entries ("fast entries")
        fast_entries = 0
        time_before = time.time()
        for i in range(nine_tenths_out_of_max):
            if i % 10000 == 0:
                print("Insertion #{}".format(i))
            key, payload = entries_to_insert[i]
            try:
                self.core.insert(key, payload)
            except hw_tablescli.ResourceException:
                break
            fast_entries += 1
        time_after = time.time()

        fast_entries_time = time_after - time_before

        # Inserts the remaining 10% of the entries ("slow entries")
        slow_entries = 0
        time_before = time.time()
        for i in range(nine_tenths_out_of_max, max_entries_in_em):
            if i % 10000 == 0:
                print("Insertion #{}".format(i))
            key, payload = entries_to_insert[i]
            try:
                self.core.insert(key, payload)
            except hw_tablescli.ResourceException:
                break
            slow_entries += 1
        time_after = time.time()

        slow_entries_time = time_after - time_before

        # Inserts the remaining 10% of the entries ("slow entries")
        very_slow_entries = 0
        time_before = time.time()
        for i in range(max_entries_in_em, max_entries_in_em + nine_tenths_out_of_max):
            if i % 10000 == 0:
                print("Insertion #{}".format(i))
            key, payload = entries_to_insert[i]
            try:
                self.core.insert(key, payload)
            except hw_tablescli.ResourceException:
                pass
            very_slow_entries += 1
        time_after = time.time()

        very_slow_entries_time = time_after - time_before

        # Prints out a summery of the results
        utilization = 100 * (fast_entries + slow_entries) / max_entries_in_em
        entries_per_sec = (fast_entries + slow_entries) / (fast_entries_time + slow_entries_time)
        print(
            "Done inserting %lu entries (max capacity = %lu, utilization = %.2f%%) in %lu ms (%lu insertions per second) with seed %lu" %
            (fast_entries + slow_entries, max_entries_in_em, utilization, 1000 * (slow_entries_time + fast_entries_time),
             entries_per_sec, random_generator.seed))
        print("First 90%% of entries (%lu entries) were inserted in %lu ms (%lu insertion per second)" %
              (fast_entries, int(fast_entries_time * 1000), int(fast_entries / fast_entries_time)))
        print("The remaining entries (%lu entries) were inserted in %lu ms (%lu insertion per second)" %
              (slow_entries, int(1000 * slow_entries_time), int(slow_entries / slow_entries_time)))
        print("The OOR insertions (%lu entries) were tried to be inserted inserted in %lu ms (%lu insertion per second)" %
              (very_slow_entries, int(1000 * very_slow_entries_time), int(very_slow_entries / very_slow_entries_time)))

        if utilization < 50:
            raise Exception("Utilization in random inserts to the EM is less then 50%.")

        return entries_to_insert

    def test_em_utilization_and_performance(self):
        self.main()

    def test_em_utilization_and_performance_erase_and_test_again(self):
        entries = self.main()
        for k, p in entries:
            try:
                self.core.erase(k)
            except BaseException:
                pass
        entries = self.main()


if __name__ == '__main__':
    unittest.main()
