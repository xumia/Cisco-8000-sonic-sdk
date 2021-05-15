#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

# Test purpose: trigger succesful evacuation from CAM.
# In this test we got one bank with 2 entries, and cam with one entry.
# We will use 4 keys, two (0,1) will hashed to entry 0, two (2,3) will hashed to entry 1.
# The flow is:
# Insert the first 2 keys: 0 will go to bank, 1 will go to cam.
# Insert key 2 to bank - EM is full.
# Delete key 0 from bank - entry 0 is free.
# Insert key 3: entry 1 is occupied, thus it's will go to cam, key 1 would be evacuated from cam to entry 0.

from leaba import sdk
import hw_tablescli
import unittest
import random
import time
import em_test_utils as etu

ENTRY_WIDTH = 100
KEY_WIDTH1 = 80
NUM_OF_BANKS = 1
NUM_OF_BANK_ENTRIES = 2
NUM_OF_CAM_ENTRIES = 1

# Using random_em_generator with any of those seeds generating keys at the same entry (at least 3 first keys) on our only bank.
SEED_OF_ENTRY_0 = 0
SEED_OF_ENTRY_1 = 1
# Notice: changing the seeds might cause different behavior - don't do it.


class test_em(unittest.TestCase):
    def setUp(self):
        em = etu.create_em(NUM_OF_BANKS, NUM_OF_BANK_ENTRIES, NUM_OF_CAM_ENTRIES, ENTRY_WIDTH,
                           [KEY_WIDTH1])
        self.core = hw_tablescli.em_core(None, em, etu.MOVING_DEPTH)

    def tearDown(self):
        self.core = None

    def main(self):
        max_entries_in_em = NUM_OF_BANKS * NUM_OF_BANK_ENTRIES + NUM_OF_CAM_ENTRIES  # 3
        # Generating 2 sets of max_entries_in_em-1 (=2) keys, one set per one bank entry
        # set 0: keys 0,1 - hashed to entry 0
        keys_same_entry_0 = set()
        entries_to_insert_same_entry_0 = []
        random_generator = etu.random_em_generator(SEED_OF_ENTRY_0)
        for i in range(max_entries_in_em - 1):
            key_width = KEY_WIDTH1
            payload_width = ENTRY_WIDTH - key_width
            payload = etu.create_em_payload(i + 1, payload_width)
            key = random_generator.random_em_key(key_width)
            while key.get_value() in keys_same_entry_0:
                key = random_generator.random_em_key(key_width)
            keys_same_entry_0.add(key.get_value())
            entries_to_insert_same_entry_0.append((key, payload))

        # set 1: keys 2,3 - hashed to entry 1
        keys_same_entry_1 = set()
        entries_to_insert_same_entry_1 = []
        random_generator = etu.random_em_generator(SEED_OF_ENTRY_1)
        for i in range(max_entries_in_em - 1):
            key_width = KEY_WIDTH1
            payload_width = ENTRY_WIDTH - key_width
            payload = etu.create_em_payload(i + 1, payload_width)
            key = random_generator.random_em_key(key_width)
            while key.get_value() in keys_same_entry_1:
                key = random_generator.random_em_key(key_width)
            keys_same_entry_1.add(key.get_value())
            entries_to_insert_same_entry_1.append((key, payload))

        # Inserts 2 keys (0,1) from set 0 - 0 on bank - entry 0, 1 on cam.
        for i in range(max_entries_in_em - 1):
            key, payload = entries_to_insert_same_entry_0[i]
            self.core.insert(key, payload)

        # insert key (2) from set 1 to the last available entry - entry 1
        i = 0
        key, payload = entries_to_insert_same_entry_1[i]
        self.core.insert(key, payload)

        # delete key 0 from bank - entry 0 will be available
        d = 0
        k, p = entries_to_insert_same_entry_0[d]
        self.core.erase(k)

        # insert key (3) from set 1 - entry 1 is occupied, thus it's will go to cam, key 1 would be evacuated from cam to entry 0.
        i = 1
        key, payload = entries_to_insert_same_entry_1[i]
        self.core.insert(key, payload)

        return 0

    def test_em_utilization_and_performance_erase_and_test_again(self):
        self.main()


if __name__ == '__main__':
    unittest.main()
