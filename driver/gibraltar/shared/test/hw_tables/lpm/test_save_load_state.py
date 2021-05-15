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
import json
import unittest
import lpm_test_utils
import pprint
from parser_formats import lpm_instruction
from logical_lpm_base import logical_lpm_base
import decor

BEFORE_STATE_FILENAME = "lpm_save_state_before_load.json"
AFTER_STATE_FILENAME = "lpm_save_state_after_load.json"

FILE_PATH = "shared/test/hw_tables/lpm/inputs/customer_tables/lpm_data.level3_ip4_fib.txt.gz"
FILE_FORMAT = "OLD_FORMAT"


class test_save_load_state(logical_lpm_base):

    def setUp(self):
        super().setUp()
        self.duplicated_logical_lpm = self.create_logical_lpm()
        self.logical_lpm.set_rebalance_interval(100)
        self.duplicated_logical_lpm.set_rebalance_interval(100)

    def tearDown(self):
        super().tearDown()
        self.duplicated_logical_lpm = None
        os.remove(BEFORE_STATE_FILENAME)
        os.remove(AFTER_STATE_FILENAME)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_save_load_state(self):
        lpm_input = lpm_test_utils.parse_lpm_input(FILE_PATH, FILE_FORMAT, 10000)
        lpm_half_actions = lpm_input[:len(lpm_input) // 2]
        lpm_half_actions = self.add_remove_actions(lpm_half_actions)
        self.perform_test_actions(lpm_half_actions, self.logical_lpm)
        self.logical_lpm.save_state(BEFORE_STATE_FILENAME)
        self.duplicated_logical_lpm.load_state(BEFORE_STATE_FILENAME)
        self.duplicated_logical_lpm.save_state(AFTER_STATE_FILENAME)
        self.compare_files(BEFORE_STATE_FILENAME, AFTER_STATE_FILENAME)
        lpm_remaining_actions = lpm_input[len(lpm_input) // 2:]
        self.perform_test_actions(lpm_remaining_actions, self.logical_lpm)
        self.perform_test_actions(lpm_remaining_actions, self.duplicated_logical_lpm)
        self.logical_lpm.save_state(BEFORE_STATE_FILENAME)
        self.duplicated_logical_lpm.save_state(AFTER_STATE_FILENAME)

    def add_remove_actions(self, instructions):
        insert_remove_instructions = instructions
        for instruction in instructions:
            if instruction.action == lpm_instruction.INSERT:
                insert_remove_instructions.append(lpm_instruction(lpm_instruction.REMOVE, instruction.ip_address, instruction.vrf))

        return insert_remove_instructions

    def compare_files(self, first_file, second_file):
        with open(first_file) as before_load_file:
            before_lpm_dump = self.load_json_from_file(before_load_file)
        with open(second_file) as after_load_file:
            after_lpm_dump = self.load_json_from_file(after_load_file)
        self.compare_lpm_members(before_lpm_dump, after_lpm_dump)

    def load_json_from_file(self, file):
        lpm_dump = json.loads(file.read())
        file.close()
        return lpm_dump

    def compare_lpm_members(self, before_lpm_dump, after_lpm_dump):
        before_lpm_members = before_lpm_dump["lpm_members"]
        after_lpm_members = after_lpm_dump["lpm_members"]
        self.assertTrue(before_lpm_members == after_lpm_members)
        before_lpm_distributer = before_lpm_dump["distributer"]
        after_lpm_distributer = after_lpm_dump["distributer"]
        self.assertTrue(before_lpm_distributer == after_lpm_distributer)


if __name__ == "__main__":
    unittest.main()
