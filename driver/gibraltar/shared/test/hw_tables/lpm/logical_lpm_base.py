#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import lldcli
import time
from parser_formats import lpm_instruction
import ipaddress
import math
from genereate_lookups import generate_lookups_for_instructions
from argument_parser import args_parser
import lpm_test_utils
import os
import decor

REQUIRED_BULK_RATE = 17900
REQUIRED_ONE_BY_ONE_RATE = 3100
LOW_THRESHOLD = 0  # TODO later

DEVICE_PATH = "/dev/testdev"
MAX_ACTION_COUNT = -1

BITS_IN_IPV4_ADDR = 32
NUM_OF_IPV4_FIELDS = 4
IPV4_FIELD_LEN = 8
PAYLOAD_WIDTH = 32
VRF_LENGTH = 11


class logical_lpm_base(unittest.TestCase):

    HBM_ENABLED = decor.is_pacific() or decor.is_gibraltar() or decor.is_asic4()
    L2_BUCKETS_PER_SRAM_ROW = 1 if HBM_ENABLED else 2
    L2_MAX_NUM_OF_HBM_BUCKETS = 12 * 1024 if HBM_ENABLED else 0

    def setUp(self):
        hw_tablescli.set_logging_level(args_parser.logging_level)
        self.lld = lldcli.ll_device_create(0, DEVICE_PATH)
        assert self.lld is not None, "ll_device_create failed"
        self.logical_lpm = self.create_logical_lpm()
        hw_tablescli.set_logging_level(args_parser.logging_level)

    def tearDown(self):
        self.logical_lpm = None
        self.lld = None

    def create_logical_lpm(self):
        lpm_settings = hw_tablescli.create_lpm_settings(self.lld)
        self.update_lpm_settings(lpm_settings)

        logical_lpm = hw_tablescli.create_logical_lpm(self.lld, lpm_settings)
        return logical_lpm

    def update_lpm_settings(self, lpm_settings):
        lpm_settings.l2_buckets_per_sram_row = logical_lpm_base.L2_BUCKETS_PER_SRAM_ROW
        lpm_settings.l2_max_number_of_hbm_buckets = logical_lpm_base.L2_MAX_NUM_OF_HBM_BUCKETS

    def perform_test_file(self, file_path, file_format, max_entries=-1):
        lpm_input = lpm_test_utils.parse_lpm_input(file_path, file_format, max_entries)
        lpm_input = lpm_test_utils.add_unique_payloads_to_lpm_instructions(lpm_input)
        self.perform_test_actions(lpm_input, self.logical_lpm)

    def perform_test_actions(self, instructions, logical_lpm):
        """
        Gets a list of LpmInstruction and performs each instruction
        :param instructions: The list of LpmInstructions
        :return: None
        """
        t0 = time.perf_counter()

        action_count = 0
        insert_count = 0
        modify_count = 0
        remove_count = 0
        lookup_count = 0

        if 0 < MAX_ACTION_COUNT < len(instructions):
            instructions = instructions[:MAX_ACTION_COUNT]

        for instruction in instructions:

            key_value, key_width = instruction.get_key_and_width()
            key = lpm_test_utils.generate_lpm_key(key_value, key_width)

            payload = instruction.payload

            # Performs the action
            try:
                if instruction.action == lpm_instruction.INSERT:
                    status = logical_lpm.insert(key, payload)
                    insert_count += 1
                elif instruction.action == lpm_instruction.MODIFY:
                    status = logical_lpm.modify(key, payload)
                    modify_count += 1
                elif instruction.action == lpm_instruction.REMOVE:
                    status = logical_lpm.remove(key)
                    remove_count += 1
                else:
                    raise ValueError("Invalid action")
            except hw_tablescli.BaseException:
                lpm_test_utils.print_utilization(logical_lpm)
                print("Failed at iteration=%d" % action_count)
                raise hw_tablescli.BaseException

            action_count += 1

        incorrect_lookups = []
        default_bug_incorrect_lookups = []

        for address_value, address_length, payload in generate_lookups_for_instructions(instructions):
            address = lpm_test_utils.generate_lpm_key(address_value, address_length)
            result = logical_lpm.lookup(address)
            if result[1] != payload:
                incorrect_lookups.append((address_value, address_length, payload, result[1], result[0]))
            lookup_count += 1

        t1 = time.perf_counter()
        total_time = (t1 - t0)

        actions_per_sec = action_count / total_time

        print('One by one actions from an empty LPM:')
        print(
            '#insertions={}, #modifications={}, #removals={}, #lookups={}, time={} seconds, #actions_per_sec={}'.format(
                insert_count, modify_count, remove_count, lookup_count, round(total_time, 2), round(actions_per_sec)))

        # Checks that the lookups were successful
        if len(incorrect_lookups) > 0:
            for address_value, address_length, payload, result_payload, result_prefix in incorrect_lookups:
                print(
                    "Lookup returned an incorrect result. address: {} (len={}), expected payload: {}, actual payload: {}, actual prefix matched: {}".format(
                        address_value,
                        address_length,
                        payload,
                        result_payload,
                        result_prefix))
            if len(incorrect_lookups) >= 0.01 * lookup_count:
                raise Exception("There were {} incorrect lookups".format(len(incorrect_lookups)))
            else:
                print("There were {} incorrect lookups".format(len(incorrect_lookups)))

        if len(default_bug_incorrect_lookups) > 0:
            if len(default_bug_incorrect_lookups) >= 0.1 * lookup_count:
                raise Exception("There were {} incorrect lookups (from default bug)".format(
                    len(default_bug_incorrect_lookups)))
            else:
                print("Error: There were {} incorrect lookups (from default bug)".format(
                    len(default_bug_incorrect_lookups)))

        self.assertEqual(status, None)
        self.assertGreater(actions_per_sec, REQUIRED_ONE_BY_ONE_RATE * LOW_THRESHOLD)
