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
import lldcli
import hw_tablescli
from parser_formats import lpm_instruction
import lpm_test_utils
from lpm_test_args_parser import lpm_tests_args
import os
import random
import sys

DEVICE_PATH = "/dev/testdev"
LPM_PAYLOAD_WIDTH = 20


class lpm_scaled_down_test(unittest.TestCase):
    device_id = 1

    def setUp(self):
        enable_hbm = lpm_tests_args.enable_hbm

        self.s_lld = lldcli.ll_device_create(self.device_id, DEVICE_PATH)
        assert self.s_lld is not None

        lldcli.set_logging_level(288, 0)  # turn off logs (Only EMERG)

        l2_double_bucket_size = 20
        l2_max_bucket_size = 17
        if self.s_lld.is_gibraltar():
            l2_double_bucket_size = 28
            l2_max_bucket_size = 26
            enable_hbm = False
        lpm_settings0 = hw_tablescli.lpm_settings()
        lpm_settings0.num_cores = 2
        lpm_settings0.num_distributor_lines = 8
        lpm_settings0.distributor_row_width = 80
        lpm_settings0.l2_double_bucket_size = l2_double_bucket_size
        lpm_settings0.l2_max_bucket_size = l2_max_bucket_size
        lpm_settings0.hbm_max_bucket_size = 24
        lpm_settings0.l1_double_bucket_size = 8
        lpm_settings0.l1_max_sram_buckets = 4 * 128
        lpm_settings0.l1_max_bucket_size = 6
        lpm_settings0.max_bucket_depth = 16
        lpm_settings0.tcam_max_quad_entries = 30
        lpm_settings0.l2_buckets_per_sram_row = 1 if enable_hbm else 2
        lpm_settings0.l2_max_number_of_sram_buckets = 512
        lpm_settings0.l2_max_number_of_hbm_buckets = 1024 if enable_hbm else 0
        lpm_settings0.tcam_num_banksets = 1
        lpm_settings0.tcam_bank_size = 64
        lpm_settings0.trap_destination = 0xc0ffe
        lpm_settings0.l1_buckets_per_sram_row = 2
        lpm_settings0.tcam_single_width_key_weight = 1
        lpm_settings0.tcam_double_width_key_weight = 2
        lpm_settings0.tcam_quad_width_key_weight = 4

        self.s_lpm0 = hw_tablescli.create_logical_lpm(self.s_lld, lpm_settings0)
        self.s_lpm0.set_rebalance_interval(100)

        if not self.s_lld.is_gibraltar():
            l2_double_bucket_size = 20
            l2_max_bucket_size = 17
        else:
            l2_double_bucket_size = 22
            l2_max_bucket_size = 22

        lpm_settings1 = hw_tablescli.lpm_settings()
        lpm_settings1.num_cores = 2
        lpm_settings1.num_distributor_lines = 4
        lpm_settings1.distributor_row_width = 80
        lpm_settings1.l2_double_bucket_size = l2_double_bucket_size
        lpm_settings1.l2_max_bucket_size = l2_max_bucket_size
        lpm_settings1.hbm_max_bucket_size = 24
        lpm_settings1.l1_double_bucket_size = 8
        lpm_settings1.l1_max_sram_buckets = 4 * 32
        lpm_settings1.l1_max_bucket_size = 6
        lpm_settings1.max_bucket_depth = 16
        lpm_settings1.tcam_max_quad_entries = 3
        lpm_settings1.l2_buckets_per_sram_row = 1 if enable_hbm else 2
        lpm_settings1.l2_max_number_of_sram_buckets = 64
        lpm_settings1.l2_max_number_of_hbm_buckets = 128 if enable_hbm else 0
        lpm_settings1.tcam_num_banksets = 1
        lpm_settings1.tcam_bank_size = 16
        lpm_settings1.trap_destination = 0xc0ffe
        lpm_settings1.l1_buckets_per_sram_row = 2
        lpm_settings1.tcam_single_width_key_weight = 1
        lpm_settings1.tcam_double_width_key_weight = 2
        lpm_settings1.tcam_quad_width_key_weight = 4

        self.s_lpm1 = hw_tablescli.create_logical_lpm(self.s_lld, lpm_settings1)
        self.s_lpm1.set_rebalance_interval(10000000)

        if not self.s_lld.is_gibraltar():
            l2_double_bucket_size = 20
            l2_max_bucket_size = 17
        else:
            l2_double_bucket_size = 22
            l2_max_bucket_size = 22

        lpm_settings2 = hw_tablescli.lpm_settings()
        lpm_settings2.num_cores = 2
        lpm_settings2.num_distributor_lines = 4
        lpm_settings2.distributor_row_width = 80
        lpm_settings2.l2_double_bucket_size = l2_double_bucket_size
        lpm_settings2.l2_max_bucket_size = l2_max_bucket_size
        lpm_settings2.hbm_max_bucket_size = 24
        lpm_settings2.l1_double_bucket_size = 8
        lpm_settings2.l1_max_sram_buckets = 4 * 32
        lpm_settings2.l1_max_bucket_size = 6
        lpm_settings2.max_bucket_depth = 16
        lpm_settings2.tcam_max_quad_entries = 3
        lpm_settings2.l2_buckets_per_sram_row = 1 if enable_hbm else 2
        lpm_settings2.l2_max_number_of_sram_buckets = 64
        lpm_settings2.l2_max_number_of_hbm_buckets = 128 if enable_hbm else 0
        lpm_settings2.tcam_num_banksets = 1
        lpm_settings2.tcam_bank_size = 16
        lpm_settings2.trap_destination = 0xc0ffe
        lpm_settings2.l1_buckets_per_sram_row = 2
        lpm_settings2.tcam_single_width_key_weight = 1
        lpm_settings2.tcam_double_width_key_weight = 2
        lpm_settings2.tcam_quad_width_key_weight = 4

        self.s_lpm2 = hw_tablescli.create_logical_lpm(self.s_lld, lpm_settings2)
        self.s_lpm2.set_rebalance_interval(10)

    def tearDown(self):
        self.s_lpm0 = None
        self.s_lpm1 = None
        self.s_lpm2 = None
        self.s_lld = None

    def perform_test_with_entries_from_file(self, logical_lpm, file_name, file_format, max_entries):
        actions = lpm_test_utils.parse_lpm_input(file_name, file_format, max_entries)
        self.assertNotEqual(len(actions), 0, "Empty Input")
        for iteration, action in enumerate(actions):
            key_val, width = action.get_key_and_width()
            key = lpm_test_utils.generate_lpm_key(key_val, width)
            # Performs the action
            try:
                payload = None
                if action.payload is not None:
                    payload = action.payload
                if action.action == lpm_instruction.INSERT:
                    assert payload is not None
                    logical_lpm.insert(key, payload)
                elif action.action == lpm_instruction.MODIFY:
                    assert payload is not None
                    logical_lpm.modify(key, payload)
                elif action.action == lpm_instruction.REMOVE:
                    logical_lpm.remove(key)
                elif action.action == lpm_instruction.REBALANCE:
                    logical_lpm.rebalance()
                else:
                    self.fail("Invalid action")

            except hw_tablescli.BaseException:
                pass

            if lpm_tests_args.show_progress and (iteration % 1000 == 0):
                print("iteration %d / %d." % (iteration, len(actions)))

    def perform_test_many_lpm_instances_with_entries_from_file(self, file_name, file_format, max_entries):
        self.perform_test_with_entries_from_file(self.s_lpm0, file_name, file_format, max_entries)
        self.perform_test_with_entries_from_file(self.s_lpm1, file_name, file_format, max_entries)
        self.perform_test_with_entries_from_file(self.s_lpm2, file_name, file_format, max_entries)

    def perform_test_add_remove(self, logical_lpm, test_actions, rounds):
        for round_num in range(rounds):
            for iteration, action in enumerate(test_actions):
                key_val, width = action.get_key_and_width()
                key = lpm_test_utils.generate_lpm_key(key_val, width)
                payload = action.payload
                try:
                    logical_lpm.insert(key, payload)
                except hw_tablescli.BaseException:
                    pass
                if lpm_tests_args.show_progress and (iteration % 1000 == 0):
                    print("insert iteration %d / %d, round %d / %d." % (iteration, len(test_actions), round_num, rounds))

            for iteration, action in enumerate(test_actions):
                key_val, width = action.get_key_and_width()
                key = lpm_test_utils.generate_lpm_key(key_val, width)
                try:
                    logical_lpm.remove(key)
                except hw_tablescli.BaseException:
                    pass
                if lpm_tests_args.show_progress and (iteration % 1000 == 0):
                    print("remove iteration %d / %d, round %d / %d." % (iteration, len(test_actions), round_num, rounds))

    def perform_test_add_remove_many_lpm_instances(self, file_name, file_format, num_entries, rounds):
        actions = lpm_test_utils.parse_lpm_input(file_name, file_format, sys.maxsize)
        self.assertNotEqual(len(actions), 0)
        if lpm_tests_args.shuffle:
            random.Random(lpm_tests_args.seed).shuffle(actions)
        assert num_entries != 0
        assert num_entries == sys.maxsize or num_entries <= len(actions)
        test_actions = actions if num_entries == sys.maxsize else actions[:num_entries]
        self.perform_test_add_remove(self.s_lpm0, test_actions, rounds)
        self.perform_test_add_remove(self.s_lpm1, test_actions, rounds)
        self.perform_test_add_remove(self.s_lpm2, test_actions, rounds)
