#!/usr/bin/env python3
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
import lldcli
import lpm_test_utils
import random
import pprint
from scale_tests import scale_test_utils
from argument_parser import args_parser
from lpm_parameters import lpm_parameters
from parser_formats import lpm_instruction

DEVICE_PATH = "/dev/testdev"

DISTRIBUTOR_ROW_WIDTH = 80
MAX_BUCKET_DEPTH = 16
TCAM_SINGLE_WIDTH_KEY_WEIGHT = 1
TRAP_DESTINATION = 0xc0ffe


class random_logical_lpm_base(unittest.TestCase):

    s_lld = None
    device_id = 1

    @classmethod
    def setUpClass(cls):
        cls.parameters = lpm_parameters.problem.getSolution()
        assert cls.parameters is not None
        print("Creating logical lpm with parameters:")
        pprint.pprint(cls.parameters)

    @classmethod
    def tearDownClass(cls):
        cls.parameters = None

    def setUp(self):
        self.s_lld = lldcli.ll_device_create(self.device_id, DEVICE_PATH)
        assert self.s_lld is not None
        lpm_settings = self.generate_lpm_settings()

        self.logical_lpm = hw_tablescli.create_logical_lpm(self.s_lld, lpm_settings)
        self.logical_lpm.set_rebalance_interval(self.parameters.get('REBALANCE_INTERVAL'))

    def tearDown(self):
        self.s_lld = None
        self.logical_lpm = None

    def generate_and_insert_consecutive_prefixes(self, num_entries, prefix, vrf=0, shuffle=False):
        instructions = scale_test_utils.generate_consecutive_prefixes(num_entries, prefix, vrf)
        if shuffle or args_parser.random:
            random_generator = random.Random(lpm_parameters.seed)
            random_generator.shuffle(instructions)
        scale_test_utils.do_lpm_insert_and_verify_prefixes(self.logical_lpm, num_entries, instructions, fail_on_oor=False)

    def lpm_generate_and_insert_many_groups_of_consecutive_prefixes(
            self, base_prefix, vrf, num_groups, num_entries_per_group, group_prefix_length):
        prefixes = scale_test_utils.generate_many_groups_of_consecutive_prefixes(
            base_prefix, vrf, num_groups, num_entries_per_group, group_prefix_length)
        if args_parser.random:
            random_generator = random.Random(lpm_parameters.seed)
            random_generator.shuffle(prefixes)
        scale_test_utils.do_lpm_insert_and_verify_prefixes(self.logical_lpm, len(prefixes), prefixes, fail_on_oor=False)

    def generate_lpm_settings(self):
        lpm_settings = hw_tablescli.lpm_settings()
        lpm_settings.num_cores = self.parameters.get('NUM_OF_CORES')
        lpm_settings.num_distributor_lines = self.parameters.get('MAX_DISTRIBUTOR_SIZE')
        lpm_settings.distributor_row_width = DISTRIBUTOR_ROW_WIDTH
        lpm_settings.l2_double_bucket_size = self.parameters.get('L2_DOUBLE_BUCKET_SIZE')
        lpm_settings.l2_max_bucket_size = self.parameters.get('L2_MAX_SRAM_BUCKET_SIZE')
        lpm_settings.hbm_max_bucket_size = self.parameters.get('L2_MAX_HBM_BUCKET_SIZE')
        lpm_settings.l1_double_bucket_size = self.parameters.get('L1_DOUBLE_BUCKET_SIZE')
        lpm_settings.l1_max_sram_buckets = self.parameters.get('L1_MAX_NUM_OF_BUCKETS')
        lpm_settings.l1_max_bucket_size = self.parameters.get('L1_MAX_BUCKET_SIZE')
        lpm_settings.max_bucket_depth = MAX_BUCKET_DEPTH
        lpm_settings.tcam_max_quad_entries = self.parameters.get('MAX_TCAM_QUAD_ENTRIES')
        lpm_settings.l2_buckets_per_sram_row = self.parameters.get('L2_BUCKETS_PER_SRAM_ROW')
        lpm_settings.l2_max_number_of_sram_buckets = self.parameters.get('L2_MAX_NUM_OF_SRAM_BUCKETS')
        lpm_settings.l2_max_number_of_hbm_buckets = self.parameters.get('L2_MAX_NUM_OF_HBM_BUCKETS')
        lpm_settings.tcam_num_banksets = self.parameters.get('TCAM_NUM_BANKSETS')
        lpm_settings.tcam_bank_size = self.parameters.get('TCAM_BANK_SIZE')
        lpm_settings.tcam_single_width_key_weight = TCAM_SINGLE_WIDTH_KEY_WEIGHT
        lpm_settings.tcam_double_width_key_weight = self.parameters.get('TCAM_DOUBLE_WIDTH_KEY_WEIGHT')
        lpm_settings.tcam_quad_width_key_weight = self.parameters.get('TCAM_QUAD_WIDTH_KEY_WEIGHT')
        lpm_settings.trap_destination = TRAP_DESTINATION
        lpm_settings.l1_buckets_per_sram_row = self.parameters.get('L1_BUCKETS_PER_SRAM_ROW')
        return lpm_settings
