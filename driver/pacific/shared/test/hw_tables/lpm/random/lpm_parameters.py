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

import random
import constraint
import os
from datetime import datetime
from argument_parser import args_parser


ASIC_GB = os.getenv('ASIC') and os.getenv('ASIC').startswith('GIBRALTAR')


def higher_or_equal_value(a, b):
    return a >= b


def less_than(a, b):
    return a < b


def add_pacific_shared_entries_constraint(hbm_enabled, l2_max_hbm_bucket_size, l2_max_sram_bucket_size, l2_double_bucket_size):
    max_double_bucket_size = l2_max_sram_bucket_size
    if hbm_enabled:
        max_double_bucket_size = min(l2_max_hbm_bucket_size, l2_max_sram_bucket_size)
    l2_num_shared_entries = max_double_bucket_size - (l2_double_bucket_size - max_double_bucket_size)
    return (l2_num_shared_entries == 14)


def add_l2_double_bucket_size_constraint(hbm_enabled, l2_max_hbm_bucket_size, l2_max_sram_bucket_size, l2_double_bucket_size):
    max_double_bucket_size = l2_max_sram_bucket_size
    if hbm_enabled:
        max_double_bucket_size = min(l2_max_hbm_bucket_size, l2_max_sram_bucket_size)
    if (2 * max_double_bucket_size < l2_double_bucket_size) or (max_double_bucket_size > l2_double_bucket_size):
        return False
    return True


class lpm_parameters:

    def __init__(self):
        self.seed = int(round(datetime.now().timestamp())) if args_parser.seed is None else args_parser.seed
        random.seed(self.seed)
        print("Seed value for lpm parameters:", self.seed)
        self.problem = constraint.Problem(constraint.MinConflictsSolver())
        self.problem.addVariable('HBM_ENABLED', [True, False])
        self.problem.addVariable('NUM_OF_CORES', range(1, 17))
        self.problem.addVariable('MAX_DISTRIBUTOR_SIZE', range(2, 129, 2))  # max_distributor_size should be even number
        self.problem.addVariable('L2_MAX_HBM_BUCKET_SIZE', range(1, 25))
        self.problem.addVariable('L2_BUCKETS_PER_SRAM_ROW', [1, 2])
        if ASIC_GB:
            self.problem.addVariable('L2_DOUBLE_BUCKET_SIZE', range(2, 19, 2))
            self.problem.addVariable('L2_MAX_SRAM_BUCKET_SIZE', range(2, 19, 2))
        else:
            self.problem.addVariable('L2_DOUBLE_BUCKET_SIZE', range(1, 25))
            self.problem.addVariable('L2_MAX_SRAM_BUCKET_SIZE', range(1, 20))
            # Pacific constraint:l2_num_shared_entries == 14
            self.problem.addConstraint(
                add_pacific_shared_entries_constraint, [
                    'HBM_ENABLED', 'L2_MAX_HBM_BUCKET_SIZE', 'L2_MAX_SRAM_BUCKET_SIZE', 'L2_DOUBLE_BUCKET_SIZE'])
        self.problem.addVariable('L2_MAX_NUM_OF_SRAM_BUCKETS', range(2, 4097, 2))  # l2_max_num_of_buckets should be even number
        self.problem.addVariable('L2_MAX_NUM_OF_HBM_BUCKETS', range(0, 12 * 1024 + 1))
        self.problem.addVariable('L1_DOUBLE_BUCKET_SIZE', range(1, 9))
        self.problem.addVariable('L1_MAX_BUCKET_SIZE', range(1, 7))
        self.problem.addVariable('L1_MAX_NUM_OF_BUCKETS', range(2, 4 * 1024 + 1, 2))  # l1_max_num_of_buckets should be even number
        self.problem.addVariable('L1_BUCKETS_PER_SRAM_ROW', [1, 2])
        self.problem.addVariable('TCAM_NUM_BANKSETS', range(1, 3))
        self.problem.addVariable('TCAM_BANK_SIZE', range(2, 513))
        self.problem.addVariable('MAX_TCAM_QUAD_ENTRIES', range(1, 241))
        self.problem.addVariable('TCAM_DOUBLE_WIDTH_KEY_WEIGHT', range(1, 5))
        self.problem.addVariable('TCAM_QUAD_WIDTH_KEY_WEIGHT', range(1, 13))
        self.problem.addVariable('REBALANCE_INTERVAL', range(50, 2000))
        self.problem.addConstraint(higher_or_equal_value, ['L2_DOUBLE_BUCKET_SIZE', 'L2_MAX_SRAM_BUCKET_SIZE'])
        self.problem.addConstraint(higher_or_equal_value, ['L1_DOUBLE_BUCKET_SIZE', 'L1_MAX_BUCKET_SIZE'])
        self.problem.addConstraint(higher_or_equal_value, ['TCAM_QUAD_WIDTH_KEY_WEIGHT', 'TCAM_DOUBLE_WIDTH_KEY_WEIGHT'])
        self.problem.addConstraint(less_than, ['MAX_TCAM_QUAD_ENTRIES', 'TCAM_BANK_SIZE'])
        self.problem.addConstraint(lambda a, b: (a and (b == 1)) or (not a), ['HBM_ENABLED', 'L2_BUCKETS_PER_SRAM_ROW'])
        self.problem.addConstraint(
            lambda a, b: ((not a) and (b == 0)) or (a and (b > 0)), ['HBM_ENABLED', 'L2_MAX_NUM_OF_HBM_BUCKETS']
        )
        # 2*l2_max_bucket_size >= l2_double_bucket_size and l2_max_bucket_size = min(l2_max_hbm_size, l2_max_bucket_size)
        self.problem.addConstraint(
            add_l2_double_bucket_size_constraint, [
                'HBM_ENABLED', 'L2_MAX_HBM_BUCKET_SIZE', 'L2_MAX_SRAM_BUCKET_SIZE', 'L2_DOUBLE_BUCKET_SIZE'])


lpm_parameters = lpm_parameters()
