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
import decor
from leaba import debug
from leaba import sdk
import lldcli
import json
import os
import sys


verbose = 0

# If true, use an existing expected results file. Otherwise, generate one.
sanity_run = False


@unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
class testcase(unittest.TestCase):

    def setUp(self):
        device_id = 0
        import sim_utils
        self.device = sim_utils.create_device(device_id)
        self.ldev = self.device.get_ll_device()
        self.dd = debug.debug_device(self.device)

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_initialize_masks(self):
        ldev = self.ldev
        if ldev.is_gibraltar():
            if decor.is_matilda():
                res, _ = decor.get_matilda_model_from_env()
                expected_result_file_name = os.path.join(
                    sys.path[0], "expected/matilda_{}_test_initialize_masks_expected.json".format(res))
            else:
                expected_result_file_name = os.path.join(sys.path[0], 'expected/gibraltar_test_initialize_masks_expected.json')
        elif ldev.is_asic4():
            expected_result_file_name = os.path.join(sys.path[0], 'expected/asic4_test_initialize_masks_expected.json')
        elif ldev.is_asic5():
            expected_result_file_name = os.path.join(sys.path[0], 'expected/asic5_test_initialize_masks_expected.json')
        else:
            expected_result_file_name = os.path.join(sys.path[0], 'expected/pacific_test_initialize_masks_expected.json')
        if sanity_run:
            with open(expected_result_file_name, 'r') as fp:
                expected_result = json.load(fp)
        else:
            expected_result = {}

        # this test runs in SA mode, in LC mode ts_ms.general_interrupt_register.uch_ms_time_error is masked on slices 3,4,5
        for block in self.dd.device_tree.get_leaf_blocks():
            if not self.ldev.is_block_allowed(block):
                continue
            for reg in block.get_registers():
                if reg.get_desc().type == lldcli.lld_register_type_e_INTERRUPT_MASK:
                    val = ldev.read_register(reg)
                    if sanity_run:
                        if val != expected_result[reg.get_name()]:
                            self.fail("register value doesn't match expected value.\nregister: {}\nexpected value: {}\nactual value: {}\n".format(
                                reg.get_name(), expected_result[reg.get_name()], val))
                    else:
                        expected_result[reg.get_name()] = ldev.read_register(reg)
        if not sanity_run:
            with open(expected_result_file_name, 'w') as fp:
                json.dump(expected_result, fp, indent=2)


if __name__ == '__main__':
    unittest.main()
