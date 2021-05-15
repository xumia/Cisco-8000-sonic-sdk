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

from lpm_debug_utils import lpm_helper
from logical_lpm_with_simulator import logical_lpm_with_simulator
import unittest
import lpm_test_utils
import lpm_compare_models
import os
from parser_formats import lpm_instruction
import decor

FILE_PATH = "shared/test/hw_tables/lpm/inputs/ip_mix_big.txt.gz"
FILE_FORMAT = "OLD_FORMAT"
LPM_DUMP_FILENAME = "lpm_dump_compare_hw_sw.json.gz"
LPM_HW_FILENAME = "lpm_hw.csv"


@unittest.skipIf(not decor.is_pacific(), "Test is ready only for PACIFIC")
class test_hw_scripts_management(logical_lpm_with_simulator):
    '''
    The parameters values for working with the test:
    LPM_DEVICE_SIMULATOR should work
    Shadow_read should be enable
    HBM_ENABLED souldn't be enable (the simulator does not support HBM)
    '''
    HBM_ENABLED = False  # TODO:HBM

    def test_hw_sw_state(self):
        print(" * Inserting entries from file \"{}\"".format(FILE_PATH))
        lpm_input = lpm_test_utils.generate_instructions_from_file(FILE_PATH, FILE_FORMAT, 100000)
        lpm_test_utils.execute_bulk(self.logical_lpm, lpm_input, 100000)
        device_type = self.get_device_type()
        self.generate_models_files(device_type)
        equal = lpm_compare_models.compare_models(LPM_DUMP_FILENAME, LPM_HW_FILENAME, device_type)
        print(" * Deleting the dump file (by calling save_state)")
        os.remove(LPM_DUMP_FILENAME)
        print(" * Deleting the hw file (by calling read_lpm_memory)")
        os.remove(LPM_HW_FILENAME)
        self.assertTrue(equal, "Models are not equal")

    #@staticmethod
    def get_device_type(self):
        is_gb = decor.is_gibraltar()
        is_pacific = decor.is_pacific()
        check_correct_device = is_pacific or is_gb
        self.assertTrue(check_correct_device)
        if is_pacific:
            return lpm_helper.PACIFIC
        else:
            return lpm_helper.GB

    def generate_models_files(self, device_type):
        '''
        Getting SW model and HW model
        '''
        self.logical_lpm.save_state(LPM_DUMP_FILENAME)
        debug_object = lpm_helper.load_from_live_device(self.logical_lpm, device_type)
        # HBM is not working with the simulator
        debug_object.read_lpm_memory(output_file=LPM_HW_FILENAME, print_hbm=False, print_hbm_replicas=False)


if __name__ == "__main__":
    unittest.main()
