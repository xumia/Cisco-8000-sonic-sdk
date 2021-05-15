#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import sys
import gzip

import unittest
from leaba import sdk
import decor
import packet_test_utils


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_hw_gibraltar(), "SKIP-GB-HW")
class test_init(unittest.TestCase):

    def setUp(self):
        import sim_utils
        self.device = sim_utils.create_device(0)

        self.expected_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'expected', 'test_init')

    def tearDown(self):
        self.device.tearDown()

    def _test_tm(self):
        out_overhead = self.device.get_accounted_packet_overhead()
        self.assertEqual(out_overhead, 0)

        # Change the overhead accounting to match TM NPL application
        # Regular NPU header is 40 bytes while in TM NPL the NPU header is 24 bytes - hence has to add 16.
        self.device.set_accounted_packet_overhead(16)

        out_overhead = self.device.get_accounted_packet_overhead()
        self.assertEqual(out_overhead, 16)

        in_file = os.path.join(self.expected_dir, 'test_init_input.txt.gz')
        with gzip.open(in_file, 'rb') as fh_in:
            device = self.device
            lineno = 0
            for line in fh_in:
                lineno += 1
                try:
                    exec(line)
                except Exception as e:
                    print(e)
                    print('lineno=%d' % lineno)
                    raise

            packet_test_utils.compare_regs_mems(
                self, self.device, os.path.join(self.expected_dir, 'test_init.json.gz'), 'test',
                217118, '\.npu\.|\.npuh\.|\.cdb\.|\.mac_pool|\.ifgb\.|\.sch\.spare_reg|\.pdoq\.fdoq\.ifg_credit_init')


if __name__ == '__main__':
    unittest.main()
