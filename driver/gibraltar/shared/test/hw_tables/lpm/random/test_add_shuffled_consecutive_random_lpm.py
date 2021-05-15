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
import lpm_test_utils

from random_logical_lpm_base import random_logical_lpm_base
import decor


@unittest.skip("Test is currently skipped because of failure.")
class test_add_shuffled_consecutive_prefixes_random_lpm(random_logical_lpm_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_insert_consecutive_1_5m_ipv4_shuffled(self):
        prefixes = lpm_test_utils.generate_consecutive_prefixes(
            num_entries=1500000, step=1, vrf=0, base_prefix=lpm_test_utils.BASE_IPV4_PREFIX)
        lpm_test_utils.randomize_list(prefixes)
        instructions = lpm_test_utils.populate_with_actions(
            self.logical_lpm, prefixes, action=lpm_test_utils.lpm_instruction.INSERT)
        lpm_test_utils.execute_one_by_one(self.logical_lpm, instructions, fail=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_insert_consecutive_450k_ipv6_shuffled(self):
        prefixes = lpm_test_utils.generate_consecutive_prefixes(
            num_entries=450000, step=1, vrf=0, base_prefix=lpm_test_utils.BASE_IPV6_PREFIX)
        lpm_test_utils.randomize_list(prefixes)
        instructions = lpm_test_utils.populate_with_actions(
            self.logical_lpm, prefixes, action=lpm_test_utils.lpm_instruction.INSERT)
        lpm_test_utils.execute_one_by_one(self.logical_lpm, instructions, fail=False)


if __name__ == '__main__':
    unittest.main()
