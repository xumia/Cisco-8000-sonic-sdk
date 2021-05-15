# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
from scale_test_base import scale_test_base
import lpm_test_utils
import decor


class test_add_many_groups_of_consecutive_prefixes(scale_test_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_insert_many_consecutive_groups_1_5m_ipv4(self):
        prefixes = lpm_test_utils.generate_many_groups_of_consecutive_prefixes(
            num_entries=3000,
            step=1,
            num_groups=50,
            group_prefix_length=6,
            vrf=0,
            base_prefix=lpm_test_utils.BASE_IPV4_PREFIX)
        instructions = lpm_test_utils.populate_with_actions(
            self.logical_lpm, prefixes, action=lpm_test_utils.lpm_instruction.INSERT)
        lpm_test_utils.execute_one_by_one(self.logical_lpm, instructions)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_insert_many_consecutive_groups_450k_ipv6(self):
        prefixes = lpm_test_utils.generate_many_groups_of_consecutive_prefixes(
            num_entries=9000,
            step=1,
            num_groups=50,
            group_prefix_length=10,
            vrf=0,
            base_prefix=lpm_test_utils.BASE_IPV6_PREFIX)
        instructions = lpm_test_utils.populate_with_actions(
            self.logical_lpm, prefixes, action=lpm_test_utils.lpm_instruction.INSERT)
        lpm_test_utils.execute_one_by_one(self.logical_lpm, instructions)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_insert_many_consecutive_groups_300k_ipv4_and_300k_ipv6(self):
        prefixes = lpm_test_utils.generate_many_groups_of_consecutive_prefixes(
            num_entries=6000,
            step=1,
            num_groups=50,
            group_prefix_length=10,
            vrf=0,
            base_prefix=lpm_test_utils.BASE_IPV4_PREFIX)
        instructions = lpm_test_utils.populate_with_actions(
            self.logical_lpm, prefixes, action=lpm_test_utils.lpm_instruction.INSERT)
        lpm_test_utils.execute_one_by_one(self.logical_lpm, instructions)

        prefixes = lpm_test_utils.generate_many_groups_of_consecutive_prefixes(
            num_entries=6000,
            step=1,
            num_groups=50,
            group_prefix_length=10,
            vrf=0,
            base_prefix=lpm_test_utils.BASE_IPV6_PREFIX)
        instructions = lpm_test_utils.populate_with_actions(
            self.logical_lpm, prefixes, action=lpm_test_utils.lpm_instruction.INSERT)
        lpm_test_utils.execute_one_by_one(self.logical_lpm, instructions)


if __name__ == '__main__':
    unittest.main()
