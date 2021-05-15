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

import ipaddress
import unittest
from scale_test_base import scale_test_base
import lpm_test_utils
import decor


class test_add_groups_of_consecutive_prefixes(scale_test_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_insert_consecutive_groups_1_5m_ipv4(self):
        lpm_groups_parameters = []
        lpm_groups_parameters.append(
            lpm_test_utils.lpm_groups_desc(
                num_entries=300000,
                step=1,
                vrf=0,
                base_prefix=ipaddress.IPv4Network('10.0.0.0/28')))
        lpm_groups_parameters.append(
            lpm_test_utils.lpm_groups_desc(
                num_entries=500000,
                step=2,
                vrf=0,
                base_prefix=ipaddress.IPv4Network('200.0.0.0/28')))
        lpm_groups_parameters.append(
            lpm_test_utils.lpm_groups_desc(
                num_entries=400000,
                step=3,
                vrf=0,
                base_prefix=ipaddress.IPv4Network('11.1.0.0/28')))
        lpm_groups_parameters.append(
            lpm_test_utils.lpm_groups_desc(
                num_entries=300000,
                step=4,
                vrf=0,
                base_prefix=ipaddress.IPv4Network('250.0.0.0/28')))
        prefixes = lpm_test_utils.generate_groups_of_consecutive(lpm_groups_parameters)
        instructions = lpm_test_utils.populate_with_actions(
            self.logical_lpm, prefixes, action=lpm_test_utils.lpm_instruction.INSERT)
        lpm_test_utils.execute_one_by_one(self.logical_lpm, instructions)

    def disabled_test_insert_consecutive_groups_450k_ipv6(self):
        lpm_groups_parameters = []
        lpm_groups_parameters.append(
            lpm_test_utils.lpm_groups_desc(
                num_entries=125000,
                step=1,
                vrf=0,
                base_prefix=ipaddress.IPv6Network('500:0::/64')))
        lpm_groups_parameters.append(
            lpm_test_utils.lpm_groups_desc(
                num_entries=100000,
                step=2,
                vrf=0,
                base_prefix=ipaddress.IPv6Network('1000:0::/64')))
        lpm_groups_parameters.append(
            lpm_test_utils.lpm_groups_desc(
                num_entries=100000,
                step=3,
                vrf=0,
                base_prefix=ipaddress.IPv6Network('2000:0::/64')))
        lpm_groups_parameters.append(
            lpm_test_utils.lpm_groups_desc(
                num_entries=125000,
                step=4,
                vrf=0,
                base_prefix=ipaddress.IPv6Network('4000:0::/64')))

        prefixes = lpm_test_utils.generate_groups_of_consecutive(lpm_groups_parameters)
        instructions = lpm_test_utils.populate_with_actions(
            self.logical_lpm, prefixes, action=lpm_test_utils.lpm_instruction.INSERT)
        lpm_test_utils.execute_one_by_one(self.logical_lpm, instructions)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_insert_consecutive_300k_ipv4_and_300k_ipv6(self):
        lpm_groups_parameters = []
        lpm_groups_parameters.append(
            lpm_test_utils.lpm_groups_desc(
                num_entries=300000,
                step=1,
                vrf=0,
                base_prefix=ipaddress.IPv6Network('2000:0::/60')))
        lpm_groups_parameters.append(
            lpm_test_utils.lpm_groups_desc(
                num_entries=300000,
                step=2,
                vrf=0,
                base_prefix=ipaddress.IPv4Network('10.0.0.0/30')))

        prefixes = lpm_test_utils.generate_groups_of_consecutive(lpm_groups_parameters)
        instructions = lpm_test_utils.populate_with_actions(
            self.logical_lpm, prefixes, action=lpm_test_utils.lpm_instruction.INSERT)
        lpm_test_utils.execute_one_by_one(self.logical_lpm, instructions)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_insert_consecutive_groups_1_5m_ipv4_shuffled(self):
        lpm_groups_parameters = []
        lpm_groups_parameters.append(
            lpm_test_utils.lpm_groups_desc(
                num_entries=300000,
                step=1,
                vrf=0,
                base_prefix=ipaddress.IPv4Network('10.0.0.0/28')))
        lpm_groups_parameters.append(
            lpm_test_utils.lpm_groups_desc(
                num_entries=500000,
                step=2,
                vrf=0,
                base_prefix=ipaddress.IPv4Network('200.0.0.0/28')))
        lpm_groups_parameters.append(
            lpm_test_utils.lpm_groups_desc(
                num_entries=400000,
                step=3,
                vrf=0,
                base_prefix=ipaddress.IPv4Network('11.1.0.0/28')))
        lpm_groups_parameters.append(
            lpm_test_utils.lpm_groups_desc(
                num_entries=300000,
                step=4,
                vrf=0,
                base_prefix=ipaddress.IPv4Network('250.0.0.0/28')))

        prefixes = lpm_test_utils.generate_groups_of_consecutive(lpm_groups_parameters)
        lpm_test_utils.randomize_list(prefixes)
        instructions = lpm_test_utils.populate_with_actions(
            self.logical_lpm, prefixes, action=lpm_test_utils.lpm_instruction.INSERT)
        lpm_test_utils.execute_one_by_one(self.logical_lpm, instructions)

    def disabled_test_insert_consecutive_groups_450k_ipv6_shuffled(self):
        lpm_groups_parameters = []
        lpm_groups_parameters.append(
            lpm_test_utils.lpm_groups_desc(
                num_entries=125000,
                step=1,
                vrf=0,
                base_prefix=ipaddress.IPv6Network('500:0::/64')))
        lpm_groups_parameters.append(
            lpm_test_utils.lpm_groups_desc(
                num_entries=100000,
                step=2,
                vrf=0,
                base_prefix=ipaddress.IPv6Network('1000:0::/64')))
        lpm_groups_parameters.append(
            lpm_test_utils.lpm_groups_desc(
                num_entries=100000,
                step=3,
                vrf=0,
                base_prefix=ipaddress.IPv6Network('2000:0::/64')))
        lpm_groups_parameters.append(
            lpm_test_utils.lpm_groups_desc(
                num_entries=125000,
                step=4,
                vrf=0,
                base_prefix=ipaddress.IPv6Network('4000:0::/64')))

        prefixes = lpm_test_utils.generate_groups_of_consecutive(lpm_groups_parameters)
        lpm_test_utils.randomize_list(prefixes)
        instructions = lpm_test_utils.populate_with_actions(
            self.logical_lpm, prefixes, action=lpm_test_utils.lpm_instruction.INSERT)
        lpm_test_utils.execute_one_by_one(self.logical_lpm, instructions)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_insert_consecutive_300k_ipv4_and_300k_ipv6_shuffled(self):
        lpm_groups_parameters = []
        lpm_groups_parameters.append(
            lpm_test_utils.lpm_groups_desc(
                num_entries=300000,
                step=1,
                vrf=0,
                base_prefix=ipaddress.IPv6Network('2000:0::/60')))
        lpm_groups_parameters.append(
            lpm_test_utils.lpm_groups_desc(
                num_entries=300000,
                step=2,
                vrf=0,
                base_prefix=ipaddress.IPv4Network('10.0.0.0/30')))

        prefixes = lpm_test_utils.generate_groups_of_consecutive(lpm_groups_parameters)
        lpm_test_utils.randomize_list(prefixes)
        instructions = lpm_test_utils.populate_with_actions(
            self.logical_lpm, prefixes, action=lpm_test_utils.lpm_instruction.INSERT)
        lpm_test_utils.execute_one_by_one(self.logical_lpm, instructions)


if __name__ == '__main__':
    unittest.main()
