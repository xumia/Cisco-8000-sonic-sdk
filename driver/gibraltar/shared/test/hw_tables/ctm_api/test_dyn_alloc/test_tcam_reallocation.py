# BEGIN_LEGAL
#
# Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
from unified_table_test_case_base import *
import decor
import logging

#
# Test description:
#
#   - fill the content of all TCAMs by consecutevely filling all the tables;
#
#   - erase certain number of entries from a table that occupies most of the space
#
#   - refill a table that can be refilled utilizing the space freed in the previous step
#

# In order to see logging messages, uncomment next line:
# logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')


@unittest.skipUnless(decor.is_hw_pacific() or decor.is_hw_gibraltar(), "Requires HW Pacific or Gb device")
class test_tcam_reallocation(unified_table_test_case_base):

    def run_tcam_realloc_scenario(self, table_1_name, table_2_name,
                                  erase_entries_count, expected_fill_count,
                                  erase_entries_start=0, erase_entries_step=1, is_random_pattern=False):

        table_1_ref = table_factory.create_table(self, self.device, self.topology, table_1_name, 0)
        table_1_gen = gen_factory.create_gen(self, self.device, table_1_name)
        table_1_ref.attach_default()

        table_2_ref = table_factory.create_table(self, self.device, self.topology, table_2_name, 0)
        table_2_gen = gen_factory.create_gen(self, self.device, table_2_name)
        table_2_ref.attach_default()

        self.fill_table(table_1_name, table_1_ref, table_1_gen)
        self.fill_table(table_2_name, table_2_ref, table_2_gen)

        if is_random_pattern:
            self.erase_entries_random(table_1_name, table_1_ref, erase_entries_count)
        else:
            self.erase_entries_regular(table_1_name, table_1_ref, erase_entries_start, erase_entries_step, erase_entries_count)

        table_2_second_fill_count = self.fill_table(table_2_name, table_2_ref, table_2_gen)
        if(table_2_second_fill_count != expected_fill_count):
            message = "Refill insert count (" + str(table_2_second_fill_count) + \
                ") does not have expected value (" + str(expected_fill_count) + ")"
            self.fail(message)
        else:
            logging.info("Refill insert count (" + str(table_2_second_fill_count) + ") has expected value.")

        table_1_ref.detach_default()
        table_2_ref.detach_default()

    def run_tcam_realloc_scenario_random_tables(self, table_1_is_wide, table_2_is_wide,
                                                erase_entries_count, expected_fill_count,
                                                erase_entries_start=None, erase_entries_step=1, is_random_pattern=False):

        table_1_name = self.get_random_wide_table_name() if table_1_is_wide else self.get_random_narrow_table_name()
        table_2_name = self.get_random_wide_table_name() if table_2_is_wide else self.get_random_narrow_table_name()
        self.run_tcam_realloc_scenario(
            table_1_name=table_1_name,
            table_2_name=table_2_name,
            erase_entries_count=erase_entries_count,
            expected_fill_count=expected_fill_count,
            erase_entries_start=erase_entries_start,
            erase_entries_step=erase_entries_step,
            is_random_pattern=is_random_pattern)

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_tcam_reallocation_nn_random_pattern_1(self):
        self.run_tcam_realloc_scenario(table_1_name="INGRESS_IPV4_SEC_TABLE",
                                       table_2_name="EGRESS_IPV4_SEC_TABLE",
                                       erase_entries_count=512, expected_fill_count=512, is_random_pattern=True)

    def test_tcam_reallocation_nn_1(self):
        self.run_tcam_realloc_scenario(
            table_1_name="INGRESS_IPV4_SEC_TABLE",
            table_2_name="EGRESS_IPV4_SEC_TABLE",
            erase_entries_count=512,
            expected_fill_count=512,
            erase_entries_start=32,
            is_random_pattern=False)

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_tcam_reallocation_nn_random_pattern_2(self):
        self.run_tcam_realloc_scenario(table_1_name="INGRESS_IPV4_SEC_TABLE",
                                       table_2_name="EGRESS_IPV4_SEC_TABLE",
                                       erase_entries_count=1024, expected_fill_count=1024, is_random_pattern=True)

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_tcam_reallocation_nn_2(self):
        self.run_tcam_realloc_scenario(
            table_1_name="INGRESS_IPV4_SEC_TABLE",
            table_2_name="EGRESS_IPV4_SEC_TABLE",
            erase_entries_count=1024,
            expected_fill_count=1024,
            erase_entries_start=32,
            is_random_pattern=False)

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_tcam_reallocation_nn_random_tables_1(self):
        self.run_tcam_realloc_scenario_random_tables(
            table_1_is_wide=False,
            table_2_is_wide=False,
            erase_entries_count=512,
            expected_fill_count=512,
            erase_entries_start=32,
            is_random_pattern=False)

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_tcam_reallocation_nn_random_tables_2(self):
        self.run_tcam_realloc_scenario_random_tables(
            table_1_is_wide=False,
            table_2_is_wide=False,
            erase_entries_count=1024,
            expected_fill_count=1024,
            erase_entries_start=32,
            is_random_pattern=False)

    def test_tcam_reallocation_wn_1(self):
        self.run_tcam_realloc_scenario(
            table_1_name="INGRESS_IPV6_SEC_TABLE",
            table_2_name="EGRESS_IPV4_SEC_TABLE",
            erase_entries_count=512,
            expected_fill_count=1024,
            erase_entries_start=32,
            is_random_pattern=False)

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_tcam_reallocation_wn_random_pattern_1(self):
        self.run_tcam_realloc_scenario(table_1_name="INGRESS_IPV6_SEC_TABLE",
                                       table_2_name="EGRESS_IPV4_SEC_TABLE",
                                       erase_entries_count=512, expected_fill_count=1024, is_random_pattern=True)

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_tcam_reallocation_wn_2(self):
        self.run_tcam_realloc_scenario(
            table_1_name="INGRESS_IPV6_SEC_TABLE",
            table_2_name="EGRESS_IPV4_SEC_TABLE",
            erase_entries_count=1024,
            expected_fill_count=2048,
            erase_entries_start=32,
            is_random_pattern=False)

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_tcam_reallocation_wn_random_pattern_2(self):
        self.run_tcam_realloc_scenario(table_1_name="INGRESS_IPV6_SEC_TABLE",
                                       table_2_name="EGRESS_IPV4_SEC_TABLE",
                                       erase_entries_count=1024, expected_fill_count=2048, is_random_pattern=True)

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_tcam_reallocation_wn_random_tables_1(self):
        self.run_tcam_realloc_scenario_random_tables(
            table_1_is_wide=True,
            table_2_is_wide=False,
            erase_entries_count=512,
            expected_fill_count=1024,
            erase_entries_start=32,
            is_random_pattern=False)

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_tcam_reallocation_wn_random_tables_2(self):
        self.run_tcam_realloc_scenario_random_tables(
            table_1_is_wide=True,
            table_2_is_wide=False,
            erase_entries_count=1024,
            expected_fill_count=2048,
            erase_entries_start=32,
            is_random_pattern=False)

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_tcam_reallocation_ww_random_pattern_1(self):
        self.run_tcam_realloc_scenario(table_1_name="INGRESS_IPV6_SEC_TABLE",
                                       table_2_name="EGRESS_IPV6_SEC_TABLE",
                                       erase_entries_count=512, expected_fill_count=512, is_random_pattern=True)

    def test_tcam_reallocation_ww_1(self):
        self.run_tcam_realloc_scenario(
            table_1_name="INGRESS_IPV6_SEC_TABLE",
            table_2_name="EGRESS_IPV6_SEC_TABLE",
            erase_entries_count=512,
            expected_fill_count=512,
            erase_entries_start=32,
            is_random_pattern=False)

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_tcam_reallocation_ww_random_pattern_2(self):
        self.run_tcam_realloc_scenario(table_1_name="INGRESS_IPV6_SEC_TABLE",
                                       table_2_name="EGRESS_IPV6_SEC_TABLE",
                                       erase_entries_count=1024, expected_fill_count=1024, is_random_pattern=True)

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_tcam_reallocation_ww_2(self):
        self.run_tcam_realloc_scenario(
            table_1_name="INGRESS_IPV6_SEC_TABLE",
            table_2_name="EGRESS_IPV6_SEC_TABLE",
            erase_entries_count=1024,
            expected_fill_count=1024,
            erase_entries_start=32,
            is_random_pattern=False)

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_tcam_reallocation_ww_random_tables_1(self):
        self.run_tcam_realloc_scenario_random_tables(
            table_1_is_wide=True,
            table_2_is_wide=True,
            erase_entries_count=512,
            expected_fill_count=512,
            erase_entries_start=32,
            is_random_pattern=False)

    @unittest.skipUnless(decor.is_run_slow(), "Testcase will run only if RUN_SLOW_TESTS mode is enabled")
    def test_tcam_reallocation_ww_random_tables_2(self):
        self.run_tcam_realloc_scenario_random_tables(
            table_1_is_wide=True,
            table_2_is_wide=True,
            erase_entries_count=1024,
            expected_fill_count=1024,
            erase_entries_start=32,
            is_random_pattern=False)


if __name__ == '__main__':
    unittest.main()
