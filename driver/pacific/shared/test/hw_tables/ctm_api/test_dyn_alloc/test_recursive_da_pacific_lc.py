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

from unified_table_test_case_base import *
import decor
import logging

#
# Test description: Testing recursive allocation in pacific linecard
#

# In order to see logging messages, uncomment next line:
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')


@unittest.skipUnless(decor.is_hw_pacific(), "Requires HW Pacific device")
class test_recursive_reallocation(unified_table_test_case_base):
    unified_table_test_case_base.slice_modes = sim_utils.LINECARD_3N_3F_DEV

    # Testing recursive allocation Tx0 -> Fw0 (allocate for Fw0)
    def test_alloc_narrow_for_narrow(self):
        tables = [
            "INGRESS_IPV4_SEC_TABLE",
            "EGRESS_IPV4_SEC_TABLE",
        ]

        tables, generators = self.prepare_test_tables(tables)

        tables_to_insert = {
            "INGRESS_IPV4_SEC_TABLE": 3500,
            "EGRESS_IPV4_SEC_TABLE": 3500,
        }

        for table_name in tables_to_insert.keys():
            self.insert_entries_n(table_name, tables[table_name], generators[table_name], tables_to_insert[table_name])
            tables[table_name].attach_default()

        self.assertEqual(tables["EGRESS_IPV4_SEC_TABLE"].do_get_count(), tables_to_insert["EGRESS_IPV4_SEC_TABLE"])

        for table in tables:
            tables[table].detach_default()

    # Testing recursive allocation Tx wide -> Fw wide (reallocate Fw0)
    def test_realloc_wide_for_wide(self):
        tables = [
            "INGRESS_IPV4_SEC_TABLE",
            "EGRESS_IPV4_SEC_TABLE",
            "EGRESS_IPV6_SEC_TABLE",
            "INGRESS_IPV6_SEC_TABLE",
        ]

        tables, generators = self.prepare_test_tables(tables)

        tables_to_init = {
            "INGRESS_IPV4_SEC_TABLE": 3500,
            "EGRESS_IPV4_SEC_TABLE": 2500,
        }

        for table_name in tables_to_init.keys():
            self.insert_entries_n(table_name, tables[table_name], generators[table_name], tables_to_init[table_name])
            tables[table_name].attach_default()

        table_name = "INGRESS_IPV4_SEC_TABLE"
        self.insert_entries_n(table_name, tables[table_name], generators[table_name], 500)

        self.clear_table(tables["INGRESS_IPV4_SEC_TABLE"])

        table_name = "INGRESS_IPV6_SEC_TABLE"
        self.insert_entries_n(table_name, tables[table_name], generators[table_name], 1000)
        tables[table_name].attach_default()

        self.clear_table(tables["EGRESS_IPV4_SEC_TABLE"])

        tables["EGRESS_IPV6_SEC_TABLE"].attach_default()
        self.fill_table(tables["EGRESS_IPV6_SEC_TABLE"], generators["EGRESS_IPV6_SEC_TABLE"])

        self.assertTrue(tables["EGRESS_IPV6_SEC_TABLE"].do_get_count() > 512)

        for table in tables:
            tables[table].detach_default()

    # Testing recursive allocation Tx wide -> Fw wide -> Fw0 (reallocate Tx0)
    def test_realloc_narrow_for_wide_for_wide(self):
        tables = [
            "INGRESS_IPV4_SEC_TABLE",
            "EGRESS_IPV4_SEC_TABLE",
            "EGRESS_IPV6_SEC_TABLE",
            "INGRESS_IPV6_SEC_TABLE",
        ]

        tables, generators = self.prepare_test_tables(tables)

        tables_to_init = {
            "INGRESS_IPV4_SEC_TABLE": 3500,
            "EGRESS_IPV4_SEC_TABLE": 2500,
        }

        for table_name in tables_to_init.keys():
            self.insert_entries_n(table_name, tables[table_name], generators[table_name], tables_to_init[table_name])
            tables[table_name].attach_default()

        table_name = "INGRESS_IPV4_SEC_TABLE"
        self.insert_entries_n(table_name, tables[table_name], generators[table_name], 500)

        self.erase_entries_regular(tables["INGRESS_IPV4_SEC_TABLE"], 0, 1, 512)

        table_name = "INGRESS_IPV6_SEC_TABLE"
        self.insert_entries_n(table_name, tables[table_name], generators[table_name], 1000)
        tables[table_name].attach_default()

        self.clear_table(tables["EGRESS_IPV4_SEC_TABLE"])

        tables["EGRESS_IPV6_SEC_TABLE"].attach_default()
        self.fill_table(tables["EGRESS_IPV6_SEC_TABLE"], generators["EGRESS_IPV6_SEC_TABLE"])

        self.assertTrue(tables["EGRESS_IPV6_SEC_TABLE"].do_get_count() > 512)

        for table in tables:
            tables[table].detach_default()

    #############
    # utilities #
    #############
    def insert_entries_n(self, table_name, table, generator, entries_count):
        logging.info("Inserting " + str(entries_count) + " entries into " + table_name)
        count_before = table.do_get_count()
        for i in range(entries_count):
            if i % 500 == 0:
                logging.info("Inserted " + str(i) + " entries into " + table_name)
            entry = generator.generate_next_entry()
            table.do_append(entry)
        self.assertEqual(table.do_get_count(), count_before + entries_count)

    def prepare_test_tables(self, table_names):
        tables = {}
        generators = {}
        for table in table_names:
            tables[table] = table_factory.create_table(self, self.device, self.topology, table, 0)
            generators[table] = gen_factory.create_gen(self, self.device, table)
        return tables, generators

    def clear_table(self, table):
        table.do_clear()


if __name__ == '__main__':
    unittest.main()
