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

from unified_table_test_case_base import *
import logging
import decor

NUM_ENTRIES_TO_ALLOCATE_ONE_TCAM = 512
NUM_ENTRIES_TO_ALLOCATE_TWO_TCAMS = NUM_ENTRIES_TO_ALLOCATE_ONE_TCAM * 2

# In order to see logging messages, uncomment next line:
# logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')


class test_tcam_allocation(unified_table_test_case_base):

    def run_tcam_alloc_scenario(self, insert_dict):

        table_refs = {}
        table_gens = {}

        for key in insert_dict:
            table_refs[key] = table_factory.create_table(self, self.device, self.topology, key, 0)
            table_gens[key] = gen_factory.create_gen(self, self.device, key)

        for key in insert_dict:
            logging.info("Inserting " + str(insert_dict[key]) + " entries into " + key)
            table_refs[key].attach_default()
            for i in range(insert_dict[key]):
                entry = table_gens[key].generate_next_entry()
                table_refs[key].do_append(entry)
            self.assertEqual(table_refs[key].do_get_count(), insert_dict[key])

        for key in table_refs:
            table_refs[key].detach_default()

    def test_1_tx0_1_f0(self):
        insert_dict = {
            "EGRESS_IPV4_SEC_TABLE": NUM_ENTRIES_TO_ALLOCATE_ONE_TCAM,
            "INGRESS_IPV4_SEC_TABLE": NUM_ENTRIES_TO_ALLOCATE_ONE_TCAM
        }
        self.run_tcam_alloc_scenario(insert_dict)

    def test_1_tx0_1_fw(self):
        insert_dict = {
            "EGRESS_IPV4_SEC_TABLE": NUM_ENTRIES_TO_ALLOCATE_ONE_TCAM,
            "INGRESS_IPV6_SEC_TABLE": NUM_ENTRIES_TO_ALLOCATE_ONE_TCAM
        }
        self.run_tcam_alloc_scenario(insert_dict)

    def test_1_txw_1_f0(self):
        insert_dict = {
            "EGRESS_IPV6_SEC_TABLE": NUM_ENTRIES_TO_ALLOCATE_ONE_TCAM,
            "INGRESS_IPV4_SEC_TABLE": NUM_ENTRIES_TO_ALLOCATE_ONE_TCAM
        }
        self.run_tcam_alloc_scenario(insert_dict)

    def test_1_txw_1_fw(self):
        insert_dict = {
            "EGRESS_IPV6_SEC_TABLE": NUM_ENTRIES_TO_ALLOCATE_ONE_TCAM,
            "INGRESS_IPV6_SEC_TABLE": NUM_ENTRIES_TO_ALLOCATE_ONE_TCAM
        }
        self.run_tcam_alloc_scenario(insert_dict)

    def test_2_tx0_2_f0(self):
        insert_dict = {
            "EGRESS_IPV4_SEC_TABLE": NUM_ENTRIES_TO_ALLOCATE_TWO_TCAMS,
            "INGRESS_IPV4_SEC_TABLE": NUM_ENTRIES_TO_ALLOCATE_TWO_TCAMS
        }
        self.run_tcam_alloc_scenario(insert_dict)

    def test_2_txw_2_f0(self):
        insert_dict = {
            "EGRESS_IPV6_SEC_TABLE": NUM_ENTRIES_TO_ALLOCATE_TWO_TCAMS,
            "INGRESS_IPV4_SEC_TABLE": NUM_ENTRIES_TO_ALLOCATE_TWO_TCAMS
        }
        self.run_tcam_alloc_scenario(insert_dict)

    def test_1_f0_1_fw_1_tx0(self):
        insert_dict = {
            "INGRESS_IPV4_SEC_TABLE": NUM_ENTRIES_TO_ALLOCATE_ONE_TCAM,
            "INGRESS_IPV6_SEC_TABLE": NUM_ENTRIES_TO_ALLOCATE_ONE_TCAM,
            "EGRESS_IPV4_SEC_TABLE": NUM_ENTRIES_TO_ALLOCATE_ONE_TCAM,
        }
        self.run_tcam_alloc_scenario(insert_dict)


if __name__ == '__main__':
    unittest.main()
