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

from logical_lpm_base import logical_lpm_base
import lpm_test_utils
from hw_tablescli import lpm_ip_protocol_e_IPV4, lpm_ip_protocol_e_IPV6
import unittest


class test_logical_lpm_api(logical_lpm_base):
    INPUT_FILE = "shared/test/hw_tables/lpm/inputs/customer_tables/lpm_data.Spitfire-route-attga401me9.txt.gz"

    @classmethod
    def setUpClass(cls):
        cls.lpm_input = lpm_test_utils.generate_instructions_from_file(cls.INPUT_FILE, "OLD_FORMAT", -1)

    def test_get_available_entries(self):
        BULK_SIZE = 800
        NUM_BULKS = 100
        MAX_ENTRIES_TO_INSERT = max(BULK_SIZE * NUM_BULKS, len(self.lpm_input))
        current_ipv4_available_entries = self.logical_lpm.get_available_entries(lpm_ip_protocol_e_IPV4)
        current_ipv6_available_entries = self.logical_lpm.get_available_entries(lpm_ip_protocol_e_IPV6)

        for bulk_start_idx in range(0, MAX_ENTRIES_TO_INSERT, BULK_SIZE):
            bulk_entries = self.lpm_input[bulk_start_idx:bulk_start_idx + BULK_SIZE]
            lpm_test_utils.execute_bulk(self.logical_lpm, bulk_entries, BULK_SIZE)
            post_insert_v4_available_entries = self.logical_lpm.get_available_entries(lpm_ip_protocol_e_IPV4)
            self.assertLess(post_insert_v4_available_entries, current_ipv4_available_entries)
            post_insert_v6_available_entries = self.logical_lpm.get_available_entries(lpm_ip_protocol_e_IPV6)
            self.assertLess(post_insert_v6_available_entries, current_ipv6_available_entries)
            current_ipv4_available_entries = post_insert_v4_available_entries
            current_ipv6_available_entries = post_insert_v6_available_entries


if __name__ == "__main__":
    unittest.main()
