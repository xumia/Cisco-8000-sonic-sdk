#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

from scaled_down_logical_lpm_test_base import lpm_scaled_down_test
import unittest
import sys
import decor


class add_remove_large_database(lpm_scaled_down_test):
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_add_remove_large_database(self):
        self.perform_test_add_remove_many_lpm_instances(
            "shared/test/hw_tables/lpm/inputs/lpm_data.consecutive_ipv4_entries_with_some_ipv6.10k.txt.gz",
            "OLD_FORMAT",
            sys.maxsize,
            3)


if __name__ == '__main__':
    unittest.main()
