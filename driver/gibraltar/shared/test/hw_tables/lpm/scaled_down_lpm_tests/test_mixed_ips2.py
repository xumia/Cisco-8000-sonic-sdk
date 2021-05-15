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

import unittest
import sys
import lpm_test_utils
from scaled_down_logical_lpm_test_base import lpm_scaled_down_test
import decor


@unittest.skipIf(lpm_test_utils.is_valgrind(),
                 "Test is skipped in valgrind environment due to long running time")
class mixed_ips2(lpm_scaled_down_test):
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mixed_ips2(self):
        self.perform_test_many_lpm_instances_with_entries_from_file(
            "shared/test/hw_tables/lpm/inputs/lpm_data.mixed_ips2.txt.gz", "OLD_FORMAT", sys.maxsize)


if __name__ == '__main__':
    unittest.main()
