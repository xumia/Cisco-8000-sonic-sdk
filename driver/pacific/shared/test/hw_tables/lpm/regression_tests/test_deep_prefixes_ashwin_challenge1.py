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

from logical_lpm_base import logical_lpm_base
import lpm_test_utils
import unittest
import decor


@unittest.skipIf(lpm_test_utils.is_valgrind(), "Test is skipped in valgrind environment due to long running time")
class test_regression_deep_prefixes_ashwin_challenge1(logical_lpm_base):
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_regression_deep_prefixes_ashwin_challenge1(self):
        self.logical_lpm.set_rebalance_interval(1000)
        print("\n\nTesting file: shared/test/hw_tables/lpm/inputs/deep_prefixes_ashwin_challenge1.txt.gz")
        self.perform_test_file(
            "shared/test/hw_tables/lpm/inputs/deep_prefixes_ashwin_challenge1.txt.gz", "OLD_FORMAT", -1)


if __name__ == "__main__":
    unittest.main()
