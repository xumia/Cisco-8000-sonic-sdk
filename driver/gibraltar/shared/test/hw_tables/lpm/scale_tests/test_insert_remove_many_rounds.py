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
import scale_test_utils
import lpm_test_utils
import decor


@unittest.skip("Test is skipped because of long running time.")
class test_insert_remove_prefixes_many_rounds(scale_test_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_insert_remove_consecutive_1_5m_ipv4_many_rounds(self):
        scale_test_utils.lpm_insert_remove_consecutive_prefixes_many_rounds(
            self.logical_lpm, 1500000, scale_test_utils.BASE_IPV4_PREFIX, num_to_delete=1500000, rounds=3)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_insert_remove_consecutive_450k_ipv6_many_rounds(self):
        scale_test_utils.lpm_insert_remove_consecutive_prefixes_many_rounds(
            self.logical_lpm, 450000, scale_test_utils.BASE_IPV6_PREFIX, num_to_delete=450000, rounds=3)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_insert_remove_consecutive_1_5m_ipv4_many_rounds_shuffled(self):
        scale_test_utils.lpm_insert_remove_consecutive_prefixes_many_rounds(
            self.logical_lpm, 1500000, scale_test_utils.BASE_IPV4_PREFIX, num_to_delete=750000, rounds=3, shuffle=True)

    def disabled_test_insert_remove_consecutive_450k_ipv6_many_rounds_shuffled(self):
        scale_test_utils.lpm_insert_remove_consecutive_prefixes_many_rounds(
            self.logical_lpm, 450000, scale_test_utils.BASE_IPV6_PREFIX, num_to_delete=250000, rounds=3, shuffle=True)


if __name__ == '__main__':
    unittest.main()
