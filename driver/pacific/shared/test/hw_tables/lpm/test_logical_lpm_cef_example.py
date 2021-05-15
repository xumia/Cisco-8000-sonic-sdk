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
import unittest
import decor

FILENAME = "shared/test/hw_tables/lpm/inputs/customer_tables/raw/Telefonica_ipv4_table.txt.gz"
FORMAT = "CEF"


class test_logical_lpm_cef_example(logical_lpm_base):
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_actions_from_file(self):
        self.perform_test_file(FILENAME, FORMAT)


# if __name__ == '__main__':
#     unittest.main()
