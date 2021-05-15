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

from ipv4_l3_ac_erspan_base import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_2acls(ipv4_l3_ac_erspan_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_2acls_1(self):
        self._test_2acls_1()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_2acls_2(self):
        self._test_2acls_2()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_2acls_3(self):
        self._test_2acls_3()


if __name__ == '__main__':
    unittest.main()
