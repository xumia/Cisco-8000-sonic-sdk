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
import mtu.mtu_test_utils as MTU
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_ipv4_l3_ac_erspan(ipv4_l3_ac_erspan_base):

    def test_erspan_without_acl(self):
        self._test_erspan_without_acl()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_l3_erspan_without_acl(self):
        self._test_l3_erspan_without_acl()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mirroring_with_acl(self):
        self._test_mirroring_with_acl()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    def test_multicast_erspan(self):
        self._test_ip_multicast_erspan()


if __name__ == '__main__':
    unittest.main()
