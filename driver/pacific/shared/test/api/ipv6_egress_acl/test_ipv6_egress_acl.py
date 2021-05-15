#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import decor
import unittest
from leaba import sdk
import sim_utils
import ip_test_base
from packet_test_utils import *
from ipv6_egress_acl_base import *
from scapy.all import *
import topology as T


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_ipv6_egress_acl(ipv6_egress_acl_base):

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_drop_acl(self):
        self._test_drop_acl()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_drop_acl_svi(self):
        self._test_drop_acl(True)

    @unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_multislice_acl(self):
        self._test_multislice_acl()

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_nop_acl(self):
        self._test_nop_acl()

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_route_default_and_acl(self):
        self._test_route_default_and_acl()

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_route_default_delete_acl(self):
        self._test_route_default_delete_acl()

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_route_default_delete_all_acl(self):
        self._test_route_default_delete_all_acl()

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_two_acls(self):
        self._test_two_acls()

    @unittest.skip('TCP flags are not part of default IPv6 key')  # MERGE HELP!!!!
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic5(), "RTF is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "RTF is not yet enabled on PL")
    def test_tcp_flags(self):
        self._test_tcp_flags_ace()


if __name__ == '__main__':
    unittest.main()
