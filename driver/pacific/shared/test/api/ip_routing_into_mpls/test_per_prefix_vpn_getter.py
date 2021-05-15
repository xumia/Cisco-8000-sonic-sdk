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

from leaba import sdk
import unittest
import packet_test_utils as U
import scapy.all as S
import topology as T
from per_prefix_vpn_base import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_per_prefix_vpn_getter(per_prefix_vpn_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_per_prefix_vpn_getter(self):
        self.setup_multi_pe_single_path()
        self._test_per_prefix_vpn_getter()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_per_prefix_vpn_getter_bgp_lu(self):
        self.setup_multi_pe_single_path_bgp_lu()
        self._test_per_prefix_vpn_getter_bgp_lu()


if __name__ == '__main__':
    unittest.main()
