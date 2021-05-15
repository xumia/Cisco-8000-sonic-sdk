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

import unittest
import decor
from max_power_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipUnless(decor.is_hw_device(), "Requires HW device")
class max_power(max_power_base):
    @unittest.skipUnless(decor.is_pacific(), "Requires Pacific device")
    def test_ipv4_traffic(self):
        self.params = {
            'json_mix': None,
            'hbm': False,
            'cache': False,
            'nflows': 1,
            'packet_sizes': [
                348,
                348],
            'device_frequency_khz': None}
        self.run_ipv4_traffic()

    @unittest.skipUnless(decor.is_gibraltar(), "Requires GB device")
    def test_ipv6_traffic(self):
        self.params = {
            'json_mix': None,
            'hbm': False,
            'cache': False,
            'nflows': 1,
            'packet_sizes': [
                220,
                156],
            'device_frequency_khz': None}
        self.run_ipv6_traffic()

    @unittest.skip("Disabled for maxpower")
    def test_l2_traffic(self):
        self.params = {
            'json_mix': None,
            'hbm': False,
            'cache': False,
            'nflows': 1,
            'packet_sizes': [
                348,
                348],
            'device_frequency_khz': None}
        self.run_l2_traffic()

    @unittest.skip("Disabled for maxpower")
    def test_empty_flow(self):
        self.params = {
            'json_mix': None,
            'hbm': False,
            'cache': False,
            'nflows': 1,
            'packet_sizes': [
                348,
                348],
            'device_frequency_khz': None}
        self.run_empty_flow()


if __name__ == '__main__':
    unittest.main()
