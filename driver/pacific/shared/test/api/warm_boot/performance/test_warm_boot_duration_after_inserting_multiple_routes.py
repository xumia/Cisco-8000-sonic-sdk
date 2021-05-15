#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
from sdk_test_case_base import *
import warm_boot_test_utils as wb
import ip_test_base
import time
import decor


wb.support_warm_boot()


SA = T.mac_addr('be:ef:5d:35:7a:35')
DA = T.mac_addr('02:02:02:02:02:02')
SIP_V4 = T.ipv4_addr('12.10.12.10')
DIP_V4 = T.ipv4_addr('82.81.95.250')
SIP_V6 = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
DIP_V6 = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')
PREFIX_LEN = 24
TTL = 128
PRIVATE_DATA = 0x1234567890abcdef


# limits in seconds
if decor.is_hw_device():
    PY_OBJS_SAVE_AND_RESTORE_DURATION_LIMIT = 20
    SDK_DISCONNECT_AND_RECONNECT_DURATION_LIMIT = 25
else:
    PY_OBJS_SAVE_AND_RESTORE_DURATION_LIMIT = 5
    SDK_DISCONNECT_AND_RECONNECT_DURATION_LIMIT = 5


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
@unittest.skip("Needs further tuning, blacktips' timing is inconsistent")
@unittest.skipUnless(decor.is_hw_device(), "Run WB performance tests only on HW.")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip WB performance tests in auto-WB sanity.")
@unittest.skipUnless(decor.is_pacific() or decor.is_gibraltar(), "WB is currently supported by GB and PAC only")
class warm_boot_duration(sdk_test_case_base):
    def setUp(self):
        super().setUp()
        self.vrf = self.topology.vrf
        self.l3_dest = self.topology.nh_l3_ac_reg

    def insert_consecutive_ipv4_routes(self, first_route, prefix_len, num_of_routes):
        prefix = ip_test_base.ipv4_test_base.build_prefix(first_route, prefix_len)
        shift = 32 - prefix_len
        for _ in range(num_of_routes):
            ip_test_base.ipv4_test_base.add_route(self.vrf, prefix, self.l3_dest, PRIVATE_DATA)

            addr = prefix.addr.s_addr
            next_addr = (((addr >> shift) + 1) << shift) & ((1 << 32) - 1)
            prefix.addr.s_addr = next_addr

    def insert_consecutive_ipv6_routes(self, first_route, prefix_len, num_of_routes):
        prefix = ip_test_base.ipv6_test_base.build_prefix(first_route, prefix_len)
        shift = 128 - prefix_len
        for _ in range(num_of_routes):
            ip_test_base.ipv6_test_base.add_route(self.vrf, prefix, self.l3_dest, PRIVATE_DATA)

            q0 = sdk.get_ipv6_addr_q0(prefix.addr)
            q1 = sdk.get_ipv6_addr_q1(prefix.addr)
            addr = q1 << 64 | q0
            next_addr = (((addr >> shift) + 1) << shift) & ((1 << 128) - 1)
            next_q0 = next_addr & ((1 << 64) - 1)
            next_q1 = next_addr >> 64
            sdk.set_ipv6_addr(prefix.addr, next_q0, next_q1)

    def do_wb_and_measure_time(self):
        duration_stats = wb.WarmBootDurationStats()
        wb.warm_boot(self.device.device, duration_stats)

        # print duration stats
        print('\nSDK WB outage duration (s):')
        print(duration_stats.to_string())

        # check duration stats against predefined thresholds
        py_objs_save_and_restore_duration = duration_stats.save_py_objects_duration + duration_stats.restore_py_objects_duration
        self.assertLess(py_objs_save_and_restore_duration, PY_OBJS_SAVE_AND_RESTORE_DURATION_LIMIT)
        sdk_disconnect_and_reconnect_duration = duration_stats.sdk_disconnect_duration + duration_stats.sdk_reconnect_duration
        self.assertLess(sdk_disconnect_and_reconnect_duration, SDK_DISCONNECT_AND_RECONNECT_DURATION_LIMIT)

    def test_wb_duration_1k_ipv4_routes(self):
        self.insert_consecutive_ipv4_routes(DIP_V4, PREFIX_LEN, 1_000)
        self.do_wb_and_measure_time()

    def test_wb_duration_10k_ipv4_routes(self):
        self.insert_consecutive_ipv4_routes(DIP_V4, PREFIX_LEN, 10_000)
        self.do_wb_and_measure_time()

    def test_wb_duration_100k_ipv4_routes(self):
        self.insert_consecutive_ipv4_routes(DIP_V4, PREFIX_LEN, 100_000)
        self.do_wb_and_measure_time()

    def test_wb_duration_1k_ipv6_routes(self):
        self.insert_consecutive_ipv6_routes(DIP_V6, PREFIX_LEN, 1_000)
        self.do_wb_and_measure_time()

    def test_wb_duration_10k_ipv6_routes(self):
        self.insert_consecutive_ipv6_routes(DIP_V6, PREFIX_LEN, 10_000)
        self.do_wb_and_measure_time()

    def test_wb_duration_100k_ipv6_routes(self):
        self.insert_consecutive_ipv6_routes(DIP_V6, PREFIX_LEN, 100_000)
        self.do_wb_and_measure_time()


if __name__ == '__main__':
    unittest.main()
