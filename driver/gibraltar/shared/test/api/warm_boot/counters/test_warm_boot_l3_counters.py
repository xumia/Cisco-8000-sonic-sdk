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


import decor
import unittest
from leaba import sdk
import sim_utils
import packet_test_utils as U
import scapy.all as S
import topology as T
import warm_boot_counters_base
import warm_boot_test_utils as wb


wb.support_warm_boot()


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip in auto-WB sanity")
@unittest.skipUnless(decor.is_pacific() or decor.is_gibraltar(), "WB is currently supported by GB and PAC only")
class warm_boot_ipv4_svi_counters_test(warm_boot_counters_base.warm_boot_ipv4_svi_counters_base):

    def test_warm_boot_ipv4_svi_counters(self):
        self.do_warm_boot_l3_counters_test()

    def test_warm_boot_ipv4_svi_counters_sdk_down_kernel_module_up(self):
        self.do_warm_boot_l3_counters_test_sdk_down_kernel_module_up()


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip in auto-WB sanity")
@unittest.skipUnless(decor.is_pacific() or decor.is_gibraltar(), "WB is currently supported by GB and PAC only")
class warm_boot_ipv4_ac_counters_test(warm_boot_counters_base.warm_boot_ipv4_ac_counters_base):

    def test_warm_boot_ipv4_ac_counters(self):
        self.do_warm_boot_l3_counters_test()

    def test_warm_boot_ipv4_ac_counters_sdk_down_kernel_module_up(self):
        self.do_warm_boot_l3_counters_test_sdk_down_kernel_module_up()


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip in auto-WB sanity")
@unittest.skipUnless(decor.is_pacific() or decor.is_gibraltar(), "WB is currently supported by GB and PAC only")
class warm_boot_ipv6_svi_counters_test(warm_boot_counters_base.warm_boot_ipv6_svi_counters_base):

    def test_warm_boot_ipv6_svi_counters(self):
        self.do_warm_boot_l3_counters_test()

    def test_warm_boot_ipv6_svi_counters_sdk_down_kernel_module_up(self):
        self.do_warm_boot_l3_counters_test_sdk_down_kernel_module_up()


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip in auto-WB sanity")
@unittest.skipUnless(decor.is_pacific() or decor.is_gibraltar(), "WB is currently supported by GB and PAC only")
class warm_boot_ipv6_ac_counters_test(warm_boot_counters_base.warm_boot_ipv6_ac_counters_base):

    def test_warm_boot_ipv6_ac_counters(self):
        self.do_warm_boot_l3_counters_test()

    def test_warm_boot_ipv6_ac_counters_sdk_down_kernel_module_up(self):
        self.do_warm_boot_l3_counters_test_sdk_down_kernel_module_up()


if __name__ == '__main__':
    unittest.main()
