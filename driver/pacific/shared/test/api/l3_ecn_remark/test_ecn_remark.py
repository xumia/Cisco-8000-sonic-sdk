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

import ecn_remark_base
import sys
import unittest
from leaba import sdk
import ip_test_base
import packet_test_utils as U
import scapy.all as S
import sim_utils
import decor

import topology as T


@unittest.skipIf(decor.is_hw_device(), 'Test group not applicable to HW device. Simulated congestion.')
class ipv4_l3_ac_ecn_remark_test(
        ecn_remark_base.ipv4_test,
        ecn_remark_base.l3_ac_test,
        ecn_remark_base.ecn_remark_test):
    pass


@unittest.skipIf(decor.is_hw_device(), 'Test group not applicable to HW device. Simulated congestion.')
class ipv4_svi_ecn_remark_test(
        ecn_remark_base.ipv4_test,
        ecn_remark_base.svi_test,
        ecn_remark_base.ecn_remark_test):
    pass


@unittest.skipIf(decor.is_hw_device(), 'Test group not applicable to HW device. Simulated congestion.')
class ipv6_l3_ac_ecn_remark_test(
        ecn_remark_base.ipv6_test,
        ecn_remark_base.l3_ac_test,
        ecn_remark_base.ecn_remark_test):
    pass


@unittest.skipIf(decor.is_hw_device(), 'Test group not applicable to HW device. Simulated congestion.')
class ipv6_svi_ecn_remark_test(
        ecn_remark_base.ipv6_test,
        ecn_remark_base.svi_test,
        ecn_remark_base.ecn_remark_test):
    pass


if __name__ == '__main__':
    unittest.main()
