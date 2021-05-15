#!/usr/bin/env python3
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

import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
import ip_test_base
import sim_utils
from sdk_test_case_base import *
from ip_over_ip_tunnel_base import *
from ipv4_l3_ac_ip_over_ip_tunnel_base import *
import decor


class test_ipv4_l3_ac_ip_over_ip_tunnel_mtu(ipv4_l3_ac_ip_over_ip_tunnel_base):

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_ip_over_ip_tunnel_decap_mtu(self):
        self._test_ip_over_ip_tunnel_decap_mtu()

    def test_ip_over_ip_tunnel_ttl_qos_uniform_mtu(self):
        self._test_ip_over_ip_tunnel_ttl_qos_uniform_mtu()


if __name__ == '__main__':
    unittest.main()
