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


class test_ipv4_l3_ac_ip_over_ip_tunnel(ipv4_l3_ac_ip_over_ip_tunnel_base):

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_ip_over_ip_tunnel_decap(self):
        self._test_ip_over_ip_tunnel_decap()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_ip_over_ip_any_src_tunnel_decap(self):
        self._test_ip_over_ip_any_src_tunnel_decap()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_ip_over_ip_tunnel_update_overlay_vrf(self):
        self._test_ip_over_ip_tunnel_update_overlay_vrf()

    def test_ip_over_ip_tunnel_update_underlay_vrf(self):
        self._test_ip_over_ip_tunnel_update_underlay_vrf()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_ip_over_ip_tunnel_update_remote_ip_addr(self):
        self._test_ip_over_ip_tunnel_update_remote_ip_addr()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_ip_over_ip_tunnel_update_local_ip_addr(self):
        self._test_ip_over_ip_tunnel_update_local_ip_addr()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_ip_over_ip_tunnel_ttl_qos_uniform(self):
        self._test_ip_over_ip_tunnel_ttl_qos_uniform()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ip_over_ip_tunnel_decap_acl_outer_header(self):
        self._test_ip_over_ip_tunnel_decap_acl_outer_header()

    def test_ip_over_ip_tunnel_duplicates(self):
        self._test_ip_over_ip_tunnel_duplicates()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_ip_over_ip_tunnel_decap_ecmp(self):
        self._test_ip_over_ip_tunnel_decap_ecmp()


if __name__ == '__main__':
    unittest.main()
