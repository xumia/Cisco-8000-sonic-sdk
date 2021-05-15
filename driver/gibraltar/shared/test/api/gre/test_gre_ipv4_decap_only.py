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
import decor
import topology as T
import packet_test_defs as P
import ip_test_base
from sdk_test_case_base import *
import mtu.mtu_test_utils as MTU
from sdk_test_case_base import *
from gre_base import *
from gre.gre_ipv4_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_gre_ipv4_decap_only(gre_ipv4_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap(self):
        self.gre_port_single_underlay_path(sdk.la_ip_tunnel_mode_e_DECAP_ONLY)
        self._test_gre_port_decap()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_ttl(self):
        self.gre_port_single_underlay_path(sdk.la_ip_tunnel_mode_e_DECAP_ONLY)
        self._test_gre_port_decap_ttl()

    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_port_decap_p2mp_termination(self):
        self.gre_port_single_underlay_path(sdk.la_ip_tunnel_mode_e_DECAP_ONLY)
        self._test_gre_port_decap_p2mp_termination()

    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_port_decap_termination_negative(self):
        self.gre_port_single_underlay_path(sdk.la_ip_tunnel_mode_e_DECAP_ONLY)
        self._test_gre_port_decap_termination_negative(sdk.la_ip_tunnel_mode_e_DECAP_ONLY)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_acl_outer_header(self):
        self.gre_port_single_underlay_path(sdk.la_ip_tunnel_mode_e_DECAP_ONLY)
        self._test_gre_port_decap_acl_outer_header()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_qos(self):
        self.gre_port_single_underlay_path(sdk.la_ip_tunnel_mode_e_DECAP_ONLY)
        self._test_gre_port_decap_qos()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_qos2(self):
        self.gre_port_single_underlay_path(sdk.la_ip_tunnel_mode_e_DECAP_ONLY)
        self._test_gre_port_decap_qos2()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mtu(self):
        self.gre_port_single_underlay_path(sdk.la_ip_tunnel_mode_e_DECAP_ONLY)
        self._test_gre_port_decap_mtu()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_unsupported_protocol(self):
        self.gre_port_multi_underlay_path(sdk.la_ip_tunnel_mode_e_DECAP_ONLY)
        self._test_gre_unsupported_protocol_decap()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_lpts(self):
        self.gre_port_single_underlay_path(sdk.la_ip_tunnel_mode_e_DECAP_ONLY)
        self._test_gre_port_decap_lpts()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_miss(self):
        self.gre_port_single_underlay_path(sdk.la_ip_tunnel_mode_e_DECAP_ONLY)
        self._test_gre_port_decap_miss()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_ecmp(self):
        self.gre_port_multi_underlay_path_ecmp(sdk.la_ip_tunnel_mode_e_DECAP_ONLY)
        self._test_gre_port_decap_ecmp(sdk.la_l3_protocol_e_IPV4_UC)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_scale(self):
        self._test_gre_decap_scale()


if __name__ == '__main__':
    unittest.main()
