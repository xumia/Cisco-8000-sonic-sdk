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
class test_gre_ipv4_encap_only(gre_ipv4_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_encap(self):
        self.gre_port_single_underlay_path(sdk.la_ip_tunnel_mode_e_ENCAP_ONLY)
        self._test_gre_port_single_underlay_path()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_encap_ecmp(self):
        self.gre_port_multi_underlay_path(sdk.la_ip_tunnel_mode_e_ENCAP_ONLY)
        self._test_gre_port_multi_underlay_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_gre_encap_qos1(self):
        self.gre_port_single_underlay_path(sdk.la_ip_tunnel_mode_e_ENCAP_ONLY)
        self._test_gre_encap_qos()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_gre_encap_qos2(self):
        self.gre_port_single_underlay_path(sdk.la_ip_tunnel_mode_e_ENCAP_ONLY)
        self._test_gre_encap_qos2()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_gre_encap_tunnel_qos(self):
        self.gre_port_single_underlay_path(sdk.la_ip_tunnel_mode_e_ENCAP_ONLY)
        self._test_gre_encap_tunnel_qos()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_gre_padding(self):
        self.gre_port_single_underlay_path(sdk.la_ip_tunnel_mode_e_ENCAP_ONLY)
        self._test_gre_port_single_underlay_path_verify_padding()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_encap_ecmp_mtu(self):
        self.gre_port_multi_underlay_path(sdk.la_ip_tunnel_mode_e_ENCAP_ONLY)
        self._test_gre_port_multi_underlay_path_mtu()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_encap_abf(self):
        self.gre_port_multi_underlay_path(sdk.la_ip_tunnel_mode_e_ENCAP_ONLY)
        self._test_gre_port_encap_abf()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_encap_dip_entropy_prefix_lengths(self):
        self.gre_port_single_underlay_path(sdk.la_ip_tunnel_mode_e_ENCAP_ONLY)
        self._test_gre_encap_dip_entropy_prefix_lengths()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_encap_dip_entropy_forwarding(self):
        self.gre_port_single_underlay_path(sdk.la_ip_tunnel_mode_e_ENCAP_ONLY)
        self._test_gre_encap_dip_entropy_forwarding()


if __name__ == '__main__':
    unittest.main()
