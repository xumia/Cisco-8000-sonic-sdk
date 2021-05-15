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
import packet_test_utils as U
from scapy.all import *
from pwe_encap_base import *
import sim_utils
import topology as T

# This test assumes that MPLS bottom-of-stack label is followed by Ether
bind_layers(MPLS, Ether, s=1)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_pwe_encap_p2p(pwe_encap_base):
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_encap_p2p_attach(self):
        self._test_pwe_encap_p2p_attach()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_encap_p2p_detach(self):
        self._test_pwe_encap_p2p_detach()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_encap_p2p_change_l3_dest(self):
        self._test_pwe_encap_p2p_change_l3_dest()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_encap_p2p_cw(self):
        self._test_pwe_encap_p2p_cw()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_pwe_encap_p2p_flow_label(self):
        self._test_pwe_encap_p2p_flow_label()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_pwe_encap_p2p_cw_flow_label(self):
        self._test_pwe_encap_p2p_cw_flow_label()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_encap_p2p_bgp_lu(self):
        self._test_pwe_encap_p2p_bgp_lu()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_encap_p2p_bgp_ecmp(self):
        self._test_pwe_encap_p2p_bgp_ecmp()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_encap_p2p_tenh(self):
        self._test_pwe_encap_p2p_tenh()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_encap_p2p_ldp_tenh(self):
        self._test_pwe_encap_p2p_ldp_tenh()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_encap_p2p_ac_vlan_pop_1(self):
        self._test_pwe_encap_p2p_ac_vlan_pop_1()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_encap_p2p_ac_vlan_push_1(self):
        self._test_pwe_encap_p2p_ac_vlan_push_1()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(not decor.is_hw_device(), "Not supported on NSIM until NPSUITE support")
    def test_pwe_encap_p2p_ac_translate_1_1(self):
        self._test_pwe_encap_p2p_ac_translate_1_1()


if __name__ == '__main__':
    unittest.main()
