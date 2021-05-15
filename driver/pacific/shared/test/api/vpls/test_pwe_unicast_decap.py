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
from pwe_unicast_decap_base import *
import sim_utils
import topology as T

# This test assumes that MPLS bottom-of-stack label is followed by Ether
bind_layers(MPLS, Ether, s=1)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class pwe_decap_unicast(pwe_decap_base):
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_unicast_attach(self):
        self._test_pwe_decap_attach()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_unicast_null_attach(self):
        self._test_pwe_decap_null_attach()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_unicast_detach(self):
        self._test_pwe_decap_detach()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_unicast_cw(self):
        self._test_pwe_decap_cw()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_unicast_flow_label(self):
        self._test_pwe_decap_flow_label()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_unicast_ac_vlan_pop_1(self):
        self._test_pwe_decap_ac_vlan_pop_1()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_unicast_ac_vlan_push_1(self):
        self._test_pwe_decap_ac_vlan_push_1()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_unicast_ac_translate_1_1(self):
        self._test_pwe_decap_ac_translate_1_1()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_unicast_cw_flow_label(self):
        self._test_pwe_decap_cw_flow_label()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_unicast_cw_punt(self):
        self._test_pwe_decap_cw_punt()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_unicast_null_drop_ttl_1(self):
        self._test_pwe_decap_null_drop_ttl_1()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_unicast_drop_ttl_1(self):
        self._test_pwe_decap_drop_ttl_1()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_2_pwe(self):
        self._test_pwe_2_pwe_attach()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_2_pwe_cw(self):
        self._test_pwe_2_pwe_cw()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_2_pwe_flow_label(self):
        self._test_pwe_2_pwe_flow_label()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_2_pwe_cw_flow_label(self):
        self._test_pwe_2_pwe_cw_flow_label()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_cw_2_pwe(self):
        self._test_pwe_cw_2_pwe()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_flow_lable_2_pwe(self):
        self._test_pwe_flow_lable_2_pwe()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_cw_flow_label_2_pwe(self):
        self._test_pwe_cw_flow_label_2_pwe()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_2_pwe_bgp_lu(self):
        self._test_pwe_2_pwe_bgp_lu()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_2_pwe_shg(self):
        self._test_pwe_2_pwe_shg()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_2_ac_shg(self):
        self._test_pwe_decap_shg()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_2_ac_single_counter(self):
        self.do_test_counter_pwe_2_ac(single_counter=True, prios=[0, 2])


if __name__ == '__main__':
    unittest.main()
