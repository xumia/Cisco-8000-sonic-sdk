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

import unittest
from sdk_test_case_base import *
from gue_base import *
from l3_ac_gue_base import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class test_l3_ac_gue(l3_ac_gue_base):
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gue_decap(self):
        self._test_gue_decap()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gue_decap_transit_counter_no_increment(self):
        self._test_gue_decap_transit_counter_no_increment()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gue_decap_v6(self):
        self._test_gue_decap_v6()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gue_any_src_tunnel_decap(self):
        self._test_gue_any_src_tunnel_decap()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gue_update_overlay_vrf(self):
        self._test_gue_update_overlay_vrf()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gue_update_underlay_vrf(self):
        self._test_gue_update_underlay_vrf()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gue_update_remote_ip_addr(self):
        self._test_gue_update_remote_ip_addr()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gue_update_local_ip_addr(self):
        self._test_gue_update_local_ip_addr()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gue_ttl_qos_uniform(self):
        self._test_gue_ttl_qos_uniform()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gue_decap_acl_outer_header(self):
        self._test_gue_decap_acl_outer_header()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gue_duplicates(self):
        self._test_gue_duplicates()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gue_tunnel_decap_mtu(self):
        self._test_gue_decap_mtu()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gue_ttl_qos_uniform_mtu(self):
        self._test_gue_ttl_qos_uniform_mtu()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gue_decap_mpls_swap(self):
        self._test_gue_decap_mpls_swap()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gue_decap_mpls_encap(self):
        self._test_gue_decap_mpls_encap()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gue_decap_mpls_decap(self):
        self._test_gue_decap_mpls_decap()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gue_decap_mpls_swap_v6(self):
        self._test_gue_decap_mpls_swap_v6()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gue_decap_mpls_encap_v6(self):
        self._test_gue_decap_mpls_encap_v6()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gue_decap_mpls_decap_v6(self):
        self._test_gue_decap_mpls_decap_v6()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gue_decap_ecmp(self):
        self._test_gue_decap_ecmp()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gue_decap_mpls_ecmp(self):
        self._test_gue_decap_mpls_ecmp()


if __name__ == '__main__':
    unittest.main()
