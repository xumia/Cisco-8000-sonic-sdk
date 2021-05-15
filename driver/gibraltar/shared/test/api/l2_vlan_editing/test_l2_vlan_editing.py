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
from packet_test_utils import *
import sim_utils
from scapy.all import *
from l2_vlan_editing_base import *
from leaba import sdk
import unittest
import topology as T


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class test_l2_vlan_editing(l2_vlan_editing_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_nop(self):
        self._test_nop()

    def test_pop1(self):
        self._test_pop1()

    def test_pop2(self):
        self._test_pop2()

    def test_push1(self):
        self._test_push1()

    def test_push2(self):
        self._test_push2()

    def test_push2_mtu(self):
        self._test_push2_mtu()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_tag1_pop2(self):
        self._test_tag1_pop2()

    def test_translate_any_1(self):
        self._test_translate_any_1()

    @unittest.skipIf(decor.is_asic5(), "Test is failing on AR")
    def test_translate_many_1(self):
        self._test_translate_many_1()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_many_1_with_spa(self):
        self._test_translate_many_1_with_spa()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_1_1(self):
        self._test_translate_1_1()

    def test_translate_1_2(self):
        self._test_translate_1_2()

    @unittest.skipUnless(decor.is_hw_device(), "Not supported on NSIM until NPSUITE support")
    def test_translate_2_1(self):
        self._test_translate_2_1()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_2_2(self):
        self._test_translate_2_2()

    def test_nop_ive(self):
        self._test_nop_ive()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop1_ive(self):
        self._test_pop1_ive()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop2_ive(self):
        self._test_pop2_ive()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_push1_ive(self):
        self._test_push1_ive()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_push2_ive(self):
        self._test_push2_ive()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_1_1_ive(self):
        self._test_translate_1_1_ive()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_1_2_ive(self):
        self._test_translate_1_2_ive()

    @unittest.skipUnless(decor.is_hw_device(), "Not supported on NSIM until NPSUITE support")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_2_1_ive(self):
        self._test_translate_2_1_ive()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_2_2_ive(self):
        self._test_translate_2_2_ive()

    def test_vlan_table_overflow(self):
        self._test_vlan_table_overflow()

    def test_access_to_trunk(self):
        self._test_access_to_trunk()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_port_default_pcpdei(self):
        self._test_port_default_pcpdei()


if __name__ == '__main__':
    unittest.main()
