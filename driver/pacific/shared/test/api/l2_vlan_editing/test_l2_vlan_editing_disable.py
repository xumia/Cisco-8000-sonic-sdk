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
class test_l2_vlan_editing(l2_vlan_editing_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_nop_disable_rx(self):
        self._test_nop(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_nop_disable_tx(self):
        self._test_nop(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop1_disable_rx(self):
        self._test_pop1(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop1_disable_tx(self):
        self._test_pop1(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop2_disable_rx(self):
        self._test_pop2(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop2_disable_tx(self):
        self._test_pop2(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_push1_disable_rx(self):
        self._test_push1(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_push1_disable_tx(self):
        self._test_push1(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_push2_disable_rx(self):
        self._test_push2(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_push2_disable_tx(self):
        self._test_push2(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_1_1_disable_rx(self):
        self._test_translate_1_1(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_1_1_disable_tx(self):
        self._test_translate_1_1(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_1_2_disable_rx(self):
        self._test_translate_1_2(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_1_2_disable_tx(self):
        self._test_translate_1_2(disable_tx=True)

    @unittest.skipUnless(decor.is_hw_device(), "Not supported on NSIM until NPSUITE support")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_2_1_disable_rx(self):
        self._test_translate_2_1(disable_rx=True)

    @unittest.skipUnless(decor.is_hw_device(), "Not supported on NSIM until NPSUITE support")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_2_1_disable_tx(self):
        self._test_translate_2_1(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_2_2_disable_rx(self):
        self._test_translate_2_2(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_2_2_disable_tx(self):
        self._test_translate_2_2(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_nop_ive_disable_rx(self):
        self._test_nop_ive(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_nop_ive_disable_tx(self):
        self._test_nop_ive(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop1_ive_disable_rx(self):
        self._test_pop1_ive(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop1_ive_disable_tx(self):
        self._test_pop1_ive(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop2_ive_disable_rx(self):
        self._test_pop2_ive(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop2_ive_disable_tx(self):
        self._test_pop2_ive(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_push1_ive_disable_rx(self):
        self._test_push1_ive(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_push1_ive_disable_tx(self):
        self._test_push1_ive(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_push2_ive_disable_rx(self):
        self._test_push2_ive(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_push2_ive_disable_tx(self):
        self._test_push2_ive(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_1_1_ive_disable_rx(self):
        self._test_translate_1_1_ive(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_1_1_ive_disable_tx(self):
        self._test_translate_1_1_ive(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_1_2_ive_disable_rx(self):
        self._test_translate_1_2_ive(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_1_2_ive_disable_tx(self):
        self._test_translate_1_2_ive(disable_tx=True)

    @unittest.skipUnless(decor.is_hw_device(), "Not supported on NSIM until NPSUITE support")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_2_1_ive_disable_rx(self):
        self._test_translate_2_1_ive(disable_rx=True)

    @unittest.skipUnless(decor.is_hw_device(), "Not supported on NSIM until NPSUITE support")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_2_1_ive_disable_tx(self):
        self._test_translate_2_1_ive(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_2_2_ive_disable_rx(self):
        self._test_translate_2_2_ive(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_translate_2_2_ive_disable_tx(self):
        self._test_translate_2_2_ive(disable_tx=True)


if __name__ == '__main__':
    unittest.main()
