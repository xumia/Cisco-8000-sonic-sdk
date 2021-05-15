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
from punt_inject_port_base import *
import unittest
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class punt_inject_port(punt_inject_port_base):

    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_inject_down(self):
        self._test_inject_down()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_inject_down_and_up(self):
        self._test_inject_down_and_up()

    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_inject_down_pci(self):
        self._test_inject_down_pci()

    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_inject_up(self):
        self._test_inject_up()

    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_inject_mcid(self):
        self._test_inject_mcid()

    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_inject_up_ipv6_nd(self):
        self._test_inject_up_ipv6_nd()

    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_inject_up_with_trailer(self):
        self._test_inject_up_with_trailer()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_punt_inject_creation(self):
        self._test_punt_inject_creation()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_punt_trap(self):
        self._test_punt_trap()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_punt_trap_fail(self):
        self._test_punt_trap_fail()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_snoop_ethernet(self):
        self._test_snoop_ethernet()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_snoop_ethernet_short(self):
        self._test_snoop_ethernet_short()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_snoop_ethernet_short_pci(self):
        self._test_snoop_ethernet_short_pci()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    # Incorrect Punt format used for punt ethertype static table lookup in P4
    # for asic4
    def test_traps_egress(self):
        self._test_traps_egress()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_traps_ethernet(self):
        self._test_traps_ethernet()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_traps_ethernet_pci(self):
        self._test_traps_ethernet_pci()

    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_traps_non_inject_up(self):
        self._test_traps_non_inject_up()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_no_route_to_sender_rpf_loose_nh(self):
        self._test_no_route_to_sender_rpf_loose_nh()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_punt_inject_counter(self):
        self._test_punt_inject_counter()


if __name__ == '__main__':
    unittest.main()
