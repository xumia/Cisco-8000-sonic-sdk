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
import decor
from sdk_test_case_base import *
from ipv4_l3_ac_routing_base import *


PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
PUNT_VLAN = 0xA13
MIRROR_CMD_GID = 9
PUNT_SLICE = 2  # must be even numbered slice
PUNT_IFG = 0
PUNT_PIF_FIRST = 8
PUNT_PIF_LAST = PUNT_PIF_FIRST
PUNT_SP_GID = SYS_PORT_GID_BASE + 3


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_ipv4_l3_ac_routing_disable(ipv4_l3_ac_routing_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_add_host_disable_rx(self):
        self._test_add_host(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_add_host_disable_tx(self):
        self._test_add_host(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_change_mac_disable_rx(self):
        self._test_change_mac(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_change_mac_disable_tx(self):
        self._test_change_mac(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_change_vrf_disable_rx(self):
        self._test_change_vrf(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_change_vrf_disable_tx(self):
        self._test_change_vrf(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l3_ac_tag_change_vlan_disable_rx(self):
        self._test_l3_ac_tag_change_vlan(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l3_ac_tag_change_vlan_disable_tx(self):
        self._test_l3_ac_tag_change_vlan(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_active_disable_tx(self):
        self._test_route_set_active(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_active_disable_rx(self):
        self._test_route_set_active(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_single_fec_disable_rx(self):
        self._test_route_single_fec(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_single_fec_disable_tx(self):
        self._test_route_single_fec(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_single_nh_disable_rx(self):
        self._test_route_single_nh(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_single_nh_disable_tx(self):
        self._test_route_single_nh(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_default_disable_rx(self):
        self._test_route_default(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_default_disable_tx(self):
        self._test_route_default(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_destroy_route_disable_rx(self):
        self._test_destroy_route(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_destroy_route_disable_tx(self):
        self._test_destroy_route(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l3_ac_tag_tag_change_vlan_disable_rx(self):
        self._test_l3_ac_tag_tag_change_vlan(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l3_ac_tag_tag_change_vlan_disable_tx(self):
        self._test_l3_ac_tag_tag_change_vlan(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_longer_prefix_disable_rx(self):
        self._test_route_longer_prefix(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_longer_prefix_disable_tx(self):
        self._test_route_longer_prefix(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_modify_host_disable_rx(self):
        self._test_modify_host(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_modify_host_disable_tx(self):
        self._test_modify_host(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_update_mac_disable_rx(self):
        self._test_route_update_mac(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_update_mac_disable_tx(self):
        self._test_route_update_mac(disable_tx=True)


if __name__ == '__main__':
    unittest.main()
