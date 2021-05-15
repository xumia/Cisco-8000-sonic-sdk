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

import decor
import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
import ip_test_base
import sim_utils
from sdk_test_case_base import *
from ip_routing_base import *
from ipv6_svi_routing_base import *


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class test_ipv6_svi_routing(ipv6_svi_routing_base):

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_add_host(self):
        self._test_add_host()

    def test_add_subnet(self):
        self._test_add_subnet()

    def test_add_host_wo_subnet(self):
        self._test_add_host_wo_subnet()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_default(self):
        self._test_route_default()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_destroy_route(self):
        self._test_destroy_route()

    def test_existing_entry(self):
        self._test_route_existing_entry()

    def test_get_host_route(self):
        self._test_get_host_route()

    def test_get_route(self):
        self._test_get_route()

    def test_get_subnets(self):
        self._test_get_subnets()

    def test_get_routing_entry(self):
        self._test_get_routing_entry()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_longer_prefix(self):
        self._test_route_longer_prefix()

    def test_longer_prefix_mtu(self):
        self._test_route_longer_prefix_mtu()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_modify_host(self):
        self._test_modify_host()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_modify_route(self):
        self._test_modify_route()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_sflow(self):
        self._test_sflow(self.SNOOP_PACKET, is_ingress=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_sflow_pci(self):
        self._test_sflow(self.SNOOP_PACKET, is_ingress=True, is_pci=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_sflow(self):
        self._test_sflow(self.SNOOP_PACKET, is_ingress=False)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_sflow_pci(self):
        self._test_sflow(self.SNOOP_PACKET, is_ingress=False, is_pci=True)

    @unittest.skip("NPL emits wrong destination LP")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_sflow_host(self):
        self._test_sflow(self.SNOOP_PACKET, is_ingress=False, is_host=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_sflow_add_remove_add(self):
        self._test_sflow_add_remove_add(self.SNOOP_PACKET, is_ingress=False, is_host=False)

    @unittest.skip("NPL emits wrong destination LP")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_sflow_add_remove_add_host(self):
        self._test_sflow_add_remove_add(self.SNOOP_PACKET, is_ingress=False, is_host=True)

    def test_no_default(self):
        self._test_route_no_default()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_set_active(self):
        self._test_route_set_active()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_remove_default_route(self):
        self._test_remove_default_route()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_single_fec(self):
        self._test_route_single_fec()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_single_nh(self):
        self._test_route_single_nh()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_update_mac(self):
        self._test_route_update_mac()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    # Egress SVI flood feature is not enabled on AR/GR/PL yet
    def test_update_nh_mac(self):
        self._test_route_update_nh_mac()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_update_nh(self):
        self._test_route_update_nh()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_with_vlan(self):
        self._test_route_with_vlan()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_move_host(self):
        self._test_move_host()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_move_route_single_nh(self):
        self._test_move_route_single_nh()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_change_mac(self):
        self._test_change_mac()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_change_vrf(self):
        self._test_change_vrf()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_route_hsrp_v2_ipv6_vmac(self):
        self._test_route_hsrp_v2_ipv6_vmac()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_route_vrrp_ipv6_vmac(self):
        self._test_route_vrrp_ipv6_vmac()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_with_host_spa(self):
        self._test_add_host_spa()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_change_nh_type(self):
        self._test_route_change_nh_type()


if __name__ == '__main__':
    unittest.main()
