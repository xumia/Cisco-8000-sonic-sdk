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
from ipv4_svi_routing_base import *

FIRST_SERDES2 = T.get_device_first_serdes(4)
LAST_SERDES2 = T.get_device_last_serdes(5)
RX_SYS_PORT_GID2 = 0x41
RX_L2_AC_PORT_GID2 = 0x213


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class test_ipv4_svi_routing(ipv4_svi_routing_base):

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

    def test_delete_vrf(self):
        self._test_delete_vrf()

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

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_sflow_pci(self):
        self._test_sflow(self.SNOOP_PACKET, is_ingress=True, is_pci=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_sflow(self):
        self._test_sflow(self.SNOOP_PACKET, is_ingress=True)

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

    def test_fhrp_macs(self):
        self._test_fhrp_macs()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_route_hsrp_v1_ipv4_vmac(self):
        self._test_route_hsrp_v1_ipv4_vmac()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_route_hsrp_v2_ipv4_vmac(self):
        self._test_route_hsrp_v2_ipv4_vmac()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_route_vrrp_ipv4_vmac(self):
        self._test_route_vrrp_ipv4_vmac()

    def setUp(self):
        super().setUp()

    def test_svi_create_destroy_create(self):

        # Destroy the existing rx_svi
        self.topology.rx_svi.destroy()
        self.topology.rx_svi = None

        # Add one more L2 AC port in rx_switch
        self.rx_eth_port2 = T.ethernet_port(self, self.device, T.RX_SLICE, T.RX_IFG1, RX_SYS_PORT_GID2, FIRST_SERDES2, LAST_SERDES2)
        self.rx_l2_ac_port2 = T.l2_ac_port(
            self,
            self.device,
            RX_L2_AC_PORT_GID2,
            None,
            self.topology.rx_switch,
            self.rx_eth_port2,
            T.RX_MAC,
            T.RX_L2_AC_PORT_VID1,
            T.RX_L2_AC_PORT_VID2)

        # Create rx_svi
        self.topology.rx_svi = T.svi_port(self, self.device, T.RX_SVI_GID, self.topology.rx_switch, self.topology.vrf, T.RX_SVI_MAC)

        # Destroy the rx_svi and try to create again
        self.topology.rx_svi.destroy()
        self.topology.rx_svi = None
        self.topology.rx_svi = T.svi_port(self, self.device, T.RX_SVI_GID, self.topology.rx_switch, self.topology.vrf, T.RX_SVI_MAC)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_with_host_spa(self):
        self._test_add_host_spa()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_change_nh_type(self):
        self._test_route_change_nh_type()


if __name__ == '__main__':
    unittest.main()
