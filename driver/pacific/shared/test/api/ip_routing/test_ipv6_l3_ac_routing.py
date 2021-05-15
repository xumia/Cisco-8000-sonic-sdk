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
import topology as T
import ip_test_base
import decor
from sdk_test_case_base import *
from ip_routing_base import *
from ipv6_l3_ac_routing_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class test_ipv6_l3_ac_routing(ipv6_l3_ac_routing_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_add_host(self):
        self._test_add_host()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_add_host_wo_subnet(self):
        self._test_add_host_wo_subnet()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_add_subnet(self):
        self._test_add_subnet()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_change_mac(self):
        self._test_change_mac()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_change_vrf(self):
        self._test_change_vrf()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_default(self):
        self._test_route_default()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_destroy_route(self):
        self._test_destroy_route()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_hosts(self):
        self._test_get_hosts()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_route(self):
        self._test_get_route()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_routing_entry(self):
        self._test_get_routing_entry()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_subnets(self):
        self._test_get_subnets()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l3_ac_illegal_dip(self):
        self._test_illegal_dip('0000:0000:0000:0000:0000:0000:0000:0000')

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_longer_prefix(self):
        self._test_route_longer_prefix()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_longer_prefix_mtu(self):
        self._test_route_longer_prefix_mtu()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_modify_host(self):
        self._test_modify_host()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_no_default(self):
        self._test_route_no_default()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_active(self):
        self._test_route_set_active()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_single_fec(self):
        self._test_route_single_fec()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_single_nh(self):
        self._test_route_single_nh()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_remove_default_route(self):
        self._test_remove_default_route()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_update_mac(self):
        self._test_route_update_mac()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_update_nh(self):
        self._test_route_update_nh()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_with_vlan(self):
        self._test_route_with_vlan()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l3_ac_tag_tag_change_vlan(self):
        self._test_l3_ac_tag_tag_change_vlan()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l3_ac_tag_tag_change_vlan_mtu(self):
        self._test_l3_ac_tag_tag_change_vlan_mtu()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - NP2 compound")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l3_ac_tag_tag_with_fallback_change_vlan(self):
        self._test_l3_ac_tag_tag_with_fallback_change_vlan()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l3_ac_tag_change_vlan(self):
        self._test_l3_ac_tag_change_vlan()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_modify_route(self):
        self._test_modify_route()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_sflow_pci(self):
        self._test_sflow(self.SNOOP_PACKET, is_ingress=True, is_pci=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_sflow(self):
        self._test_sflow(self.SNOOP_PACKET, is_ingress=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_sflow(self):
        self._test_sflow(self.SNOOP_PACKET, is_ingress=False)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_sflow_pci(self):
        self._test_sflow(self.SNOOP_PACKET, is_ingress=False, is_pci=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_sflow_host(self):
        snoop_packet_copy = deepcopy(self.SNOOP_PACKET)
        snoop_packet_copy[Punt].destination_lp = 0  # No DLP info for directly attached host
        self._test_sflow(snoop_packet_copy, is_ingress=False, is_host=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_sflow_add_remove_add(self):
        self._test_sflow_add_remove_add(self.SNOOP_PACKET, is_ingress=False, is_host=False)

    @unittest.skip("NPL emits wrong destination LP")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_sflow_add_remove_add_host(self):
        snoop_packet_copy = deepcopy(self.SNOOP_PACKET)
        snoop_packet_copy[Punt].destination_lp = 0  # No DLP info for directly attached host
        self._test_sflow_add_remove_add(snoop_packet_copy, is_ingress=False, is_host=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_existing_entry(self):
        self._test_route_existing_entry()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_host_route(self):
        self._test_get_host_route()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv6_routing_128_bit_prefix(self):
        self.destroy_default_route()

        prefix = self.ip_impl.build_prefix(self.DIP, length=128)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.topology.nh_l3_ac_reg, ip_routing_base.PRIVATE_DATA, False)

        # Test to ensure double-add not possible
        with self.assertRaises(sdk.ExistException):
            self.ip_impl.add_route(self.topology.vrf, prefix, self.topology.nh_l3_ac_reg, ip_routing_base.PRIVATE_DATA, True)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.ip_impl.modify_route(self.topology.vrf, prefix, self.topology.nh_l3_ac_ext)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_EXTRA_OUTPUT_PACKET, T.TX_SLICE_EXT,
                          T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        self.ip_impl.add_route(self.topology.vrf, prefix, self.topology.nh_l3_ac_reg, ip_routing_base.PRIVATE_DATA, True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        # Test to ensure double-add not possible
        with self.assertRaises(sdk.ExistException):
            self.ip_impl.add_route(self.topology.vrf, prefix, self.topology.nh_l3_ac_reg, ip_routing_base.PRIVATE_DATA, False)

        self.ip_impl.modify_route(self.topology.vrf, prefix, self.topology.nh_l3_ac_ext)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_EXTRA_OUTPUT_PACKET, T.TX_SLICE_EXT,
                          T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv6_routing_120_bit_prefix(self):
        self.destroy_default_route()

        prefix = self.ip_impl.build_prefix(self.DIP, length=120)

        self.ip_impl.add_route(self.topology.vrf, prefix, self.topology.nh_l3_ac_reg, ip_routing_base.PRIVATE_DATA, False)

        # Test to ensure double-add not possible
        with self.assertRaises(sdk.ExistException):
            self.ip_impl.add_route(self.topology.vrf, prefix, self.topology.nh_l3_ac_reg, ip_routing_base.PRIVATE_DATA, True)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.ip_impl.modify_route(self.topology.vrf, prefix, self.topology.nh_l3_ac_ext)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_EXTRA_OUTPUT_PACKET, T.TX_SLICE_EXT,
                          T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    # Bulk command

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_longer_prefix_bulk(self):
        self._test_route_longer_prefix_bulk()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_interface_prefix_bulk(self):
        self._test_route_interface_prefix_bulk()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_add_prefix_fec_dependancy_bulk(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self._test_add_prefix_fec_dependancy_bulk(prefix)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_modify_prefix_fec_dependancy_bulk(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self._test_modify_prefix_fec_dependancy_bulk(prefix)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_add_def_prefix_fec_dependancy_bulk(self):
        def_prefix = self.ip_impl.get_default_prefix()
        self._test_add_prefix_fec_dependancy_bulk(def_prefix)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_modify_def_prefix_fec_dependancy_bulk(self):
        def_prefix = self.ip_impl.get_default_prefix()
        self._test_modify_prefix_fec_dependancy_bulk(def_prefix)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - NP2 compound")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_128_bit_prefix_bulk(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=128)
        self._test_route_max_length_prefix_bulk(prefix)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_add_same_prefix_bulk(self):
        self._test_route_add_same_prefix_bulk()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_modify_same_prefix_bulk(self):
        self._test_route_modify_same_prefix_bulk()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_delete_same_prefix_bulk(self):
        self._test_route_delete_same_prefix_bulk()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_with_host_spa(self):
        self._test_add_host_spa()


if __name__ == '__main__':
    unittest.main()
