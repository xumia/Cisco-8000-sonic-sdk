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
from leaba.debug import debug_device
import packet_test_utils as U
import scapy.all as S
import topology as T
import ip_test_base
import decor
from sdk_test_case_base import *
from ip_routing_base import *
from ipv4_l3_ac_routing_base import *

PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
PUNT_VLAN = 0xA13
PUNT_RELAY_ID = 0 if decor.is_pacific() else T.VRF_GID
MIRROR_CMD_GID = 9
MIRROR_GID_INGRESS_OFFSET = 32
MIRROR_GID_EGRESS_OFFSET = 0
MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET

PUNT_SLICE = T.get_device_slice(2)  # must be even numbered slice
PUNT_IFG = 0
PUNT_PIF_FIRST = T.get_device_first_serdes(8)
PUNT_PIF_LAST = PUNT_PIF_FIRST
PUNT_SP_GID = SYS_PORT_GID_BASE  + 3


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class test_ipv4_l3_ac_routing(ipv4_l3_ac_routing_base):

    def test_add_host_wo_subnet(self):
        self._test_add_host_wo_subnet()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_add_host(self):
        self._test_add_host()

    def test_add_subnet(self):
        self._test_add_subnet()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_change_mac(self):
        self._test_change_mac()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_change_vrf(self):
        self._test_change_vrf()

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

    def test_get_hosts(self):
        self._test_get_hosts()

    def test_get_route(self):
        self._test_get_route()

    def test_get_routing_entry(self):
        self._test_get_routing_entry()

    def test_get_subnets(self):
        self._test_get_subnets()

    def test_l3_ac_illegal_dip(self):
        self._test_illegal_dip('0.0.0.0')

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_l3_drop_adj_non_inject(self):
        self._test_route_l3_drop_adj_non_inject()

    @unittest.skipIf(decor.is_hw_device(), 'Skip on HW device.')
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_l3_drop_adj(self):
        self._test_route_l3_drop_adj()

    @unittest.skipIf(decor.is_hw_device(), 'Skip on HW device.')
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_l3_user_trap_adj(self):
        self._test_route_l3_user_trap_adj()

    @unittest.skipIf(decor.is_hw_device(), 'Skip on HW device.')
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_l3_user_trap2_adj(self):
        self._test_route_l3_user_trap_adj(2)

    @unittest.skipIf(decor.is_hw_device(), 'Skip on HW device.')
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_l3_drop_adj_pif_counter(self):
        self._test_route_l3_drop_adj_pif_counter()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_longer_prefix(self):
        self._test_route_longer_prefix()

    def test_longer_prefix_mtu(self):
        self._test_route_longer_prefix_mtu()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_modify_host(self):
        self._test_modify_host()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_hw_gibraltar(), "sflow tests make test_modify_route fail running on GB HW")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_sflow_pci(self):
        self._test_sflow(self.SNOOP_PACKET, is_ingress=True, is_pci=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_hw_gibraltar(), "sflow tests make test_modify_route fail running on GB HW")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_sflow(self):
        self._test_sflow(self.SNOOP_PACKET, is_ingress=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_hw_gibraltar(), "sflow tests make test_modify_route fail running on GB HW")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_sflow(self):
        self._test_sflow(self.SNOOP_PACKET, is_ingress=False)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_hw_gibraltar(), "sflow tests make test_modify_route fail running on GB HW")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_sflow_pci(self):
        self._test_sflow(self.SNOOP_PACKET, is_ingress=False, is_pci=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_hw_gibraltar(), "sflow tests make test_modify_route fail running on GB HW")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_sflow_host(self):
        snoop_packet_copy = deepcopy(self.SNOOP_PACKET)
        snoop_packet_copy[Punt].destination_lp = 0  # No DLP info for directly attached host
        self._test_sflow(snoop_packet_copy, is_ingress=False, is_host=True)

    @unittest.skipIf(decor.is_hw_gibraltar(), "sflow tests make test_modify_route fail running on GB HW")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_sflow_add_remove_add(self):
        self._test_sflow_add_remove_add(self.SNOOP_PACKET, is_ingress=False, is_host=False)

    @unittest.skipIf(decor.is_hw_gibraltar(), "sflow tests make test_modify_route fail running on GB HW")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_sflow_add_remove_add_host(self):
        snoop_packet_copy = deepcopy(self.SNOOP_PACKET)
        snoop_packet_copy[Punt].destination_lp = 0  # No DLP info for directly attached host
        self._test_sflow_add_remove_add(snoop_packet_copy, is_ingress=False, is_host=True)

    def test_no_default(self):
        self._test_route_no_default()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_l3_ac_px(self):
        self._test_l3_ac_px()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_l3_ac_px_vx(self):
        self._test_l3_ac_px_vx()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_remove_default_route(self):
        self._test_remove_default_route()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_active(self):
        self._test_route_set_active()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_single_fec(self):
        self._test_route_single_fec()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_single_nh(self):
        self._test_route_single_nh()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l3_ac_tag_change_vlan(self):
        self._test_l3_ac_tag_change_vlan()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l3_ac_tag_tag_change_vlan(self):
        self._test_l3_ac_tag_tag_change_vlan()

    def test_l3_ac_tag_tag_change_vlan_mtu(self):
        self._test_l3_ac_tag_tag_change_vlan_mtu()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    def test_l3_ac_tag_tag_with_fallback_change_vlan(self):
        self._test_l3_ac_tag_tag_with_fallback_change_vlan()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_update_mac(self):
        self._test_route_update_mac()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    def test_update_nh(self):
        self._test_route_update_nh()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_with_vlan(self):
        self._test_route_with_vlan()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_with_vlan_vlan(self):
        self._test_route_with_vlan_vlan()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_routing_32_bit_prefix(self):
        self.destroy_default_route()
        prefix = self.ip_impl.build_prefix(self.DIP, length=32)

        for latency_sensitive in [True, False]:
            self.ip_impl.add_route(
                self.topology.vrf,
                prefix,
                self.topology.nh_l3_ac_reg,
                ip_routing_base.PRIVATE_DATA,
                latency_sensitive)

            # Test to ensure double-add not possible
            with self.assertRaises(sdk.ExistException):
                self.ip_impl.add_route(
                    self.topology.vrf,
                    prefix,
                    self.topology.nh_l3_ac_reg,
                    ip_routing_base.PRIVATE_DATA,
                    not latency_sensitive)

            U.run_and_compare(self, self.device,
                              self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                              self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                              T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

            self.ip_impl.modify_route(self.topology.vrf, prefix, self.topology.nh_l3_ac_ext)
            U.run_and_compare(self, self.device,
                              self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                              self.EXPECTED_EXTRA_OUTPUT_PACKET, T.TX_SLICE_EXT,
                              T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT)

            ri = self.ip_impl.get_route(self.topology.vrf, self.DIP)
            self.assertEquals(ri.latency_sensitive, latency_sensitive)

            self.ip_impl.delete_route(self.topology.vrf, prefix)
            U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - NP2 compound")
    @unittest.skipIf(decor.is_gibraltar(), "GB-SKIP: Latency sensitive routes not supported on GB")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_routing_30_bit_prefix(self):
        self.destroy_default_route()
        prefix = self.ip_impl.build_prefix(self.DIP, length=30)

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

        ri = self.ip_impl.get_route(self.topology.vrf, self.DIP)
        self.assertEquals(ri.latency_sensitive, False)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_route_vxlan(self):
        self._test_route_vxlan()

    @unittest.skipUnless(decor.is_hw_gibraltar(), "Run only on GB HW")
    def test_error_counters_fwd(self):
        if T.is_matilda_model(self.device):
            self.skipTest("not yet enabled on matilda")
            return

        # Add route
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, ip_routing_base.PRIVATE_DATA)

        # Test without SER
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        # inject SER
        dd = debug_device(self.device)
        orig_reg_values = []
        for c in range(8):
            v = dd.read_register(dd.device_tree.cdb.core[c].ecc_2b_err_initiate_register)
            orig_reg_values.append(v)
            v.subtrie_mem0_ecc_2b_err_initiate = 1
            v.subtrie_mem1_ecc_2b_err_initiate = 1
            v.extnd_subtrie_mem0_ecc_2b_err_initiate = 1
            v.extnd_subtrie_mem1_ecc_2b_err_initiate = 1
            dd.write_register(dd.device_tree.cdb.core[c].ecc_2b_err_initiate_register, v)

        # packet should be dropped
        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # internal-error counter should increment
        ser_counter = self.device.get_internal_error_counter(
            sdk.la_device.internal_error_stage_e_FORWARDING,
            sdk.la_device.internal_error_type_e_SER)
        slice_ifg = sdk.la_slice_ifg()
        slice_ifg.slice = T.RX_SLICE
        slice_ifg.ifg = T.RX_IFG
        # packets get the odd numbered Rx slice thru inject down and up.
        # So the PIF on the Rx slice is the scheduled-recycle port
        p, b = ser_counter.read(slice_ifg, T.GIBRALTAR_RCY_SERDES, True,  # Force update
                                False  # Clear on read
                                )
        self.assertEqual(p, 1)
        self.assertEqual(b, U.get_injected_packet_len(self.device, self.INPUT_PACKET, T.RX_SLICE))

        # Cleanup
        self.ip_impl.delete_route(self.topology.vrf, prefix)
        for c in range(8):
            dd.write_register(dd.device_tree.cdb.core[c].ecc_2b_err_initiate_register, orig_reg_values[c])

    # @unittest.skipIf(not decor.is_hw_gibraltar(), "Run only on GB HW")
    # @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    # def test_error_counters_term(self):
        #
        #     # Add route
        #     prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        #     self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, ip_routing_base.PRIVATE_DATA)
        #
        #     # Test without SER
        #     U.run_and_compare(self, self.device,
        #                       self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
        #                       self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
        #
        #     # inject SER
        #     dd = debug_device(self.device)
        #     orig_reg_values = []
        #     for sp in range(3):
        #         v = dd.read_register(dd.device_tree.slice_pair[sp].idb.macdb.ecc_2b_err_initiate_register)
        #         orig_reg_values.append(v)
        #         v.large_relay_table_ecc_2b_err_initiate = 1
        #         v.small_relay_table0_ecc_2b_err_initiate = 1
        #         v.small_relay_table1_ecc_2b_err_initiate = 1
        #         dd.write_register(dd.device_tree.slice_pair[sp].idb.macdb.ecc_2b_err_initiate_register, v)
        #
        #     # packet should be dropped
        #     U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        #
        #     # internal-error counter should increment
        #     ser_counter = self.device.get_internal_error_counter(
        #         sdk.la_device.internal_error_stage_e_TERMINATION,
        #         sdk.la_device.internal_error_type_e_SER)
        #     slice_ifg = sdk.la_slice_ifg()
        #     slice_ifg.slice = T.RX_SLICE
        #     slice_ifg.ifg = T.RX_IFG
        #     p, b = ser_counter.read(slice_ifg, T.GIBRALTAR_RCY_SERDES)
        #
        #     self.assertEqual(p, 1)
        #     self.assertEqual(b, U.get_injected_packet_len(self.device, self.INPUT_PACKET, T.RX_SLICE))
        #
        #     # Cleanup
        #     self.ip_impl.delete_route(self.topology.vrf, prefix)
        #     for sp in range(3):
        #         dd.write_register(dd.device_tree.slice_pair[sp].idb.macdb.ecc_2b_err_initiate_register, orig_reg_values[sp])

    # @unittest.skipIf(not decor.is_hw_gibraltar(), "Run only on GB HW")
    # @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    # def test_error_counters_transmit(self):
        #
        #     # Add route
        #     prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        #     self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, ip_routing_base.PRIVATE_DATA)
        #
        #     # Test without SER
        #     U.run_and_compare(self, self.device,
        #                       self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
        #                       self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
        #
        #     # inject SER
        #     dd = debug_device(self.device)
        #     for sp in range(3):
        #         v = dd.read_register(dd.device_tree.slice_pair[sp].idb.encdb.ecc_2b_err_initiate_register)
        #         v.slice0_direct0_nh_table_ecc_2b_err_initiate = 1
        #         v.slice1_direct0_nh_table_ecc_2b_err_initiate = 1
        #         v.slice0_direct1_adj_table_ecc_2b_err_initiate = 1
        #         v.slice1_direct1_adj_table_ecc_2b_err_initiate = 1
        #         dd.write_register(dd.device_tree.slice_pair[sp].idb.encdb.ecc_2b_err_initiate_register, v)
        #
        #     # packet should be dropped
        #     U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        #
        #     # internal-error counter should increment
        #     ser_counter = self.device.get_internal_error_counter(
        #         sdk.la_device.internal_error_stage_e_TRANSMIT,
        #         sdk.la_device.internal_error_type_e_SER)
        #     slice_ifg = sdk.la_slice_ifg()
        #     slice_ifg.slice = T.TX_SLICE_REG
        #     slice_ifg.ifg = T.TX_IFG_REG
        #     p, b = ser_counter.read(slice_ifg, self.l3_port_impl.serdes_reg)
        #
        #     self.assertEqual(p, 1)
        #     # TODO - unexpected byte count
        #     #self.assertEqual(b, U.get_output_packet_len_for_counters(self.device, self.EXPECTED_OUTPUT_PACKET))
        #
        #     # Cleanup
        #     self.ip_impl.delete_route(self.topology.vrf, prefix)
        #     for sp in range(3):
        #         v = dd.read_register(dd.device_tree.slice_pair[sp].idb.encdb.ecc_2b_err_initiate_register)
        #         v.slice0_direct0_nh_table_ecc_2b_err_initiate = 0
        #         v.slice1_direct0_nh_table_ecc_2b_err_initiate = 0
        #         v.slice0_direct1_adj_table_ecc_2b_err_initiate = 0
        #         v.slice1_direct1_adj_table_ecc_2b_err_initiate = 0
        #         dd.write_register(dd.device_tree.slice_pair[sp].idb.encdb.ecc_2b_err_initiate_register, v)

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_longer_prefix_bulk(self):
        self._test_route_longer_prefix_bulk()

    def test_interface_prefix_bulk(self):
        self._test_route_interface_prefix_bulk()

    def test_add_prefix_fec_dependancy_bulk(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self._test_add_prefix_fec_dependancy_bulk(prefix)

    def test_modify_prefix_fec_dependancy_bulk(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self._test_modify_prefix_fec_dependancy_bulk(prefix)

    def test_add_def_prefix_fec_dependancy_bulk(self):
        def_prefix = self.ip_impl.get_default_prefix()
        self._test_add_prefix_fec_dependancy_bulk(def_prefix)

    def test_modify_def_prefix_fec_dependancy_bulk(self):
        def_prefix = self.ip_impl.get_default_prefix()
        self._test_modify_prefix_fec_dependancy_bulk(def_prefix)

    def test_route_add_same_prefix_bulk(self):
        self._test_route_add_same_prefix_bulk()

    def test_route_modify_same_prefix_bulk(self):
        self._test_route_modify_same_prefix_bulk()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_route_delete_same_prefix_bulk(self):
        self._test_route_delete_same_prefix_bulk()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_32_bit_prefix_bulk(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=32)
        self._test_route_max_length_prefix_bulk(prefix)

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_32_bit_latency_sensitive_prefix_bulk(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=32)
        self._test_route_max_length_latency_sensitive_prefix_bulk(prefix)

    def test_route_latency_sensitive_prefix_same_bulk(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=32)
        self._test_route_latency_sensitive_prefix_same_bulk(prefix)

    @unittest.skipIf(decor.is_hw_gibraltar(), "Test is not yet enabled on GB HW")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_scale_prefix_bulk(self):
        NUM_PREFIXES = 10000
        prefix = self.ip_impl.build_prefix(self.DIP, length=24)
        prefixes_update_vec = []
        nh = self.l3_port_impl.reg_fec.hld_obj.get_destination()
        dest = self.topology.nh_l3_ac_reg.hld_obj

        for i in range(NUM_PREFIXES):
            prefix.addr.s_addr += 512
            prefix_update = sdk.la_ipv4_route_entry_parameters()
            prefix_update.action = sdk.la_route_entry_action_e_ADD
            prefix_update.destination = nh
            prefix_update.user_data = ip_routing_base.PRIVATE_DATA
            prefix_update.prefix = prefix
            prefixes_update_vec.append(prefix_update)

        self.program_ip_route_bulk(self.topology.vrf, prefixes_update_vec)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mirror_on_disabled_port(self):

        # Setup punt
        pi_port = T.punt_inject_port(
            self,
            self.device,
            PUNT_SLICE,
            PUNT_IFG,
            PUNT_SP_GID,
            PUNT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)
        punt_ifg = PUNT_IFG
        punt_pif_first = PUNT_PIF_FIRST
        punt_pif_last = PUNT_PIF_LAST

        self.punt_dest = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN)

        # Configure LA_EVENT_IPV4_UC_FORWARDING_DISABLED trap to be sent to punt_dest for verifying later that port is disabled
        priority = 0
        self.device.set_trap_configuration(sdk.LA_EVENT_IPV4_UC_FORWARDING_DISABLED,
                                           priority, None, self.punt_dest, False, False, True, 0)

        # Setting netflow
        sampling_rate = 1.0
        mirror_cmd = T.create_l2_mirror_command(
            self.device,
            MIRROR_CMD_INGRESS_GID,
            pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN,
            sampling_rate)

        # Clear trap and set snoop -> packet will go out and another packet with punt header will be generated.
        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_INGRESS_MONITOR)
        priority = 1
        self.device.set_snoop_configuration(sdk.LA_EVENT_L3_INGRESS_MONITOR, priority, False, False, mirror_cmd)

        # Enable netflow at input port
        self.topology.rx_l3_ac.hld_obj.set_ingress_sflow_enabled(True)

        # Set the route
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix,
                               self.l3_port_impl.reg_fec,
                               ip_routing_base.PRIVATE_DATA)

        TRAP_PACKET = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=len(S.Ether()) + 2 * len(S.Dot1Q()),
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_IPV4_UC_FORWARDING_DISABLED,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_L3_AC_GID,
                   # destination_lp=0x7fff,
                   destination_lp=sdk.LA_EVENT_IPV4_UC_FORWARDING_DISABLED,
                   relay_id=PUNT_RELAY_ID,
                   lpts_flow_type=0) / \
            self.INPUT_PACKET

        SNOOP_PACKET = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR, code=MIRROR_CMD_INGRESS_GID,
                   source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_L3_AC_GID, destination_lp=T.TX_L3_AC_REG_GID,
                   relay_id=T.VRF_GID, lpts_flow_type=0) / \
            self.INPUT_PACKET

        # Test first stage: Send INPUT_PACKET and verify receiving both EXPECTED_OUTPUT_PACKET and SNOOP_PACKET (netflow is on)
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.l3_port_impl.serdes_reg})
        expected_packets.append({'data': SNOOP_PACKET, 'slice': PUNT_SLICE, 'ifg': punt_ifg, 'pif': punt_pif_first})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # Test second stage: Disable rx_l3_ac, send INPUT_PACKET and verify receiving only TRAP_PACKET (without the SNOOP_PACKET)
        self.topology.rx_l3_ac.hld_obj.set_active(False)

        expected_packet = []
        expected_packet.append({'data': TRAP_PACKET, 'slice': PUNT_SLICE, 'ifg': punt_ifg, 'pif': punt_pif_first})

        # run_and_compare_list will make sure only 1 packet got to egress side and will compare it to be the trap packet
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packet)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_with_host_spa(self):
        self._test_add_host_spa()


if __name__ == '__main__':
    unittest.main()
