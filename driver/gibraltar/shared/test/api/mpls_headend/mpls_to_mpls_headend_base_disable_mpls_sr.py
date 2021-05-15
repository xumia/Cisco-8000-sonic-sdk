#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

from scapy.all import *
import sys
import unittest
from leaba import sdk
import ip_test_base
import topology as T
import packet_test_utils as U
from sdk_test_case_base import *
from mpls_headend_base_disable_mpls_sr import *

U.parse_ip_after_mpls()


class mpls_to_mpls_headend_base_disable_mpls_sr(sdk_test_case_base):
    PREFIX0_GID = 0x690
    PREFIX1_GID = 0x691
    PREFIX_16b_GID = 0x8000
    DPE_GID = 0x1008
    DPE_GID1 = 0x2008
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    MPLS_TTL = 0x88
    IP_TTL = 0x90
    INPUT_LABEL0 = sdk.la_mpls_label()
    INPUT_LABEL0.label = 0x64
    INPUT_LABEL1 = sdk.la_mpls_label()
    INPUT_LABEL1.label = 0x63
    OUTPUT_LABEL0 = sdk.la_mpls_label()
    OUTPUT_LABEL0.label = 0x65
    OUTPUT_LABEL1 = sdk.la_mpls_label()
    OUTPUT_LABEL1.label = 0x66
    OUTPUT_LABEL2 = sdk.la_mpls_label()
    OUTPUT_LABEL2.label = 0x67
    LDP_LABEL = sdk.la_mpls_label()
    LDP_LABEL.label = 0x70
    BGP_LABEL = sdk.la_mpls_label()
    BGP_LABEL.label = 0x71
    BGP_LABEL_NEW = sdk.la_mpls_label()
    BGP_LABEL_NEW.label = 0x72
    VPN_LABEL = sdk.la_mpls_label()
    VPN_LABEL.label = 0x77
    PROTECTION_GROUP_ID = 0x500
    PRIVATE_DATA = 0x1234567890abcdef
    OUTPUT_VID = 0xac
    l2_packet_count = 0

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            device.set_bool_property(sdk.la_device_property_e_ENABLE_MPLS_SR_ACCOUNTING, False)

    @classmethod
    def setUpClass(cls):
        super(mpls_to_mpls_headend_base_disable_mpls_sr, cls).setUpClass(
            device_config_func=mpls_to_mpls_headend_base_disable_mpls_sr.device_config_func)

    def setUp(self):
        super().setUp()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)
        self.ingress_counter = self.device.create_counter(sdk.la_l3_protocol_e_LAST)
        self.l3_port_impl.rx_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.ingress_counter)
        self.egress_counter = self.device.create_counter(sdk.la_l3_protocol_e_LAST)
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.egress_counter)
        self.l2_egress_counter = self.device.create_counter(sdk.la_l3_protocol_e_LAST)
        self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l2_egress_counter)

    def set_l2_ac_vlan_tag(self, ac_port):
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = 0x8100
        eve.tag0.tci.fields.vid = self.OUTPUT_VID + 1
        ac_port.hld_obj.set_egress_vlan_edit_command(eve)
        self.l2_packet_count = 1

    def _test_sr_global_per_protocol_counters(self, protocol, add_lsp_counter=False):
        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(self.l3_port_impl.reg_nh.hld_obj)

        pfx_obj = T.global_prefix_object(self, self.device, self.PREFIX1_GID, nh_ecmp)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        # Destroy the old counter set
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, None)
        self.device.destroy(self.egress_counter)

        # Create and set counter set for MPLS SR accounting
        egress_counter = self.device.create_counter(sdk.la_l3_protocol_counter_e_LAST)
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, egress_counter)

        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(3)
        lsp_labels = []
        lsp_labels.append(self.OUTPUT_LABEL0)
        lsp_labels.append(self.OUTPUT_LABEL1)
        lsp_labels.append(self.OUTPUT_LABEL2)
        pfx_obj.hld_obj.set_global_lsp_properties(
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_PER_PROTOCOL)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_WITH_EXP, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = lsp_counter.read(protocol, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR, byte_count)

        packet_count, byte_count = egress_counter.read(sdk.la_l3_protocol_counter_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET, byte_count)

    def _test_php_ecmp_uniform(self, add_lsp_counter=True):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(self.l3_port_impl.reg_nh.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, nh_ecmp)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)
        lsp_labels = []

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        if (self.l3_port_impl.is_svi):
            self.set_l2_ac_vlan_tag(self.topology.tx_l2_ac_port_reg)
            self.output_packet = self.EXPECTED_OUTPUT_PHP_UNIFORM_PACKET_WITH_VLAN
        else:
            self.output_packet = self.EXPECTED_OUTPUT_PHP_UNIFORM_PACKET

        U.run_and_compare(self, self.device, self.INPUT_PACKET,
                          T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES, self.output_packet,
                          T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.l2_egress_counter.read(self.protocol, True, True)
        self.assertEqual(packet_count, self.l2_packet_count)
        packet_count, byte_count = self.egress_counter.read(self.protocol, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.output_packet, byte_count)

        if add_lsp_counter:
            packet_count, byte_count = lsp_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.output_packet, byte_count)

    def _test_prefix_global_php_ecmp_uniform(self, add_lsp_counter=True, is_svi=False):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(self.l3_port_impl.reg_nh.hld_obj)

        pfx_obj = T.global_prefix_object(self, self.device, self.PREFIX1_GID, nh_ecmp)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        # Destroy the old counter set
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, None)
        self.device.destroy(self.egress_counter)

        # Create and set counter set for MPLS SR accounting
        egress_counter = self.device.create_counter(sdk.la_l3_protocol_counter_e_LAST)
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, egress_counter)

        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)
        lsp_labels = []

        pfx_obj.hld_obj.set_global_lsp_properties(lsp_labels, lsp_counter, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PHP_UNIFORM_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = lsp_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PHP_UNIFORM_PACKET, byte_count)

        offset = self.protocol
        packet_count, byte_count = egress_counter.read(offset, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PHP_UNIFORM_PACKET, byte_count)

    def _test_php_uniform(self, add_lsp_counter=True):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)
        lsp_labels = []

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        if (self.l3_port_impl.is_svi):
            self.set_l2_ac_vlan_tag(self.topology.tx_l2_ac_port_reg)
            self.output_packet = self.EXPECTED_OUTPUT_PHP_UNIFORM_PACKET_WITH_VLAN
        else:
            self.output_packet = self.EXPECTED_OUTPUT_PHP_UNIFORM_PACKET

        U.run_and_compare(self, self.device, self.INPUT_PACKET,
                          T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES, self.output_packet,
                          T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.l2_egress_counter.read(self.protocol, True, True)
        self.assertEqual(packet_count, self.l2_packet_count)
        packet_count, byte_count = self.egress_counter.read(self.protocol, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.output_packet, byte_count)

        if add_lsp_counter:
            packet_count, byte_count = lsp_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.output_packet, byte_count)

    def _test_pop_double_label_uniform_1(self, add_lsp_counter=True):
        # This test behaves like the Pipe mode since the decremented outer
        # label ttl is > the inner label ttl
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)
        lsp_labels = []

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_DOUBLE_LABEL_1, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_POP_PIPE_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = lsp_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_POP_PIPE_PACKET, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_POP_PIPE_PACKET, byte_count)

    def _test_pop_double_label_uniform_2(self, add_lsp_counter=True):
        # This test behaves in the Uniform mode since the decremented outer
        # label ttl is < the inner label ttl
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)
        lsp_labels = []

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_DOUBLE_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_POP_UNIFORM_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = lsp_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_POP_UNIFORM_PACKET, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_POP_UNIFORM_PACKET, byte_count)
