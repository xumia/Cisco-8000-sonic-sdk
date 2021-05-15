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
U.parse_ip_after_mpls()
import decor


class Object(object):
    pass


class cbf_base(sdk_test_case_base):
    PREFIX0_GID = 0x8690
    PREFIX1_GID = 0x8691
    DPE_GID = 0x1008
    DPE_GID1 = 0x2008
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    MPLS_TTL = 0x88
    IP_TTL = 0x90
    INPUT_LABEL0 = sdk.la_mpls_label()
    INPUT_LABEL0.label = 0x64
    OUTPUT_LABEL0 = sdk.la_mpls_label()
    OUTPUT_LABEL0.label = 0x65
    OUTPUT_LABEL1 = sdk.la_mpls_label()
    OUTPUT_LABEL1.label = 0x66
    OUTPUT_LABEL2 = sdk.la_mpls_label()
    OUTPUT_LABEL2.label = 0x67
    PROTECTION_GROUP_ID = 0x500
    PRIVATE_DATA = 0x1234567890abcdef
    OUTPUT_VID = 0xac
    PAYLOAD_SIZE = 40

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            device.set_bool_property(sdk.la_device_property_e_ENABLE_MPLS_SR_ACCOUNTING, False)
            if (not decor.is_pacific()):
                device.set_bool_property(sdk.la_device_property_e_ENABLE_PBTS, True)

    @classmethod
    def setUpClass(cls):
        super(cbf_base, cls).setUpClass(device_config_func=cbf_base.device_config_func)

    def setUp(self):
        super().setUp()
        self.is_ecmp = False
        self.is_protect_nh = False
        self.is_prefix_object_global = False
        self.l3_port_impl = self.l3_port_impl_class(self.topology)
        self.ingress_counter = self.device.create_counter(sdk.la_l3_protocol_e_LAST)
        self.l3_port_impl.rx_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.ingress_counter)
        self.egress_counter = self.device.create_counter(sdk.la_l3_protocol_e_LAST)
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.egress_counter)
        self.l2_egress_counter = self.device.create_counter(sdk.la_l3_protocol_e_LAST)
        self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l2_egress_counter)

        max_offset = sdk.la_pbts_destination_offset()
        max_offset.value = 1
        self.pbts_map_profile = self.device.create_pbts_map_profile(sdk.la_pbts_map_profile.level_e_LEVEL_0, max_offset)

        tc = sdk.la_mpls_tc()
        tc.value = 1

        dscp = sdk.la_ip_dscp()
        dscp.value = 2

        self.topology.ingress_qos_profile_def.hld_obj.set_encap_qos_tag_mapping(sdk.la_ip_version_e_IPV4, dscp, tc)
        self.topology.ingress_qos_profile_def.hld_obj.set_encap_qos_tag_mapping(sdk.la_ip_version_e_IPV6, dscp, tc)

    def tearDown(self):
        print("Calling {} tearDown()".format(super()))
        self.delete_routes()
        self.destroy_pbts()
        self.destroy_destinations()
        super().tearDown()

    def create_destinations(self):
        if self.is_ecmp:
            print("Ecmp")
            # PrefixObject points to ECMP
            self.ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
            self.assertNotEqual(self.ecmp1, None)
            self.ecmp1.add_member(self.l3_port_impl.reg_nh.hld_obj)
            self.pfx_0_obj = self.prefix_object_class(self, self.device, self.PREFIX0_GID, self.ecmp1)

            self.ecmp0 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
            self.assertNotEqual(self.ecmp0, None)
            self.ecmp0.add_member(self.l3_port_impl.ext_nh.hld_obj)
            self.pfx_1_obj = self.prefix_object_class(self, self.device, self.PREFIX1_GID, self.ecmp0)

        elif self.is_protect_nh:
            # PrefixObject points to P_NH
            self.pfx_0_obj = self.prefix_object_class(self, self.device, self.PREFIX0_GID, self.l3_port_impl.reg_nh.hld_obj)
            self.pfx_1_obj = self.prefix_object_class(self, self.device, self.PREFIX1_GID, self.l3_port_impl.ext_nh.hld_obj)

        else:
            print("NH")
            # PrefixObject points to NH
            self.pfx_0_obj = self.prefix_object_class(self, self.device, self.PREFIX0_GID, self.l3_port_impl.reg_nh.hld_obj)
            self.pfx_1_obj = self.prefix_object_class(self, self.device, self.PREFIX1_GID, self.l3_port_impl.ext_nh.hld_obj)

        self.lsp_counter = None
        counter_mode = sdk.la_prefix_object.lsp_counter_mode_e_LABEL
        self.lsp_counter = self.device.create_counter(1)

        # add Encap Labels
        lsp_labels = []
        lsp_labels.append(self.OUTPUT_LABEL0)
        if self.is_prefix_object_global:
            self.pfx_0_obj.hld_obj.set_global_lsp_properties(lsp_labels, self.lsp_counter, counter_mode)
        else:
            self.pfx_0_obj.hld_obj.set_nh_lsp_properties(
                self.l3_port_impl.reg_nh.hld_obj, lsp_labels, self.lsp_counter, counter_mode)

        lsp_labels.append(self.OUTPUT_LABEL1)
        lsp_labels.append(self.OUTPUT_LABEL2)

        self.lsp_counter_1 = self.device.create_counter(1)
        if self.is_prefix_object_global:
            self.pfx_1_obj.hld_obj.set_global_lsp_properties(lsp_labels, self.lsp_counter_1, counter_mode)
        else:
            self.pfx_1_obj.hld_obj.set_nh_lsp_properties(
                self.l3_port_impl.ext_nh.hld_obj, lsp_labels, self.lsp_counter_1, counter_mode)

    def destroy_destinations(self):
        if self.is_prefix_object_global:
            self.pfx_0_obj.hld_obj.clear_global_lsp_properties()
            self.pfx_1_obj.hld_obj.clear_global_lsp_properties()
        else:
            self.pfx_0_obj.hld_obj.clear_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj)
            self.pfx_1_obj.hld_obj.clear_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj)
        self.device.destroy(self.pfx_0_obj.hld_obj)
        self.device.destroy(self.pfx_1_obj.hld_obj)
        if self.is_ecmp:
            self.device.destroy(self.ecmp0)
            self.device.destroy(self.ecmp1)
        elif self.is_protect_nh:
            pass
        self.device.destroy(self.lsp_counter)

    def create_pbts(self):
        self.group = None
        self.group = self.device.create_pbts_group(self.pbts_map_profile)

        offset = sdk.la_pbts_destination_offset()
        offset.value = 0
        self.group.set_member(offset, self.pfx_0_obj.hld_obj)

        offset.value = 1
        self.group.set_member(offset, self.pfx_1_obj.hld_obj)

    def destroy_pbts(self):
        self.device.destroy(self.group)
        self.device.destroy(self.pbts_map_profile)

    def add_routes(self):
        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, self.group, self.PRIVATE_DATA)

        prefix = self.ip_impl.build_prefix(self.DIP, self.LEN)
        self.dest = Object()
        self.dest.hld_obj = self.group
        self.ip_impl.add_route(self.topology.vrf, prefix, self.dest, self.PRIVATE_DATA)

    def delete_routes(self):
        prefix = self.ip_impl.build_prefix(self.DIP, self.LEN)
        self.ip_impl.delete_route(self.topology.vrf, prefix)

        lsr = self.device.get_lsr()
        lsr.delete_route(self.INPUT_LABEL0)

    def _test_profile_usage_locks(self):
        self.create_destinations()

        # create pbts elements
        self.create_pbts()

        # point routes to pbts elements
        self.add_routes()

        # Now try change profile without valid dest. Should fail
        offset = sdk.la_pbts_destination_offset()
        offset.value = 3
        fcid = sdk.la_fwd_class_id()
        fcid.value = 1

        with self.assertRaises(sdk.InvalException):
            self.pbts_map_profile.set_mapping(fcid, offset)

        # try remove group with active user. Should fail
        with self.assertRaises(sdk.BusyException):
            self.device.destroy(self.group)

    def _test_swap_cbf(self, add_lsp_counter=True):

        self.create_destinations()

        # create pbts elements
        self.create_pbts()

        # point routes to pbts elements
        self.add_routes()

        U.run_and_compare(self, self.device,
                          self.inputs[0], T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.outputs[0], T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_ext)

        packet_count, byte_count = self.lsp_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.outputs[0], byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.outputs[0], byte_count)

        # Default MAP profiles maps all EXP/FCID to offset 0 (Prefix0)
        U.run_and_compare(self, self.device,
                          self.inputs[1], T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.outputs[1], T.TX_SLICE_REG, T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

        offset = sdk.la_pbts_destination_offset()
        offset.value = 1
        fcid = sdk.la_fwd_class_id()
        fcid.value = 1

        # Map EXP/FCID 1 to Offset 1 (prefix1)
        self.pbts_map_profile.set_mapping(fcid, offset)

        # Now EXP1 shouhld egress on Prefix1
        U.run_and_compare(self, self.device,
                          self.inputs[1], T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.outputs[2], T.TX_SLICE_EXT, T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)
