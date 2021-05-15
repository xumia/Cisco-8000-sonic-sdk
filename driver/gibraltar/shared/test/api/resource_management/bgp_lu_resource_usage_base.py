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

import sys
import unittest
from leaba import sdk
import ip_test_base
import topology as T
from sdk_test_case_base import *

U.parse_ip_after_mpls()


class bgp_lu_resource_usage_base(sdk_test_case_base):
    PREFIX0_GID = 0x690
    PREFIX1_GID = 0x691
    PROTECTION_GROUP_ID1 = 0x501
    PROTECTION_GROUP_ID2 = 0x502

    def setUp(self):
        super().setUp()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)

    def _test_bgp_lu_small_em(self):
        # Create the ASBR
        asbr0 = T.prefix_object(self, self.device, self.PREFIX0_GID, self.l3_port_impl.reg_nh.hld_obj)
        asbr0.hld_obj.set_nh_lsp_properties(self.l3_port_impl.def_nh.hld_obj, [], None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        asbr0.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, [], None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        asbr0.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, [], None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        asbr1 = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        asbr1.hld_obj.set_nh_lsp_properties(self.l3_port_impl.def_nh.hld_obj, [], None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        asbr1.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, [], None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        asbr1.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, [], None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        # Create the Label Switched Path to reach the ASBR
        asbr_lsp0 = T.asbr_lsp(
            self,
            self.device,
            asbr0.hld_obj,
            self.l3_port_impl.reg_nh.hld_obj)

        # Update the ASBR LSP destination to a new NH
        asbr_lsp0.hld_obj.set_destination(self.l3_port_impl.def_nh.hld_obj)

        rd = sdk.la_resource_descriptor()
        rd.m_resource_type = sdk.la_resource_descriptor.type_e_EGRESS_SMALL_ENCAP_EM
        small_encap_em_usage = [0, 0, 0]
        for slice_pair_id in range(T.NUM_SLICE_PAIRS_PER_DEVICE):
            rd.m_index.slice_pair_id = slice_pair_id
            res = self.device.get_resource_usage(rd)
            small_encap_em_usage[slice_pair_id] = res.used

        self.assertEqual(small_encap_em_usage[T.TX_SLICE_REG // 2], 0)
        self.assertEqual(small_encap_em_usage[T.TX_SLICE_DEF // 2], 1)

        # Update the ASBR LSP destination back to the old NH
        asbr_lsp0.hld_obj.set_destination(self.l3_port_impl.reg_nh.hld_obj)

        rd = sdk.la_resource_descriptor()
        rd.m_resource_type = sdk.la_resource_descriptor.type_e_EGRESS_SMALL_ENCAP_EM
        small_encap_em_usage = [0, 0, 0]
        for slice_pair_id in range(T.NUM_SLICE_PAIRS_PER_DEVICE):
            rd.m_index.slice_pair_id = slice_pair_id
            res = self.device.get_resource_usage(rd)
            small_encap_em_usage[slice_pair_id] = res.used

        self.assertEqual(small_encap_em_usage[T.TX_SLICE_REG // 2], 1)
        self.assertEqual(small_encap_em_usage[T.TX_SLICE_DEF // 2], 0)

        # Create Protection group
        # Primary - def_nh
        # Backup  - ext_nh
        prot_monitor = T.protection_monitor(self, self.device)
        l3_prot_group0 = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID1,
            self.l3_port_impl.def_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor.hld_obj)
        # Primary - reg_nh
        # Backup  - def_nh
        l3_prot_group1 = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID2,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.def_nh.hld_obj,
            prot_monitor.hld_obj)

        # Update the ASBR LSP destination to a L3 protection group
        asbr_lsp0.hld_obj.set_destination(l3_prot_group0.hld_obj)

        rd = sdk.la_resource_descriptor()
        rd.m_resource_type = sdk.la_resource_descriptor.type_e_EGRESS_SMALL_ENCAP_EM
        small_encap_em_usage = [0, 0, 0]
        for slice_pair_id in range(T.NUM_SLICE_PAIRS_PER_DEVICE):
            rd.m_index.slice_pair_id = slice_pair_id
            res = self.device.get_resource_usage(rd)
            small_encap_em_usage[slice_pair_id] = res.used

        self.assertEqual(small_encap_em_usage[T.TX_SLICE_REG // 2], 0)
        # def_nh and ext_nh are on the same slice_pair
        self.assertEqual(small_encap_em_usage[T.TX_SLICE_DEF // 2], 2)

        # Update the ASBR LSP destination back to the Old NH
        asbr_lsp0.hld_obj.set_destination(self.l3_port_impl.reg_nh.hld_obj)

        rd = sdk.la_resource_descriptor()
        rd.m_resource_type = sdk.la_resource_descriptor.type_e_EGRESS_SMALL_ENCAP_EM
        small_encap_em_usage = [0, 0, 0]
        for slice_pair_id in range(T.NUM_SLICE_PAIRS_PER_DEVICE):
            rd.m_index.slice_pair_id = slice_pair_id
            res = self.device.get_resource_usage(rd)
            small_encap_em_usage[slice_pair_id] = res.used

        self.assertEqual(small_encap_em_usage[T.TX_SLICE_REG // 2], 1)
        self.assertEqual(small_encap_em_usage[T.TX_SLICE_DEF // 2], 0)

        # Update the ASBR LSP destination to a second L3 protection group
        asbr_lsp0.hld_obj.set_destination(l3_prot_group1.hld_obj)

        rd = sdk.la_resource_descriptor()
        rd.m_resource_type = sdk.la_resource_descriptor.type_e_EGRESS_SMALL_ENCAP_EM
        small_encap_em_usage = [0, 0, 0]
        for slice_pair_id in range(T.NUM_SLICE_PAIRS_PER_DEVICE):
            rd.m_index.slice_pair_id = slice_pair_id
            res = self.device.get_resource_usage(rd)
            small_encap_em_usage[slice_pair_id] = res.used

        self.assertEqual(small_encap_em_usage[T.TX_SLICE_REG // 2], 1)
        self.assertEqual(small_encap_em_usage[T.TX_SLICE_DEF // 2], 1)

        # Update the ASBR LSP destination to the first L3 protection group
        asbr_lsp0.hld_obj.set_destination(l3_prot_group0.hld_obj)

        rd = sdk.la_resource_descriptor()
        rd.m_resource_type = sdk.la_resource_descriptor.type_e_EGRESS_SMALL_ENCAP_EM
        small_encap_em_usage = [0, 0, 0]
        for slice_pair_id in range(T.NUM_SLICE_PAIRS_PER_DEVICE):
            rd.m_index.slice_pair_id = slice_pair_id
            res = self.device.get_resource_usage(rd)
            small_encap_em_usage[slice_pair_id] = res.used

        self.assertEqual(small_encap_em_usage[T.TX_SLICE_REG // 2], 0)
        # def_nh and ext_nh are on the same slice_pair
        self.assertEqual(small_encap_em_usage[T.TX_SLICE_DEF // 2], 2)

        # Create a new ASBR Label Switched Path to reach the ASBR
        asbr_lsp1 = T.asbr_lsp(
            self,
            self.device,
            asbr1.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj)

        rd = sdk.la_resource_descriptor()
        rd.m_resource_type = sdk.la_resource_descriptor.type_e_EGRESS_SMALL_ENCAP_EM
        small_encap_em_usage = [0, 0, 0]
        for slice_pair_id in range(T.NUM_SLICE_PAIRS_PER_DEVICE):
            rd.m_index.slice_pair_id = slice_pair_id
            res = self.device.get_resource_usage(rd)
            small_encap_em_usage[slice_pair_id] = res.used

        self.assertEqual(small_encap_em_usage[T.TX_SLICE_REG // 2], 0)
        self.assertEqual(small_encap_em_usage[T.TX_SLICE_DEF // 2], 3)

        # Update the ASBR in the ASBR LSP
        asbr_lsp1.hld_obj.set_asbr(asbr0.hld_obj)

        rd = sdk.la_resource_descriptor()
        rd.m_resource_type = sdk.la_resource_descriptor.type_e_EGRESS_SMALL_ENCAP_EM
        small_encap_em_usage = [0, 0, 0]
        for slice_pair_id in range(T.NUM_SLICE_PAIRS_PER_DEVICE):
            rd.m_index.slice_pair_id = slice_pair_id
            res = self.device.get_resource_usage(rd)
            small_encap_em_usage[slice_pair_id] = res.used

        self.assertEqual(small_encap_em_usage[T.TX_SLICE_REG // 2], 0)
        self.assertEqual(small_encap_em_usage[T.TX_SLICE_DEF // 2], 2)
