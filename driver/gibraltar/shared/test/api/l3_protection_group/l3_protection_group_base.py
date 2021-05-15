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
import sim_utils
import topology as T
import packet_test_utils as U
from sdk_test_case_base import *

U.parse_ip_after_mpls()


class l3_protection_group_base(sdk_test_case_base):
    PREFIX1_GID = 0x691
    TE_TUNNEL1_GID = 0x391
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    INPUT_LABEL = sdk.la_mpls_label()
    INPUT_LABEL.label = 0x63
    LDP_LABEL = sdk.la_mpls_label()
    LDP_LABEL.label = 0x64
    MP_LABEL = sdk.la_mpls_label()
    MP_LABEL.label = 0x65
    PRIMARY_TE_LABEL = sdk.la_mpls_label()
    PRIMARY_TE_LABEL.label = 0x66
    BACKUP_LDP_LABEL = sdk.la_mpls_label()
    BACKUP_LDP_LABEL.label = 0x67
    PQ_LABEL = sdk.la_mpls_label()
    PQ_LABEL.label = 0x68
    BACKUP_TE_LABEL = sdk.la_mpls_label()
    BACKUP_TE_LABEL.label = 0x69
    DEST_SID_LABEL = sdk.la_mpls_label()
    DEST_SID_LABEL.label = 0x8f06a
    PROTECTION_GROUP_ID = 0x500
    IP_TTL = 0x88
    MPLS_TTL = 0xff
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    OUTPUT_VID = 0xac

    def setUp(self):
        super().setUp()
        self.ip_impl = self.ip_impl_class()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)

        self.add_default_route()

    def add_default_route(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=0)
        self.ip_impl.add_route(
            self.topology.vrf,
            prefix,
            self.l3_port_impl.def_nh,
            l3_protection_group_base.PRIVATE_DATA_DEFAULT)

    def _test_create_l3_protection_group(self):
        prot_monitor = T.protection_monitor(self, self.device)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor.hld_obj)

    def _test_l3_protection_group_getters(self):
        prot_monitor = T.protection_monitor(self, self.device)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor.hld_obj)

        primary_nh = l3_prot_group.hld_obj.get_primary_destination()
        self.assertEqual(primary_nh.this, self.l3_port_impl.reg_nh.hld_obj.this)

        protecting_nh = l3_prot_group.hld_obj.get_backup_destination()
        self.assertEqual(protecting_nh.this, self.l3_port_impl.ext_nh.hld_obj.this)

        protection_monitor = l3_prot_group.hld_obj.get_monitor()
        self.assertEqual(protection_monitor.this, prot_monitor.hld_obj.this)

        l3_prot_group_by_id = self.device.get_l3_protection_group_by_id(self.PROTECTION_GROUP_ID)
        self.assertEqual(l3_prot_group_by_id.this, l3_prot_group.hld_obj.this)

    def _test_l3_protection_group_scale(self):
        max_prot_group_gid = self.device.get_limit(sdk.limit_type_e_DEVICE__MAX_L3_PROTECTION_GROUP_GIDS)

        prot_monitor = T.protection_monitor(self, self.device)
        prot_monitor2 = T.protection_monitor(self, self.device)

        # Max 4K prot groups. Create one with GID 0 and one with GID 4095 and test traffic.
        l3_prot_group_zero = T.l3_protection_group(
            self,
            self.device,
            0,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor.hld_obj)

        l3_prot_group_max = T.l3_protection_group(
            self,
            self.device,
            max_prot_group_gid - 1,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor2.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, l3_protection_group_base.PREFIX1_GID, l3_prot_group_zero.hld_obj)
        pfx_obj2 = T.prefix_object(self, self.device, l3_protection_group_base.PREFIX1_GID + 1, l3_prot_group_max.hld_obj)

        lsp_labels = []
        pfx_obj.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels,
                                              None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        pfx_obj.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, lsp_labels,
                                              None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        pfx_obj2.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels,
                                               None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        pfx_obj2.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, lsp_labels,
                                               None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               l3_protection_group_base.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IP, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        prot_monitor.hld_obj.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IP_P_NH, T.TX_SLICE_EXT, T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

        self.ip_impl.modify_route(self.topology.vrf, prefix, pfx_obj2)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IP, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        prot_monitor2.hld_obj.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IP_P_NH, T.TX_SLICE_EXT, T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

    def _test_mpls_swap_p_nh(self, add_lsp_counter=True):
        prot_monitor = T.protection_monitor(self, self.device)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, l3_protection_group_base.PREFIX1_GID, l3_prot_group.hld_obj)

        lsp_counter_primary = None
        if add_lsp_counter:
            lsp_counter_primary = self.device.create_counter(1)
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter_primary,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsp_counter_backup = None
        if add_lsp_counter:
            lsp_counter_backup = self.device.create_counter(1)
        lsp_labels = []
        lsp_labels.append(self.BACKUP_LDP_LABEL)

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.ext_nh.hld_obj,
            lsp_labels,
            lsp_counter_backup,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_MPLS, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS_SWAP_PRIMARY, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = lsp_counter_primary.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS_SWAP_PRIMARY, byte_count)

        prot_monitor.hld_obj.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_MPLS, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS_SWAP_LFA_FRR, T.TX_SLICE_EXT, T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

        if add_lsp_counter:
            packet_count, byte_count = lsp_counter_backup.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS_SWAP_LFA_FRR, byte_count)

    def _test_prefix_ecmp_ldp_tenh_p_nh_to_mpls(self, add_lsp_counter=True):
        prot_monitor = T.protection_monitor(self, self.device)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor.hld_obj)

        te_tunnel = T.ldp_over_te_tunnel(self, self.device, l3_protection_group_base.TE_TUNNEL1_GID, l3_prot_group.hld_obj)

        te_counter_primary = None
        if add_lsp_counter:
            te_counter_primary = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter_primary)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_counter_backup = None
        if add_lsp_counter:
            te_counter_backup = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.MP_LABEL)
        te_labels.append(self.BACKUP_TE_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, te_labels, te_counter_backup)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, l3_protection_group_base.PREFIX1_GID, te_ecmp)

        lsp_counter = None
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_te_tunnel_lsp_properties(te_tunnel.hld_obj, lsp_labels, lsp_counter)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               l3_protection_group_base.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_LDPoTE, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = te_counter_primary.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_LDPoTE, byte_count)

        prot_monitor.hld_obj.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_LDPoTE_BACKUP, T.TX_SLICE_EXT, T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

        if add_lsp_counter:
            packet_count, byte_count = te_counter_backup.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_LDPoTE_BACKUP, byte_count)

    def _test_prefix_ecmp_p_nh_to_mpls(self, add_lsp_counter=True):
        prot_monitor = T.protection_monitor(self, self.device)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor.hld_obj)

        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(l3_prot_group.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, l3_protection_group_base.PREFIX1_GID, nh_ecmp)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        lsp_counter_primary = None
        if add_lsp_counter:
            lsp_counter_primary = self.device.create_counter(1)
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter_primary,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsp_counter_backup = None
        if add_lsp_counter:
            lsp_counter_backup = self.device.create_counter(1)
        lsp_labels = []
        lsp_labels.append(self.BACKUP_LDP_LABEL)

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.ext_nh.hld_obj,
            lsp_labels,
            lsp_counter_backup,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               l3_protection_group_base.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = lsp_counter_primary.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

        prot_monitor.hld_obj.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS_LFA_FRR, T.TX_SLICE_EXT, T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

        if add_lsp_counter:
            packet_count, byte_count = lsp_counter_backup.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS_LFA_FRR, byte_count)

    def _test_global_prefix_ecmp_p_nh_to_mpls(self, add_lsp_counter=True):
        prot_monitor = T.protection_monitor(self, self.device)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor.hld_obj)

        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(l3_prot_group.hld_obj)

        pfx_obj = T.global_prefix_object(self, self.device, l3_protection_group_base.PREFIX1_GID, nh_ecmp)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        lsp_counter_primary = None
        if add_lsp_counter:
            lsp_counter_primary = self.device.create_counter(1)
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_global_lsp_properties(lsp_labels, lsp_counter_primary, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               l3_protection_group_base.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = lsp_counter_primary.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

        prot_monitor.hld_obj.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)

    def _test_prefix_ecmp_tenh_p_nh_to_mpls(self, add_lsp_counter=True):
        prot_monitor = T.protection_monitor(self, self.device)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor.hld_obj)

        te_tunnel = T.te_tunnel(self, self.device, l3_protection_group_base.TE_TUNNEL1_GID, l3_prot_group.hld_obj)

        te_counter_primary = None
        if add_lsp_counter:
            te_counter_primary = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter_primary)

        te_counter_backup = None
        if add_lsp_counter:
            te_counter_backup = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.MP_LABEL)
        te_labels.append(self.BACKUP_TE_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, te_labels, te_counter_backup)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, l3_protection_group_base.PREFIX1_GID, te_ecmp)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               l3_protection_group_base.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TE, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = te_counter_primary.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE, byte_count)

        prot_monitor.hld_obj.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TE_BACKUP, T.TX_SLICE_EXT, T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

        if add_lsp_counter:
            packet_count, byte_count = te_counter_backup.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE_BACKUP, byte_count)

    def _test_prefix_ecmp_tenh_p_nh_to_mpls_tunnel_over_tunnel(self, add_lsp_counter=True):
        prot_monitor = T.protection_monitor(self, self.device)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor.hld_obj)

        te_tunnel = T.te_tunnel(self, self.device, l3_protection_group_base.TE_TUNNEL1_GID, l3_prot_group.hld_obj)

        te_counter_primary = None
        if add_lsp_counter:
            te_counter_primary = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter_primary)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_counter_backup = None
        if add_lsp_counter:
            te_counter_backup = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.MP_LABEL)
        te_labels.append(self.BACKUP_TE_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, te_labels, te_counter_backup)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, l3_protection_group_base.PREFIX1_GID, te_ecmp)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               l3_protection_group_base.PRIVATE_DATA_DEFAULT)

        prot_monitor.hld_obj.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TE_BACKUP, T.TX_SLICE_EXT, T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

        if add_lsp_counter:
            packet_count, byte_count = te_counter_backup.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE_BACKUP, byte_count)

        # Update the Protection group (in response to handling a tunnel-over-tunnel event)
        new_prot_monitor = T.protection_monitor(self, self.device)
        l3_prot_group.hld_obj.modify_protection_group(
            self.l3_port_impl.ext_nh.hld_obj,
            self.l3_port_impl.reg_nh.hld_obj,
            new_prot_monitor.hld_obj)

        # Destroy the old protection monitor (when the FRR Protection object is deleted)
        prot_monitor.destroy()

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TE_BACKUP, T.TX_SLICE_EXT, T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

        if add_lsp_counter:
            packet_count, byte_count = te_counter_backup.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE_BACKUP, byte_count)

    def _test_prefix_p_nh_to_ip(self):
        prot_monitor = T.protection_monitor(self, self.device)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, l3_protection_group_base.PREFIX1_GID, l3_prot_group.hld_obj)

        lsp_labels = []
        pfx_obj.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels,
                                              None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        pfx_obj.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, lsp_labels,
                                              None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               l3_protection_group_base.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IP, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        prot_monitor.hld_obj.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IP_P_NH, T.TX_SLICE_EXT, T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

    def _test_prefix_p_nh_to_ip_seq1(self, add_lsp_counter=True):
        prot_monitor = T.protection_monitor(self, self.device)

        prot_monitor.hld_obj.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, l3_protection_group_base.PREFIX1_GID, l3_prot_group.hld_obj)

        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)
        lsp_labels = []
        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.ext_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               l3_protection_group_base.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IP_P_NH, T.TX_SLICE_EXT, T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

    def _test_prefix_p_nh_to_ip_seq2(self, add_lsp_counter=True):
        prot_monitor = T.protection_monitor(self, self.device)

        prot_monitor.hld_obj.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor.hld_obj)

        prot_monitor.hld_obj.set_state(sdk.la_protection_monitor.monitor_state_e_UNTRIGGERED)

        pfx_obj = T.prefix_object(self, self.device, l3_protection_group_base.PREFIX1_GID, l3_prot_group.hld_obj)

        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)
        lsp_labels = []
        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               l3_protection_group_base.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IP, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def _test_prefix_p_nh_to_mpls(self, add_lsp_counter=True):
        prot_monitor = T.protection_monitor(self, self.device)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, l3_protection_group_base.PREFIX1_GID, l3_prot_group.hld_obj)

        lsp_counter_primary = None
        if add_lsp_counter:
            lsp_counter_primary = self.device.create_counter(1)
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter_primary,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsp_counter_backup = None
        if add_lsp_counter:
            lsp_counter_backup = self.device.create_counter(1)
        lsp_labels = []
        lsp_labels.append(self.BACKUP_LDP_LABEL)

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.ext_nh.hld_obj,
            lsp_labels,
            lsp_counter_backup,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               l3_protection_group_base.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = lsp_counter_primary.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

        prot_monitor.hld_obj.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS_LFA_FRR, T.TX_SLICE_EXT, T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

        if add_lsp_counter:
            packet_count, byte_count = lsp_counter_backup.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS_LFA_FRR, byte_count)

    def _test_prefix_p_nh_to_mpls_rlfa_backup_nh(self, add_lsp_counter=True):
        prot_monitor = T.protection_monitor(self, self.device)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, l3_protection_group_base.PREFIX1_GID, l3_prot_group.hld_obj)

        lsp_counter_primary = None
        if add_lsp_counter:
            lsp_counter_primary = self.device.create_counter(1)
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter_primary,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsp_counter_backup = None
        if add_lsp_counter:
            lsp_counter_backup = self.device.create_counter(1)
        lsp_labels = []
        lsp_labels.append(self.PQ_LABEL)
        lsp_labels.append(self.BACKUP_LDP_LABEL)

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.ext_nh.hld_obj,
            lsp_labels,
            lsp_counter_backup,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               l3_protection_group_base.PRIVATE_DATA_DEFAULT)

        prot_monitor.hld_obj.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_MPLS_REMOTE_LFA_FRR,
            T.TX_SLICE_EXT,
            T.TX_IFG_EXT,
            self.l3_port_impl.serdes_ext)

        if add_lsp_counter:
            packet_count, byte_count = lsp_counter_backup.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS_REMOTE_LFA_FRR, byte_count)

    def _test_prefix_p_nh_to_mpls_tilfa_backup_nh(self, add_lsp_counter=True):
        prot_monitor = T.protection_monitor(self, self.device)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, l3_protection_group_base.PREFIX1_GID, l3_prot_group.hld_obj)

        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels,
                                              None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsp_counter_backup = None
        if add_lsp_counter:
            lsp_counter_backup = self.device.create_counter(1)
        lsp_labels = []
        lsp_labels.append(self.DEST_SID_LABEL)
        lsp_labels.append(self.PQ_LABEL)
        lsp_labels.append(self.BACKUP_LDP_LABEL)

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.ext_nh.hld_obj,
            lsp_labels,
            lsp_counter_backup,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               l3_protection_group_base.PRIVATE_DATA_DEFAULT)

        prot_monitor.hld_obj.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS_TI_LFA_FRR, T.TX_SLICE_EXT, T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

        if add_lsp_counter:
            packet_count, byte_count = lsp_counter_backup.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS_TI_LFA_FRR, byte_count)

    def _test_prefix_tenh_p_nh_to_mpls(self, add_lsp_counter=True):
        prot_monitor = T.protection_monitor(self, self.device)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor.hld_obj)

        te_tunnel = T.te_tunnel(self, self.device, l3_protection_group_base.TE_TUNNEL1_GID, l3_prot_group.hld_obj)

        te_counter_primary = None
        if add_lsp_counter:
            te_counter_primary = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter_primary)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_counter_backup = None
        if add_lsp_counter:
            te_counter_backup = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.MP_LABEL)
        te_labels.append(self.BACKUP_TE_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, te_labels, te_counter_backup)

        pfx_obj = T.prefix_object(self, self.device, l3_protection_group_base.PREFIX1_GID, te_tunnel.hld_obj)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               l3_protection_group_base.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TE, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = te_counter_primary.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE, byte_count)

        prot_monitor.hld_obj.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TE_BACKUP, T.TX_SLICE_EXT, T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

        if add_lsp_counter:
            packet_count, byte_count = te_counter_backup.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE_BACKUP, byte_count)

    def _test_update_l3_protection_group_destination(self):
        prot_monitor = T.protection_monitor(self, self.device)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, l3_protection_group_base.PREFIX1_GID, l3_prot_group.hld_obj)

        lsp_labels = []
        pfx_obj.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels,
                                              None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        pfx_obj.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, lsp_labels,
                                              None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               l3_protection_group_base.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IP, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        new_prot_monitor = T.protection_monitor(self, self.device)

        l3_prot_group.hld_obj.modify_protection_group(
            self.l3_port_impl.ext_nh.hld_obj,
            self.l3_port_impl.reg_nh.hld_obj,
            new_prot_monitor.hld_obj)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IP_P_NH, T.TX_SLICE_EXT, T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)
