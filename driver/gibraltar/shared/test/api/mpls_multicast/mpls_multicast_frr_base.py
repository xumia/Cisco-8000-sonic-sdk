#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

from scapy.config import conf
from scapy.all import *

from packet_test_utils import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
from sdk_test_case_base import *
import mtu.mtu_test_utils as MTU

SA = T.mac_addr('be:ef:5d:35:7a:35')
MC_GROUP_GID = 0x10
TTL = 127

INPUT_LABEL = sdk.la_mpls_label()
INPUT_LABEL.label = 0x64
PRIVATE_DATA = 0x1234567890abcdef
OUTPUT_LABEL_1 = sdk.la_mpls_label()
OUTPUT_LABEL_1.label = 0x65
OUTPUT_LABEL_2 = sdk.la_mpls_label()
OUTPUT_LABEL_2.label = 0x76

PFX_OBJ_GID = 0x32
PFX_OBJ_GID_EXT = 0x33

EGRESS_DEVICE_ID = 10
EGRESS_TX_IFG = 0
EGRESS_TX_SERDES_FIRST = 12
EGRESS_TX_SERDES_LAST = EGRESS_TX_SERDES_FIRST + 1

REMOTE_SYS_PORT_GID = 0x1c
REMOTE_L3_AC_GID = 0x32
REMOTE_L3_AC_MAC = T.mac_addr("ab:cd:ab:cd:ab:cd")
REMOTE_NH_GID = 0x55
REMOTE_NH_MAC = T.mac_addr("12:34:56:78:12:34")

SPA_SP_IFG_1 = 0
SPA_SP_IFG_2 = 1
SPA_SP_SERDES = 8
SP_GID_1 = 123
SP_GID_2 = 124
SPA_GID = 421
L3_AC_GID = 523
L3_AC_MAC = T.mac_addr("ab:cd:ab:cd:ab:ab")
NH_GID = 112
NH_MAC = T.mac_addr("12:34:43:21:12:34")
SPA_PFX_OBJ_GID = 14


class mpls_multicast_frr_base(sdk_test_case_base):

    EGRESS_TX_SLICE = T.get_device_slice(2)

    SPA_SLICE = T.get_device_slice(1)

    def setUp(self):

        self.device_name = '/dev/testdev'

        super().setUp()

        self.EGRESS_TX_SLICE = T.choose_active_slices(self.device, self.EGRESS_TX_SLICE, [2, 4])
        self.SPA_SLICE = T.choose_active_slices(self.device, self.SPA_SLICE, [1, 2])
        self.l3_port_impl = T.ip_l3_ac_base(self.topology)

        self.output_serdes = T.FIRST_SERDES_L3

        self.create_packets()

        self.create_objects()

        self.remote_created = False

    def tearDown(self):
        self.mc_group.remove(self.prefix_object)
        self.device.destroy(self.prefix_object)
        self.device.destroy(self.mc_group)
        self.device.destroy(self.protection_group)
        self.device.destroy(self.monitor)
        if (self.remote_created):
            self.device.destroy(self.remote_prefix_object)
            self.device.destroy(self.remote_protection_group)
            self.nh_remote_p.destroy()
            self.nh_remote_b.destroy()
            self.l3_ac_remote_p.destroy()
            self.l3_ac_remote_b.destroy()
            self.remote_eth_port_b.destroy()
            self.remote_eth_port_p.destroy()
            self.remote_sys_port_b.destroy()
            self.remote_sys_port_p.destroy()
            self.remote_port_b.destroy()
            self.remote_port_p.destroy()

        super().tearDown()

    def create_objects(self):
        self.mc_group = self.device.create_mpls_multicast_group(MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)

        lsp_labels = []
        lsp_labels.append(OUTPUT_LABEL_1)

        lsp_labels_more = []
        lsp_labels_more.append(OUTPUT_LABEL_2)
        lsp_labels_more.append(OUTPUT_LABEL_1)

        self.monitor = self.device.create_multicast_protection_monitor()
        self.monitor.set_state(True, False)

        self.protection_group = self.device.create_multicast_protection_group(
            self.l3_port_impl.reg_nh.hld_obj,
            self.get_tx_sys_port(),
            self.l3_port_impl.def_nh.hld_obj,
            self.get_tx_sys_port_def(),
            self.monitor)

        self.prefix_object = self.device.create_prefix_object(
            PFX_OBJ_GID, self.protection_group, sdk.la_prefix_object.prefix_type_e_NORMAL)
        self.prefix_object.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            None,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        self.prefix_object.set_nh_lsp_properties(
            self.l3_port_impl.def_nh.hld_obj,
            lsp_labels_more,
            None,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        self.prefix_object.set_nh_lsp_properties(
            self.l3_port_impl.ext_nh.hld_obj,
            lsp_labels_more,
            None,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        self.mc_group.add(self.prefix_object, None)

    def create_remote_prot_group(self, primary_remote=False, backup_remote=False):
        self.create_remote_ports()

        self.remote_monitor = self.device.create_multicast_protection_monitor()

        if (primary_remote):
            primary = self.nh_remote_p.hld_obj
            primary_sys_port = self.remote_sys_port_p.hld_obj
        else:
            primary = self.l3_port_impl.reg_nh.hld_obj
            primary_sys_port = self.get_tx_sys_port()

        if (backup_remote):
            backup = self.nh_remote_b.hld_obj
            backup_sys_port = self.remote_sys_port_b.hld_obj
        else:
            backup = self.l3_port_impl.def_nh.hld_obj
            backup_sys_port = self.get_tx_sys_port_def()

        self.remote_protection_group = self.device.create_multicast_protection_group(
            primary,
            primary_sys_port,
            backup,
            backup_sys_port,
            self.remote_monitor)

        lsp_labels = []
        lsp_labels.append(OUTPUT_LABEL_1)

        lsp_labels_more = []
        lsp_labels_more.append(OUTPUT_LABEL_2)
        lsp_labels_more.append(OUTPUT_LABEL_1)

        self.remote_prefix_object = self.device.create_prefix_object(
            PFX_OBJ_GID + 1, self.remote_protection_group, sdk.la_prefix_object.prefix_type_e_NORMAL)
        self.remote_prefix_object.set_nh_lsp_properties(primary, lsp_labels, None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        self.remote_prefix_object.set_nh_lsp_properties(
            backup, lsp_labels_more, None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.remote_created = True

    def create_remote_ports(self):
        # Create remote ports
        self.remote_port_p = T.remote_port(
            self,
            self.device,
            EGRESS_DEVICE_ID,
            self.EGRESS_TX_SLICE,
            EGRESS_TX_IFG,
            EGRESS_TX_SERDES_FIRST,
            EGRESS_TX_SERDES_LAST)
        self.remote_port_b = T.remote_port(
            self,
            self.device,
            EGRESS_DEVICE_ID,
            self.EGRESS_TX_SLICE,
            EGRESS_TX_IFG + 1,
            EGRESS_TX_SERDES_FIRST,
            EGRESS_TX_SERDES_LAST)

        # Create remote system port above the remote port
        self.remote_sys_port_p = T.system_port(self, self.device, REMOTE_SYS_PORT_GID, self.remote_port_p)
        self.remote_sys_port_b = T.system_port(self, self.device, REMOTE_SYS_PORT_GID + 1, self.remote_port_b)

        # Create remote ethernet port above the remote system port
        self.remote_eth_port_p = T.sa_ethernet_port(self, self.device, self.remote_sys_port_p)
        self.remote_eth_port_b = T.sa_ethernet_port(self, self.device, self.remote_sys_port_b)

        # Create remote AC port above the remote ethernet
        self.l3_ac_remote_p = T.l3_ac_port(self,
                                           self.device,
                                           REMOTE_L3_AC_GID,
                                           self.remote_eth_port_p,
                                           self.topology.vrf,
                                           REMOTE_L3_AC_MAC,
                                           0,
                                           0)
        self.nh_remote_p = T.next_hop(self, self.device, REMOTE_NH_GID, REMOTE_NH_MAC, self.l3_ac_remote_p)
        self.l3_ac_remote_b = T.l3_ac_port(self,
                                           self.device,
                                           REMOTE_L3_AC_GID + 1,
                                           self.remote_eth_port_b,
                                           self.topology.vrf,
                                           REMOTE_L3_AC_MAC,
                                           0,
                                           0)
        self.nh_remote_b = T.next_hop(self, self.device, REMOTE_NH_GID + 1, REMOTE_NH_MAC, self.l3_ac_remote_b)

    def create_bundle_objects(self):
        self.mac_port_1 = T.mac_port(self, self.device, self.SPA_SLICE, SPA_SP_IFG_1, SPA_SP_SERDES, SPA_SP_SERDES + 1)
        self.mac_port_1.activate()
        self.sys_port_1 = T.system_port(self, self.device, SP_GID_1, self.mac_port_1)
        self.mac_port_2 = T.mac_port(self, self.device, self.SPA_SLICE, SPA_SP_IFG_2, SPA_SP_SERDES, SPA_SP_SERDES + 1)
        self.mac_port_2.activate()
        self.sys_port_2 = T.system_port(self, self.device, SP_GID_2, self.mac_port_2)
        self.spa_port = T.spa_port(self, self.device, SPA_GID)
        self.spa_port.add(self.sys_port_1)
        self.spa_port.add(self.sys_port_2)
        self.spa_eth_port = T.sa_ethernet_port(self, self.device, self.spa_port)
        self.spa_l3_ac = T.l3_ac_port(self, self.device, L3_AC_GID, self.spa_eth_port, self.topology.vrf, T.TX_L3_AC_REG_MAC)
        self.spa_nh = T.next_hop(self, self.device, NH_GID, T.NH_L3_AC_REG_MAC, self.spa_l3_ac)
        self.spa_prot_group = self.device.create_multicast_protection_group(
            self.spa_nh.hld_obj,
            self.sys_port_1.hld_obj,
            self.l3_port_impl.def_nh.hld_obj,
            self.get_tx_sys_port_def(),
            self.monitor)
        self.spa_pfx_obj = self.device.create_prefix_object(
            SPA_PFX_OBJ_GID, self.spa_prot_group, sdk.la_prefix_object.prefix_type_e_NORMAL)
        lsp_labels = []
        lsp_labels.append(OUTPUT_LABEL_1)
        self.spa_pfx_obj.set_nh_lsp_properties(self.spa_nh.hld_obj, lsp_labels, None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

    def destroy_bundle_objects(self):
        self.device.destroy(self.spa_pfx_obj)
        self.device.destroy(self.spa_prot_group)
        self.spa_nh.destroy()
        self.spa_l3_ac.destroy()
        self.spa_eth_port.destroy()
        self.spa_port.destroy()
        self.sys_port_1.destroy()
        self.mac_port_1.destroy()
        self.sys_port_2.destroy()
        self.mac_port_2.destroy()

    def create_packets(self):
        INPUT_PACKET_BASE = Ether(dst=T.RX_L3_AC_MAC.addr_str,
                                  src=SA.addr_str,
                                  type=Ethertype.QinQ.value) / Dot1Q(vlan=T.RX_L3_AC_PORT_VID1,
                                                                     type=Ethertype.Dot1Q.value) / Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / MPLS(label=INPUT_LABEL.label,
                                                                                                                                           ttl=TTL) / IPvX(ipvx=self.ipvx,
                                                                                                                                                           src=self.SIP.addr_str,
                                                                                                                                                           dst=self.MC_GROUP_ADDR.addr_str,
                                                                                                                                                           ttl=TTL) / TCP() / Raw(load=RAW_PAYLOAD)
        EXPECTED_OUTPUT_PACKET_BASE = Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                                            src=T.TX_L3_AC_REG_MAC.addr_str,
                                            type=Ethertype.MPLS.value) / MPLS(label=OUTPUT_LABEL_1.label,
                                                                              ttl=TTL - 1) / IPvX(ipvx=self.ipvx,
                                                                                                  src=self.SIP.addr_str,
                                                                                                  dst=self.MC_GROUP_ADDR.addr_str,
                                                                                                  ttl=TTL) / TCP() / Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_DEF_DOUBLE_LABEL_BASE = Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                                                             src=T.TX_L3_AC_DEF_MAC.addr_str,
                                                             type=Ethertype.MPLS.value) / MPLS(label=OUTPUT_LABEL_1.label,
                                                                                               ttl=TTL - 1) / \
            MPLS(label=OUTPUT_LABEL_2.label, ttl=TTL - 1) / IPvX(ipvx=self.ipvx,
                                                                 src=self.SIP.addr_str,
                                                                 dst=self.MC_GROUP_ADDR.addr_str,
                                                                 ttl=TTL) / TCP() / Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_EXT_DOUBLE_LABEL_BASE = Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str,
                                                             src=T.TX_L3_AC_EXT_MAC.addr_str,
                                                             type=Ethertype.MPLS.value) / MPLS(label=OUTPUT_LABEL_1.label,
                                                                                               ttl=TTL - 1) / \
            MPLS(label=OUTPUT_LABEL_2.label, ttl=TTL - 1) / IPvX(ipvx=self.ipvx,
                                                                 src=self.SIP.addr_str,
                                                                 dst=self.MC_GROUP_ADDR.addr_str,
                                                                 ttl=TTL) / TCP() / Raw(load=RAW_PAYLOAD)

        self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(
            INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
        __, self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF = pad_input_and_output_packets(
            INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_DEF_DOUBLE_LABEL_BASE)
        __, self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_EXT = pad_input_and_output_packets(
            INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_EXT_DOUBLE_LABEL_BASE)

    def do_test_frr_remote_to_non_remote_same_slice(self):
        self.create_bundle_objects()

        # Create remote port
        remote_port = T.remote_port(
            self,
            self.device,
            EGRESS_DEVICE_ID,
            self.SPA_SLICE,
            EGRESS_TX_IFG,
            EGRESS_TX_SERDES_FIRST,
            EGRESS_TX_SERDES_LAST)
        remote_sys_port = T.system_port(self, self.device, REMOTE_SYS_PORT_GID, remote_port)

        self.spa_port.remove(self.sys_port_2)
        self.spa_port.add(remote_sys_port)

        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        self.mc_group.remove(self.prefix_object)
        self.mc_group.add(self.spa_pfx_obj, None)

        # Modify bundle protection group to have remote primary member
        self.spa_prot_group.modify_protection_group(self.spa_nh.hld_obj, remote_sys_port.hld_obj,
                                                    self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                    self.monitor)

        # Change monitor
        self.new_monitor = self.device.create_multicast_protection_monitor()
        self.spa_prot_group.modify_protection_group(self.spa_nh.hld_obj, remote_sys_port.hld_obj,
                                                    self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                    self.new_monitor)

        # Test remote primary
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        # Modify bundle to local member
        self.spa_prot_group.modify_protection_group(self.spa_nh.hld_obj, self.sys_port_1.hld_obj,
                                                    self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                    self.new_monitor)

        # Test local primary
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': self.SPA_SLICE,
                                 'ifg': SPA_SP_IFG_1, 'pif': SPA_SP_SERDES})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        lsr.delete_route(INPUT_LABEL)
        self.mc_group.remove(self.spa_pfx_obj)
        self.mc_group.add(self.prefix_object, None)

        self.destroy_bundle_objects()

        self.device.destroy(self.new_monitor)
        self.device.destroy(remote_sys_port.hld_obj)
        self.device.destroy(remote_port.hld_obj)

    def do_test_frr_bundle(self):
        self.create_bundle_objects()

        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        self.mc_group.remove(self.prefix_object)
        self.mc_group.add(self.spa_pfx_obj, None)

        # Test first SPA member
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': self.SPA_SLICE,
                                 'ifg': SPA_SP_IFG_1, 'pif': SPA_SP_SERDES})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        # Update pinned member
        self.spa_prot_group.modify_protection_group(self.spa_nh.hld_obj, self.sys_port_2.hld_obj,
                                                    self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                    self.monitor)

        # Test second SPA member
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': self.SPA_SLICE,
                                 'ifg': SPA_SP_IFG_2, 'pif': SPA_SP_SERDES})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        lsr.delete_route(INPUT_LABEL)
        self.mc_group.remove(self.spa_pfx_obj)
        self.mc_group.add(self.prefix_object, None)

        self.destroy_bundle_objects()

    def do_test_frr(self):
        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        # Primary only
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        # Enable FRR - primary down, backup up
        self.monitor.set_state(False, True)

        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        # Reset monitor
        self.monitor.set_state(True, False)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        # Update primary
        self.protection_group.modify_protection_group(self.l3_port_impl.ext_nh.hld_obj, self.get_tx_sys_port_ext(),
                                                      self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                      self.monitor)

        lsr.delete_route(INPUT_LABEL)

    def do_test_frr_multiple_packets(self):
        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        # While not an intended use case, test with both packets set to enabled, to cover all cases
        self.monitor.set_state(True, True)
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        # Similarly, test with both packets set to disabled
        self.monitor.set_state(False, False)

        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        lsr.delete_route(INPUT_LABEL)

    def do_test_frr_remote_backup(self):
        self.create_remote_prot_group(False, True)

        self.mc_group.remove(self.prefix_object)
        self.mc_group.add(self.remote_prefix_object, None)

        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        # For primary enabled, we should see one packet flow
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        # If we set FRR, we should see no packets, as backup is a remote port
        self.remote_monitor.set_state(False, True)

        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.mc_group.add(self.prefix_object, None)
        self.mc_group.remove(self.remote_prefix_object)
        lsr.delete_route(INPUT_LABEL)

    def do_test_frr_remote_primary(self):
        self.create_remote_prot_group(True, False)

        self.mc_group.remove(self.prefix_object)
        self.mc_group.add(self.remote_prefix_object, None)

        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        # For primary enabled, we should see no packets
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        # If we set FRR, we should see one packet, as backup is not remote
        self.remote_monitor.set_state(False, True)

        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.mc_group.add(self.prefix_object, None)
        self.mc_group.remove(self.remote_prefix_object)
        lsr.delete_route(INPUT_LABEL)

    def do_test_frr_remote_both(self):
        self.create_remote_prot_group(True, True)

        self.mc_group.remove(self.prefix_object)
        self.mc_group.add(self.remote_prefix_object, None)

        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        # For primary enabled, we should see no packets
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        # If we set FRR, we should see no packets as well
        self.remote_monitor.set_state(False, True)

        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.mc_group.add(self.prefix_object, None)
        self.mc_group.remove(self.remote_prefix_object)
        lsr.delete_route(INPUT_LABEL)

    def do_test_frr_update_monitor(self):
        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        # Check basic flow
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        # Update monitor case
        self.new_monitor = self.device.create_multicast_protection_monitor()
        self.new_monitor.set_state(False, True)

        self.protection_group.modify_protection_group(self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(),
                                                      self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                      self.new_monitor)

        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        # Try to update null monitor - should fail
        with self.assertRaises(sdk.InvalException):
            self.protection_group.modify_protection_group(self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(),
                                                          self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                          None)

        lsr.delete_route(INPUT_LABEL)

    def do_test_frr_update_backup(self):
        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        # Update backup
        self.protection_group.modify_protection_group(self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(),
                                                      self.l3_port_impl.ext_nh.hld_obj, self.get_tx_sys_port_ext(),
                                                      self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_EXT, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(True, False)

        # Set backup to null
        self.protection_group.modify_protection_group(self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(),
                                                      None, None, self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(True, False)

        # Reset backup to original
        self.protection_group.modify_protection_group(self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(),
                                                      self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                      self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(True, False)

        lsr.delete_route(INPUT_LABEL)

    def do_test_frr_update_primary(self):
        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        # Update primary
        self.protection_group.modify_protection_group(self.l3_port_impl.ext_nh.hld_obj, self.get_tx_sys_port_ext(),
                                                      self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                      self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_EXT, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(True, False)

        # Reset primary to original
        self.protection_group.modify_protection_group(self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(),
                                                      self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                      self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(True, False)

        lsr.delete_route(INPUT_LABEL)

    def do_test_frr_update_swap(self):
        self.create_remote_ports()

        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        # Swap primary and backup
        self.protection_group.modify_protection_group(self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                      self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(),
                                                      self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(True, False)

        # Swap back
        self.protection_group.modify_protection_group(self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(),
                                                      self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                      self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(True, False)

        # Modify backup to a remote port, then do a swap
        self.protection_group.modify_protection_group(self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(),
                                                      self.nh_remote_p.hld_obj, self.remote_sys_port_p.hld_obj,
                                                      self.monitor)
        self.protection_group.modify_protection_group(self.nh_remote_p.hld_obj, self.remote_sys_port_p.hld_obj,
                                                      self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(),
                                                      self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        lsr.delete_route(INPUT_LABEL)

    def do_test_frr_update_swap_partial(self):
        self.create_remote_ports()

        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        # Swap old backup to primary, and add new backup
        self.protection_group.modify_protection_group(self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                      self.l3_port_impl.ext_nh.hld_obj, self.get_tx_sys_port_ext(),
                                                      self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_EXT, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(True, False)

        # Swap back
        self.protection_group.modify_protection_group(self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(),
                                                      self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                      self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(True, False)

        # Modify a remote in as a new backup
        self.protection_group.modify_protection_group(self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                      self.nh_remote_b.hld_obj, self.remote_sys_port_b.hld_obj,
                                                      self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        lsr.delete_route(INPUT_LABEL)

    def do_test_frr_update_remote_primary(self):
        self.create_remote_ports()
        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        # Update primary
        self.protection_group.modify_protection_group(self.nh_remote_p.hld_obj, self.remote_sys_port_p.hld_obj,
                                                      self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                      self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(True, False)

        # Reset primary to original
        self.protection_group.modify_protection_group(self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(),
                                                      self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                      self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        lsr.delete_route(INPUT_LABEL)

    def do_test_frr_update_remote_backup(self):
        self.create_remote_ports()
        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        # Update backup
        self.protection_group.modify_protection_group(self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(),
                                                      self.nh_remote_b.hld_obj, self.remote_sys_port_b.hld_obj,
                                                      self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(True, False)

        # Reset primary to original
        self.protection_group.modify_protection_group(self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(),
                                                      self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                      self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        lsr.delete_route(INPUT_LABEL)

    def do_test_frr_update_remote_both(self):
        self.create_remote_ports()
        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        # Update backup
        self.protection_group.modify_protection_group(self.nh_remote_p.hld_obj, self.remote_sys_port_p.hld_obj,
                                                      self.nh_remote_b.hld_obj, self.remote_sys_port_b.hld_obj,
                                                      self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(True, False)

        # Reset primary to original
        self.protection_group.modify_protection_group(self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(),
                                                      self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                      self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        lsr.delete_route(INPUT_LABEL)

    def do_test_frr_update_multiple(self):
        self.create_remote_ports()
        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        self.new_monitor = self.device.create_multicast_protection_monitor()

        # Update multiple parameters simultaneously
        self.protection_group.modify_protection_group(self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                      self.l3_port_impl.ext_nh.hld_obj, self.get_tx_sys_port_ext(),
                                                      self.new_monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.new_monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_EXT, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.new_monitor.set_state(True, False)

        # Another multi-state change - this one including a remote port
        self.protection_group.modify_protection_group(self.l3_port_impl.ext_nh.hld_obj, self.get_tx_sys_port_ext(),
                                                      self.nh_remote_b.hld_obj, self.remote_sys_port_b.hld_obj,
                                                      self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_EXT, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        lsr.delete_route(INPUT_LABEL)

    def do_test_frr_null_backup(self):
        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        self.mc_group.remove(self.prefix_object)

        lsp_labels = []
        lsp_labels.append(OUTPUT_LABEL_1)

        lsp_labels_more = []
        lsp_labels_more.append(OUTPUT_LABEL_2)
        lsp_labels_more.append(OUTPUT_LABEL_1)

        self.null_protection_group = self.device.create_multicast_protection_group(
            self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(), None, None, self.monitor)
        self.null_prefix_object = self.device.create_prefix_object(
            PFX_OBJ_GID_EXT, self.null_protection_group, sdk.la_prefix_object.prefix_type_e_NORMAL)
        self.null_prefix_object.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            None,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        self.null_prefix_object.set_nh_lsp_properties(
            self.l3_port_impl.def_nh.hld_obj,
            lsp_labels_more,
            None,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.mc_group.add(self.null_prefix_object, None)

        # Test real primary, null backup
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(True, False)

        # Modify backup
        self.null_protection_group.modify_protection_group(self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(),
                                                           self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                           self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.mc_group.remove(self.null_prefix_object)
        self.device.destroy(self.null_prefix_object)
        self.device.destroy(self.null_protection_group)
        self.mc_group.add(self.prefix_object, None)
        lsr.delete_route(INPUT_LABEL)

    def do_test_frr_update_remote_to_non_remote(self):
        self.create_remote_prot_group(False, True)

        self.mc_group.remove(self.prefix_object)
        self.mc_group.add(self.remote_prefix_object, None)

        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.remote_monitor.set_state(False, True)

        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.remote_monitor.set_state(True, False)

        # Modify primary to point to actual system port
        self.remote_protection_group.modify_protection_group(self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(),
                                                             self.nh_remote_b.hld_obj, self.remote_sys_port_b.hld_obj,
                                                             self.remote_monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.remote_monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.remote_monitor.set_state(True, False)

        # Modify back
        self.remote_protection_group.modify_protection_group(self.nh_remote_p.hld_obj, self.remote_sys_port_p.hld_obj,
                                                             self.nh_remote_b.hld_obj, self.remote_sys_port_b.hld_obj,
                                                             self.remote_monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.remote_monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.mc_group.add(self.prefix_object, None)
        self.mc_group.remove(self.remote_prefix_object)
        lsr.delete_route(INPUT_LABEL)

    def do_test_frr_multiple_protect_groups(self):
        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        lsp_labels = []
        lsp_labels.append(OUTPUT_LABEL_1)

        lsp_labels_more = []
        lsp_labels_more.append(OUTPUT_LABEL_2)
        lsp_labels_more.append(OUTPUT_LABEL_1)

        self.addl_monitor = self.device.create_multicast_protection_monitor()
        self.addl_protection_group = self.device.create_multicast_protection_group(
            self.l3_port_impl.ext_nh.hld_obj,
            self.get_tx_sys_port_ext(),
            self.l3_port_impl.def_nh.hld_obj,
            self.get_tx_sys_port_def(),
            self.addl_monitor)
        self.addl_prefix_object = self.device.create_prefix_object(
            PFX_OBJ_GID_EXT, self.addl_protection_group, sdk.la_prefix_object.prefix_type_e_NORMAL)
        self.addl_prefix_object.set_nh_lsp_properties(
            self.l3_port_impl.ext_nh.hld_obj,
            lsp_labels_more,
            None,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        self.addl_prefix_object.set_nh_lsp_properties(
            self.l3_port_impl.def_nh.hld_obj,
            lsp_labels_more,
            None,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.mc_group.add(self.addl_prefix_object, None)

        # Test both monitors set to primary
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_EXT, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': self.output_serdes})

        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        # Group 1 - backup enabled, Group 2 - primary enabled
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_EXT, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(True, False)
        self.addl_monitor.set_state(False, True)

        # Group 1 - primary enabled, Group 2 - backup enabled
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})

        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)
        self.addl_monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})

        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        lsr.delete_route(INPUT_LABEL)

    def do_test_frr_mixed(self):
        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        lsp_labels = []
        lsp_labels.append(OUTPUT_LABEL_2)
        lsp_labels.append(OUTPUT_LABEL_1)

        self.reg_prefix_object = self.device.create_prefix_object(
            PFX_OBJ_GID_EXT, self.l3_port_impl.ext_nh.hld_obj, sdk.la_prefix_object.prefix_type_e_NORMAL)
        self.reg_prefix_object.set_nh_lsp_properties(
            self.l3_port_impl.ext_nh.hld_obj,
            lsp_labels,
            None,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        self.mc_group.add(self.reg_prefix_object, self.get_tx_sys_port_ext())

        # Primary active - two packets expected
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_EXT, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        # Enable FRR - primary down, backup up - two packets expected
        self.monitor.set_state(False, True)

        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_EXT, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        # Reset monitor
        self.monitor.set_state(True, False)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_EXT, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        lsr.delete_route(INPUT_LABEL)

    def do_test_frr_counters(self):
        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        self.primary_counter = self.device.create_counter(1)
        self.backup_counter = self.device.create_counter(1)

        lsp_labels = []
        lsp_labels.append(OUTPUT_LABEL_1)

        lsp_labels_more = []
        lsp_labels_more.append(OUTPUT_LABEL_2)
        lsp_labels_more.append(OUTPUT_LABEL_1)

        self.prefix_object.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            self.primary_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        self.prefix_object.set_nh_lsp_properties(
            self.l3_port_impl.def_nh.hld_obj,
            lsp_labels_more,
            self.backup_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        packets, bytes = self.primary_counter.read(0, True, True)
        self.assertEqual(packets, 1)
        packets, bytes = self.backup_counter.read(0, True, True)
        self.assertEqual(packets, 0)

        self.monitor.set_state(False, True)

        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        packets, bytes = self.primary_counter.read(0, True, True)
        self.assertEqual(packets, 0)
        packets, bytes = self.backup_counter.read(0, True, True)
        self.assertEqual(packets, 1)

        lsr.delete_route(INPUT_LABEL)

    def do_test_frr_invalid_params(self):
        # Test invalid prot group create/update params
        # Null primary
        with self.assertRaises(sdk.InvalException):
            self.device.create_multicast_protection_group(None, None, self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                          self.monitor)
        with self.assertRaises(sdk.InvalException):
            self.protection_group.modify_protection_group(None, None, self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                          self.monitor)

        # Primary sys-port doesn't match NH
        with self.assertRaises(sdk.InvalException):
            self.device.create_multicast_protection_group(self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port_ext(),
                                                          self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                          self.monitor)
        with self.assertRaises(sdk.InvalException):
            self.protection_group.modify_protection_group(self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port_ext(),
                                                          self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                          self.monitor)

        # Backup sys-port doesn't match NH
        with self.assertRaises(sdk.InvalException):
            self.device.create_multicast_protection_group(self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(),
                                                          self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_ext(),
                                                          self.monitor)
        with self.assertRaises(sdk.InvalException):
            self.protection_group.modify_protection_group(self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(),
                                                          self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_ext(),
                                                          self.monitor)

        # Prefix object for prot group should be normal type only
        with self.assertRaises(sdk.NotImplementedException):
            self.device.create_prefix_object(PFX_OBJ_GID_EXT, self.protection_group, sdk.la_prefix_object.prefix_type_e_GLOBAL)

        # Double add prot prefix objects
        with self.assertRaises(sdk.ExistException):
            self.mc_group.add(self.prefix_object, None)

        # Double remove prefix objects
        with self.assertRaises(sdk.NotFoundException):
            self.mc_group.remove(self.prefix_object)
            self.mc_group.remove(self.prefix_object)

        self.mc_group.add(self.prefix_object, None)

    def do_test_frr_glean_nh(self):
        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        # Update primary to glean
        self.protection_group.modify_protection_group(self.topology.nh_l3_ac_glean.hld_obj, None,
                                                      self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                      self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(True, False)

        # Reset primary to original
        self.protection_group.modify_protection_group(self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(),
                                                      self.l3_port_impl.def_nh.hld_obj, self.get_tx_sys_port_def(),
                                                      self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DOUBLE_LABEL_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(True, False)

        # Update backup to glean
        self.protection_group.modify_protection_group(self.l3_port_impl.reg_nh.hld_obj, self.get_tx_sys_port(),
                                                      self.topology.nh_l3_ac_glean.hld_obj, None,
                                                      self.monitor)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(False, True)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.monitor.set_state(True, False)

        lsr.delete_route(INPUT_LABEL)

    def get_tx_sys_port(self):
        return self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj

    def get_tx_sys_port_ext(self):
        return self.topology.tx_l3_ac_eth_port_ext.sys_port.hld_obj
