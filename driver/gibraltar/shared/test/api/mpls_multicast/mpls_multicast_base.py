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
OUTPUT_LABEL = sdk.la_mpls_label()
OUTPUT_LABEL.label = 0x65

REG_PFX_OBJ_GID = 0x32
DEF_PFX_OBJ_GID = 0x33
EXT_PFX_OBJ_GID = 0x34


class mpls_multicast_base(sdk_test_case_base):

    def setUp(self):

        self.device_name = '/dev/testdev'

        super().setUp()

        self.l3_port_impl = T.ip_l3_ac_base(self.topology)

        self.output_serdes = T.FIRST_SERDES_L3

        self.mc_group = self.device.create_mpls_multicast_group(MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)

        lsp_labels = []
        lsp_labels.append(OUTPUT_LABEL)

        self.prefix_object = self.device.create_prefix_object(
            REG_PFX_OBJ_GID,
            self.l3_port_impl.reg_nh.hld_obj,
            sdk.la_prefix_object.prefix_type_e_NORMAL)
        self.prefix_object.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            None,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        self.mc_group.add(self.prefix_object, self.get_tx_sys_port())

        self.prefix_object_def = self.device.create_prefix_object(
            DEF_PFX_OBJ_GID, self.l3_port_impl.def_nh.hld_obj, sdk.la_prefix_object.prefix_type_e_NORMAL)
        self.prefix_object_def.set_nh_lsp_properties(
            self.l3_port_impl.def_nh.hld_obj,
            lsp_labels,
            None,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        self.mc_group.add(self.prefix_object_def, self.get_tx_sys_port_def())

        self.create_packets()

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
                                            type=Ethertype.MPLS.value) / MPLS(label=OUTPUT_LABEL.label,
                                                                              ttl=TTL - 1) / IPvX(ipvx=self.ipvx,
                                                                                                  src=self.SIP.addr_str,
                                                                                                  dst=self.MC_GROUP_ADDR.addr_str,
                                                                                                  ttl=TTL) / TCP() / Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_DEF_BASE = Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                                                src=T.TX_L3_AC_DEF_MAC.addr_str,
                                                type=Ethertype.MPLS.value) / MPLS(label=OUTPUT_LABEL.label,
                                                                                  ttl=TTL - 1) / IPvX(ipvx=self.ipvx,
                                                                                                      src=self.SIP.addr_str,
                                                                                                      dst=self.MC_GROUP_ADDR.addr_str,
                                                                                                      ttl=TTL) / TCP() / Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_EXT_BASE = Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str,
                                                src=T.TX_L3_AC_EXT_MAC.addr_str,
                                                type=Ethertype.MPLS.value) / MPLS(label=OUTPUT_LABEL.label,
                                                                                  ttl=TTL - 1) / IPvX(ipvx=self.ipvx,
                                                                                                      src=self.SIP.addr_str,
                                                                                                      dst=self.MC_GROUP_ADDR.addr_str,
                                                                                                      ttl=TTL) / TCP() / Raw(load=RAW_PAYLOAD)

        self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(
            INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
        __, self.EXPECTED_OUTPUT_PACKET_DEF = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_DEF_BASE)
        __, self.EXPECTED_OUTPUT_PACKET_EXT = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_EXT_BASE)

    def do_test_route(self):

        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        # Update the replication list and check the forwarding behavior
        self.prefix_object_ext = self.device.create_prefix_object(
            EXT_PFX_OBJ_GID, self.l3_port_impl.ext_nh.hld_obj, sdk.la_prefix_object.prefix_type_e_NORMAL)
        LSP_LABELS = []
        LSP_LABELS.append(OUTPUT_LABEL)
        self.prefix_object_ext.set_nh_lsp_properties(
            self.l3_port_impl.ext_nh.hld_obj,
            LSP_LABELS,
            None,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        self.mc_group.add(self.prefix_object_ext, self.get_tx_sys_port_ext())
        self.mc_group.remove(self.prefix_object)

        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_EXT, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

    def do_test_route_mtu(self):

        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}

        self.prefix_object_ext = self.device.create_prefix_object(
            EXT_PFX_OBJ_GID, self.l3_port_impl.ext_nh.hld_obj, sdk.la_prefix_object.prefix_type_e_NORMAL)
        LSP_LABELS = []
        LSP_LABELS.append(OUTPUT_LABEL)
        self.prefix_object_ext.set_nh_lsp_properties(
            self.l3_port_impl.ext_nh.hld_obj,
            LSP_LABELS,
            None,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        self.mc_group.add(self.prefix_object_ext, self.get_tx_sys_port_ext())
        self.mc_group.remove(self.prefix_object)

        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_EXT, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': self.output_serdes})
        MTU.run_mtu_tests(self, self.device, ingress_packet, expected_packets, Ether)

    def do_test_route_glean(self):

        lsr = self.device.get_lsr()
        lsr.add_route(INPUT_LABEL, self.mc_group, PRIVATE_DATA)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        # Update the replication list and check the forwarding behavior
        self.prefix_object_glean = self.device.create_prefix_object(
            EXT_PFX_OBJ_GID, self.topology.nh_l3_ac_glean.hld_obj, sdk.la_prefix_object.prefix_type_e_NORMAL)
        self.mc_group.add(self.prefix_object_glean, None)
        self.mc_group.remove(self.prefix_object)

        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

    def get_tx_sys_port(self):
        return self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj

    def get_tx_sys_port_ext(self):
        return self.topology.tx_l3_ac_eth_port_ext.sys_port.hld_obj
