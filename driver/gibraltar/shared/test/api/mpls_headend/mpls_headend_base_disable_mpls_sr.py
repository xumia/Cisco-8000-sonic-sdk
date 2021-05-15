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


class mpls_headend_base_disable_mpls_sr(sdk_test_case_base):
    PREFIX0_GID = 0x690
    PREFIX1_GID = 0x691
    DPE_GID = 0x1008
    DPE_GID1 = 0x2008
    PREFIX_INVALID_GID = 0x202
    PREFIX_OFFSET_0_GID = 0x200
    PREFIX_OFFSET_1_GID = 0x201
    PREFIX_OFFSET_2_GID = 0x202
    PREFIX_OFFSET_3_GID = 0x203
    TE_TUNNEL1_GID = 0x391
    TE_TUNNEL2_GID = 0x491
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    INPUT_LABEL0 = sdk.la_mpls_label()
    INPUT_LABEL0.label = 0x63
    LDP_LABEL = sdk.la_mpls_label()
    LDP_LABEL.label = 0x64
    NEW_LDP_LABEL = sdk.la_mpls_label()
    NEW_LDP_LABEL.label = 0x65
    SR_LABEL0 = sdk.la_mpls_label()
    SR_LABEL0.label = 0x160
    SR_LABEL1 = sdk.la_mpls_label()
    SR_LABEL1.label = 0x161
    SR_LABEL2 = sdk.la_mpls_label()
    SR_LABEL2.label = 0x162
    SR_LABEL3 = sdk.la_mpls_label()
    SR_LABEL3.label = 0x163
    SR_LABEL4 = sdk.la_mpls_label()
    SR_LABEL4.label = 0x164
    SR_LABEL5 = sdk.la_mpls_label()
    SR_LABEL5.label = 0x165
    SR_LABEL6 = sdk.la_mpls_label()
    SR_LABEL6.label = 0x166
    SR_LABEL7 = sdk.la_mpls_label()
    SR_LABEL7.label = 0x167
    PRIMARY_TE_LABEL = sdk.la_mpls_label()
    PRIMARY_TE_LABEL.label = 0x66
    MP_LABEL = sdk.la_mpls_label()
    MP_LABEL.label = 0x67
    BACKUP_TE_LABEL = sdk.la_mpls_label()
    BACKUP_TE_LABEL.label = 0x68
    INPUT_LABEL1 = sdk.la_mpls_label()
    INPUT_LABEL1.label = 0x69
    BGP_LABEL = sdk.la_mpls_label()
    BGP_LABEL.label = 0x71
    IP6PE_LDP_LABEL = sdk.la_mpls_label()
    IP6PE_LDP_LABEL.label = 0x76
    VPN_LABEL = sdk.la_mpls_label()
    VPN_LABEL.label = 0x77
    IP6PE_VPN_LABEL = sdk.la_mpls_label()
    IP6PE_VPN_LABEL.label = 0x78
    PROTECTION_GROUP_ID1 = 0x500
    PROTECTION_GROUP_ID2 = 0x504
    IP_TTL = 0x88
    MPLS_TTL = 0xff
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    OUTPUT_VID = 0xac
    RCY_SLICE = T.get_device_slice(1)
    INJECT_UP_GID = 0x100
    MC_GID = 0x20
    TX_SVI_SYS_PORT_EXT_GID2 = 0x28
    TX_L2_AC_PORT_EXT_GID2 = 0x242
    l2_packet_count = 0

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            device.set_bool_property(sdk.la_device_property_e_ENABLE_MPLS_SR_ACCOUNTING, False)

    @classmethod
    def setUpClass(cls):
        super(mpls_headend_base_disable_mpls_sr, cls).setUpClass(
            device_config_func=mpls_headend_base_disable_mpls_sr.device_config_func)

    def setUp(self):
        super().setUp()
        self.ip_impl = self.ip_impl_class()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)
        self.egress_counter = self.device.create_counter(sdk.la_l3_protocol_e_LAST)
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.egress_counter)
        self.egress_ext_counter = self.device.create_counter(sdk.la_l3_protocol_e_LAST)
        self.l3_port_impl.tx_port_ext.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.egress_ext_counter)
        self.l2_egress_counter = self.device.create_counter(sdk.la_l3_protocol_e_LAST)
        self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l2_egress_counter)
        self.l2_ext_egress_counter = self.device.create_counter(1)
        self.topology.tx_l2_ac_port_ext.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l2_ext_egress_counter)
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        self.add_default_route()

    def add_default_route(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=0)
        self.ip_impl.add_route(
            self.topology.vrf,
            prefix,
            self.l3_port_impl.def_nh,
            mpls_headend_base_disable_mpls_sr.PRIVATE_DATA_DEFAULT)

    def set_l2_ac_vlan_tag(self, ac_port):
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = 0x8100
        eve.tag0.tci.fields.vid = self.OUTPUT_VID + 1
        ac_port.hld_obj.set_egress_vlan_edit_command(eve)
        self.l2_packet_count = 1

    def flood_setup(self):
        self.inject_up_rcy_eth_port = T.sa_ethernet_port(self, self.device, self.topology.recycle_ports[self.RCY_SLICE].sys_port)
        self.inject_up_l2ac_port = T.l2_ac_port(self, self.device, self.INJECT_UP_GID, None,
                                                self.topology.tx_switch1, self.inject_up_rcy_eth_port,
                                                T.RX_MAC, self.OUTPUT_VID, 0xABC)
        self.topology.tx_svi_ext.hld_obj.set_inject_up_source_port(self.inject_up_l2ac_port.hld_obj)
        # this setting is required for inject-up port over recycle port.
        # these 2 recycle service mapping vlans are used to recover the flood relay id.
        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 0
        ive.num_tags_to_pop = 2
        self.inject_up_l2ac_port.hld_obj.set_ingress_vlan_edit_command(ive)
        self.flood_first_serdes = T.get_device_first_serdes(T.FIRST_SERDES1 + 2)
        self.flood_last_serdes = T.get_device_last_serdes(T.LAST_SERDES1 + 2)
        self.tx_svi_eth_port_ext2 = T.ethernet_port(self, self.device, T.TX_SLICE_EXT, T.TX_IFG_EXT,
                                                    self.TX_SVI_SYS_PORT_EXT_GID2, self.flood_first_serdes, self.flood_last_serdes)
        self.tx_l2_ac_port_ext2 = T.l2_ac_port(self, self.device, self.TX_L2_AC_PORT_EXT_GID2, None,
                                               self.topology.tx_switch1, self.tx_svi_eth_port_ext2, T.RX_MAC)
        self.l2_ext2_egress_counter = self.device.create_counter(1)
        self.tx_l2_ac_port_ext2.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l2_ext2_egress_counter)

        self.mc_group = self.device.create_l2_multicast_group(self.MC_GID, sdk.la_replication_paradigm_e_EGRESS)
        sys_port1 = self.topology.tx_svi_eth_port_ext.hld_obj.get_system_port()
        self.mc_group.add(self.topology.tx_l2_ac_port_ext.hld_obj, sys_port1)
        sys_port2 = self.tx_svi_eth_port_ext2.hld_obj.get_system_port()
        self.mc_group.add(self.tx_l2_ac_port_ext2.hld_obj, sys_port2)
        self.topology.tx_switch1.hld_obj.set_flood_destination(self.mc_group)
        self.topology.tx_switch1.hld_obj.remove_mac_entry(T.NH_SVI_EXT_MAC.hld_obj)

    def _test_sr_global_per_protocol_counters(self, protocol, add_lsp_counter=False):
        nh_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp1, None)
        nh_ecmp1.add_member(self.l3_port_impl.reg_nh.hld_obj)

        pfx_obj = T.global_prefix_object(self, self.device, mpls_headend_base_disable_mpls_sr.PREFIX1_GID, nh_ecmp1)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        prefix_type = pfx_obj.hld_obj.get_prefix_type()
        self.assertEqual(prefix_type, sdk.la_prefix_object.prefix_type_e_GLOBAL)

        # Destroy the old counter set
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, None)
        self.device.destroy(self.egress_counter)

        # Create and set counter set for MPLS SR accounting
        egress_counter = self.device.create_counter(sdk.la_l3_protocol_counter_e_LAST)
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, egress_counter)

        lsp_labels = []
        lsp_counter = None
        # Create a counter-set to account for protocol
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(3)
        lsp_labels.append(self.SR_LABEL0)
        lsp_labels.append(self.SR_LABEL1)
        lsp_labels.append(self.SR_LABEL2)

        pfx_obj.hld_obj.set_global_lsp_properties(lsp_labels, lsp_counter, sdk.la_prefix_object.lsp_counter_mode_e_PER_PROTOCOL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               mpls_headend_base_disable_mpls_sr.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SR, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = lsp_counter.read(protocol, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR, byte_count)

        packet_count, byte_count = egress_counter.read(sdk.la_l3_protocol_counter_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR, byte_count)

        pfx_obj.hld_obj.clear_global_lsp_properties()

    def _test_prefix_nh_to_ip_uniform(self, add_lsp_counter=True):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)

        lsp_labels = []
        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        if(self.l3_port_impl.is_svi):
            self.set_l2_ac_vlan_tag(self.topology.tx_l2_ac_port_reg)
            self.output_packet = self.EXPECTED_OUTPUT_PACKET_IP_WITH_VLAN
        else:
            self.output_packet = self.EXPECTED_OUTPUT_PACKET_IP

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.output_packet, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.l2_egress_counter.read(self.protocol, True, True)
        self.assertEqual(packet_count, self.l2_packet_count)
        packet_count, byte_count = self.egress_counter.read(self.protocol, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.output_packet, byte_count)

        if add_lsp_counter:
            packet_count, byte_count = lsp_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.output_packet, byte_count)

    def _test_prefix_nh_to_ip_uniform_flood(self, add_lsp_counter=True):
        self.flood_setup()
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.ext_nh.hld_obj)

        lsp_labels = []
        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.ext_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        egress_packets = []
        egress_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_IP_FLOOD, 'slice': T.TX_SLICE_EXT,
                               'ifg': T.TX_IFG_EXT, 'pif': self.l3_port_impl.serdes_ext})
        egress_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_IP_FLOOD, 'slice': T.TX_SLICE_EXT,
                               'ifg': T.TX_IFG_EXT, 'pif': self.flood_first_serdes})

        U.run_and_compare_list(self, self.device, ingress_packet, egress_packets)

        packet_count, byte_count = self.l2_ext_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_IP_FLOOD, byte_count)
        packet_count, byte_count = self.l2_ext2_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_IP_FLOOD, byte_count)
        packet_count, byte_count = self.egress_ext_counter.read(self.protocol, True, True)
        self.assertEqual(packet_count, 1)
        #U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_IP_FLOOD, byte_count)

    def _test_prefix_nh_to_mpls_uniform(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)

        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        # This uses a prefix object with no associated counter. For usage of lsp counter, check ecmp test.
        pfx_obj.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels,
                                              None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS_UNIFORM, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS_UNIFORM, byte_count)
