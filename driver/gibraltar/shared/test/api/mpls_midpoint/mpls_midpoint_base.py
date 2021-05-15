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
from scapy.all import *
import sim_utils
import topology as T
import packet_test_utils as U
from sdk_test_case_base import *
import ip_test_base

U.parse_ip_after_mpls()
load_contrib('mpls')


class mpls_midpoint_base(sdk_test_case_base):
    PREFIX1_GID = 0x691
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    MPLS_TTL = 0x88
    IP_TTL = 0x90
    TE_TUNNEL1_GID = 0x391
    IMPLICIT_NULL_LABEL = sdk.la_mpls_label()
    IMPLICIT_NULL_LABEL.label = 0x3
    INPUT_LABEL = sdk.la_mpls_label()
    INPUT_LABEL.label = 0x64
    INPUT_LABEL1 = sdk.la_mpls_label()
    INPUT_LABEL1.label = 0x63
    INPUT_POP_FWD_LABEL = sdk.la_mpls_label()
    INPUT_POP_FWD_LABEL.label = 0x68
    OUTPUT_LABEL = sdk.la_mpls_label()
    OUTPUT_LABEL.label = 0xf0065
    PRIMARY_TE_LABEL = sdk.la_mpls_label()
    PRIMARY_TE_LABEL.label = OUTPUT_LABEL.label
    MP_LABEL = sdk.la_mpls_label()
    MP_LABEL.label = 0x66
    BACKUP_TE_LABEL = sdk.la_mpls_label()
    BACKUP_TE_LABEL.label = 0x67
    PROTECTION_GROUP_ID = 0x500
    PRIVATE_DATA = 0x1234567890abcdef
    OUTPUT_VID = 0xac
    RCY_SLICE = T.get_device_slice(1)
    INJECT_UP_GID = 0x100
    MC_GID = 0x20
    TX_SVI_SYS_PORT_EXT_GID2 = 0x28
    TX_L2_AC_PORT_EXT_GID2 = 0x242
    l2_packet_count = 0

    def setUp(self):
        super().setUp()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)

        # Create and set counter
        self.egress_counter = self.device.create_counter(sdk.la_l3_protocol_e_LAST)
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.egress_counter)
        self.l3_port_impl.tx_port_ext.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.egress_counter)
        self.l2_egress_counter = self.device.create_counter(sdk.la_l3_protocol_e_LAST)
        self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l2_egress_counter)
        self.l2_ext_egress_counter = self.device.create_counter(1)
        self.topology.tx_l2_ac_port_ext.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l2_ext_egress_counter)

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

        self.tx_svi_eth_port_ext2 = T.ethernet_port(self, self.device, T.TX_SLICE_EXT, T.TX_IFG_EXT,
                                                    self.TX_SVI_SYS_PORT_EXT_GID2, T.FIRST_SERDES1 + 2, T.LAST_SERDES1 + 2)
        self.tx_l2_ac_port_ext2 = T.l2_ac_port(self, self.device, self.TX_L2_AC_PORT_EXT_GID2, None,
                                               self.topology.tx_switch1, self.tx_svi_eth_port_ext2, T.RX_MAC)

        self.mc_group = self.device.create_l2_multicast_group(self.MC_GID, sdk.la_replication_paradigm_e_EGRESS)
        system_port = self.topology.tx_svi_eth_port_ext.hld_obj.get_system_port()
        self.mc_group.add(self.topology.tx_l2_ac_port_ext.hld_obj, system_port)
        system_port = self.tx_svi_eth_port_ext2.hld_obj.get_system_port()
        self.mc_group.add(self.tx_l2_ac_port_ext2.hld_obj, system_port)
        self.topology.tx_switch1.hld_obj.set_flood_destination(self.mc_group)
        self.topology.tx_switch1.hld_obj.remove_mac_entry(T.NH_SVI_EXT_MAC.hld_obj)

    def _test_add_existing_lsr_entry(self):
        nhlfe = self.device.create_mpls_swap_nhlfe(self.l3_port_impl.reg_nh.hld_obj, self.OUTPUT_LABEL)
        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        try:
            lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)
            self.assertFail()
        except sdk.BaseException:
            pass

        lsr.delete_route(self.INPUT_LABEL)
        self.device.destroy(nhlfe)

    def _test_clear_mappings(self):
        nhlfe = self.device.create_mpls_swap_nhlfe(
            self.l3_port_impl.reg_nh.hld_obj, self.OUTPUT_LABEL)
        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        info = lsr.get_route(self.INPUT_LABEL)

        lsr.clear_all_routes()

        try:
            lsr.get_route(self.INPUT_LABEL)
            self.assertFail()
        except sdk.BaseException:
            pass

        self.device.destroy(nhlfe)

    def _test_get_label_mapping(self):
        lsr = self.device.get_lsr()

        try:
            info = lsr.get_route(self.INPUT_LABEL)
            self.assertFail()
        except sdk.BaseException:
            pass

        nhlfe = self.device.create_mpls_swap_nhlfe(self.l3_port_impl.reg_nh.hld_obj, self.OUTPUT_LABEL)
        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        info = lsr.get_route(self.INPUT_LABEL)
        self.assertEqual(info.user_data, self.PRIVATE_DATA)
        self.assertEqual(info.destination.this, nhlfe.this)

        lsr.delete_route(self.INPUT_LABEL)

        try:
            info = lsr.get_route(self.INPUT_LABEL)
            self.assertFail()
        except sdk.BaseException:
            pass

        self.device.destroy(nhlfe)

    def _test_modify_label_mapping(self, disable_rx=False, disable_tx=False):
        lsr = self.device.get_lsr()

        pfx_obj = T.prefix_object(self, self.device, mpls_midpoint_base.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        lsr.add_route(self.INPUT_LABEL, pfx_obj.hld_obj, self.PRIVATE_DATA)

        # Modify the route to point to an NHLFE
        nhlfe = self.device.create_mpls_swap_nhlfe(self.l3_port_impl.reg_nh.hld_obj, self.OUTPUT_LABEL)
        self.assertNotEqual(nhlfe, None)
        lsr.modify_route(self.INPUT_LABEL, nhlfe)

        info = lsr.get_route(self.INPUT_LABEL)
        self.assertEqual(info.user_data, self.PRIVATE_DATA)
        self.assertEqual(info.destination.this, nhlfe.this)

        # Verify by sending a packet
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_SWAP_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        lsr.modify_route(self.INPUT_LABEL, pfx_obj.hld_obj)

        # Modify the route to point to a Prefix Object
        info = lsr.get_route(self.INPUT_LABEL)
        self.assertEqual(info.user_data, self.PRIVATE_DATA)
        self.assertEqual(info.destination.this, pfx_obj.hld_obj.this)

        lsp_labels = []
        lsp_labels.append(self.OUTPUT_LABEL)
        pfx_obj.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels,
                                              None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        # Verify again by sending a packet
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_SWAP_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if disable_rx:
            self.l3_port_impl.rx_port.hld_obj.disable()
            U.run_and_drop(self, self.device,
                           self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        if disable_tx:
            self.l3_port_impl.tx_port.hld_obj.disable()
            U.run_and_drop(self, self.device,
                           self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        lsr.delete_route(self.INPUT_LABEL)
        self.device.destroy(nhlfe)

    def _test_php_uniform(self, disable_rx=False, disable_tx=False):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        # TTL and QoS values are untouched for uniform mode configuration
        nhlfe = self.device.create_mpls_php_nhlfe(
            self.l3_port_impl.reg_nh.hld_obj)
        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        if (self.l3_port_impl.is_svi):
            self.set_l2_ac_vlan_tag(self.topology.tx_l2_ac_port_reg)
            self.output_packet = self.EXPECTED_OUTPUT_PHP_UNIFORM_WITH_VLAN_PACKET
        else:
            self.output_packet = self.EXPECTED_OUTPUT_PHP_UNIFORM_PACKET

        U.run_and_compare(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.output_packet, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.l2_egress_counter.read(self.protocol, True, True)
        self.assertEqual(packet_count, self.l2_packet_count)
        packet_count, byte_count = self.egress_counter.read(self.protocol, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.output_packet, byte_count)

        if disable_rx:
            self.l3_port_impl.rx_port.hld_obj.disable()
            U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        if disable_tx:
            self.l3_port_impl.tx_port.hld_obj.disable()
            U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        lsr.delete_route(self.INPUT_LABEL)
        self.device.destroy(nhlfe)

    def _test_pop_fwd_invalid_next_hdr(self):
        lsr = self.device.get_lsr()
        # Program Label to pop and fwd
        nhlfe = self.device.create_mpls_php_nhlfe(self.l3_port_impl.reg_nh.hld_obj)

        # Add POP-And-Fwd action on Input Label
        decap = lsr.add_vpn_decap(self.INPUT_LABEL, self.topology.vrf.hld_obj)

        # Add IP route action on default vrf.
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, 0x1234567890abcdef)

        # Send packet with no inner label. Should lookup on default vrf.
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def _test_pop_fwd_invalid_bos(self):
        lsr = self.device.get_lsr()
        # Program Label to pop and fwd
        nhlfe = self.device.create_mpls_php_nhlfe(self.l3_port_impl.reg_nh.hld_obj)

        # Add POP-And-Fwd action on Input Label
        decap = lsr.add_vpn_decap(self.INPUT_POP_FWD_LABEL, None)

        # Add LDP action on label as well. packet should be dropped and this action should not be applied.
        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        counter = self.device.create_counter(1)
        priority = 0
        self.device.set_trap_configuration(sdk.LA_EVENT_MPLS_UNKNOWN_PROTOCOL_AFTER_BOS,
                                           priority, counter, None, False, False, True, 0)

        input_packet = self.INPUT_PACKET_POP_FWD.copy()
        input_packet[scapy.contrib.mpls.MPLS].s = 1
        # Send packet with inner label but out label bos set. Should be dropped.
        U.run_and_drop(self, self.device, input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # test counter
        packets, bytes = counter.read(0,  # sub-counter index
                                      True,  # force_update
                                      True)  # clear_on_read
        self.assertEqual(packets, 1)

    def _test_pop_fwd_invalid_bos_and_next_hdr(self):
        lsr = self.device.get_lsr()
        # Program Label to pop and fwd
        nhlfe = self.device.create_mpls_php_nhlfe(self.l3_port_impl.reg_nh.hld_obj)

        # Add POP-And-Fwd action on Input Label
        decap = lsr.add_vpn_decap(self.INPUT_LABEL, None)

        # Add LDP action on label as well. L3VPN DB in previous API should take precedence.
        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        counter = self.device.create_counter(1)
        priority = 0
        self.device.set_trap_configuration(sdk.LA_EVENT_MPLS_UNKNOWN_PROTOCOL_AFTER_BOS,
                                           priority, counter, None, False, False, True, 0)

        input_packet = self.INPUT_PACKET.copy()
        input_packet[scapy.contrib.mpls.MPLS].s = 0
        # Send packet with single label and invalid bos. Should be dropped.
        U.run_and_drop(self, self.device, input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # test counter
        packets, bytes = counter.read(0,  # sub-counter index
                                      True,  # force_update
                                      True)  # clear_on_read
        self.assertEqual(packets, 1)

    def _test_php_uniform_pop_fwd(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        # TTL and QoS values are untouched for uniform mode configuration
        nhlfe = self.device.create_mpls_php_nhlfe(
            self.l3_port_impl.reg_nh.hld_obj)
        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        decap = lsr.add_vpn_decap(self.INPUT_POP_FWD_LABEL, None)

        if (self.l3_port_impl.is_svi):
            self.set_l2_ac_vlan_tag(self.topology.tx_l2_ac_port_reg)
            self.output_packet = self.EXPECTED_OUTPUT_PHP_UNIFORM_WITH_VLAN_POP_FWD_PACKET
        else:
            self.output_packet = self.EXPECTED_OUTPUT_PHP_UNIFORM_POP_FWD_PACKET

        U.run_and_compare(self, self.device, self.INPUT_PACKET_POP_FWD, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.output_packet, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.l2_egress_counter.read(self.protocol, True, True)
        self.assertEqual(packet_count, self.l2_packet_count)
        packet_count, byte_count = self.egress_counter.read(self.protocol, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.output_packet, byte_count)

        lsr.delete_route(self.INPUT_LABEL)
        self.device.destroy(nhlfe)

    def _test_php_uniform_flood(self):
        self.flood_setup()
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        # TTL and QoS values are untouched for uniform mode configuration
        nhlfe = self.device.create_mpls_php_nhlfe(
            self.l3_port_impl.ext_nh.hld_obj)
        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        egress_packets = []
        egress_packets.append({'data': self.EXPECTED_OUTPUT_PHP_UNIFORM_FLOOD_PACKET, 'slice': T.TX_SLICE_EXT,
                               'ifg': T.TX_IFG_EXT, 'pif': self.l3_port_impl.serdes_ext})
        egress_packets.append({'data': self.EXPECTED_OUTPUT_PHP_UNIFORM_FLOOD_PACKET, 'slice': T.TX_SLICE_EXT,
                               'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES1 + 2})

        U.run_and_compare_list(self, self.device, ingress_packet, egress_packets)

        packet_count, byte_count = self.l2_ext_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.egress_counter.read(self.protocol, True, True)
        self.assertEqual(packet_count, 1)
        #U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PHP_UNIFORM_FLOOD_PACKET, byte_count)

        lsr.delete_route(self.INPUT_LABEL)
        self.device.destroy(nhlfe)

    def _test_pop_double_label_pipe(self, disable_rx=False, disable_tx=False):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        # TTL and QoS values are untouched for uniform mode configuration
        nhlfe = self.device.create_mpls_php_nhlfe(
            self.l3_port_impl.reg_nh.hld_obj)
        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_DOUBLE_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_POP_PIPE_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_POP_PIPE_PACKET, byte_count)

        if disable_rx:
            self.l3_port_impl.rx_port.hld_obj.disable()
            U.run_and_drop(self, self.device,
                           self.INPUT_PACKET_DOUBLE_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        if disable_tx:
            self.l3_port_impl.tx_port.hld_obj.disable()
            U.run_and_drop(self, self.device,
                           self.INPUT_PACKET_DOUBLE_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        lsr.delete_route(self.INPUT_LABEL)
        self.device.destroy(nhlfe)

    def _test_pop_double_label_pipe_flood(self):
        self.flood_setup()
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        # TTL and QoS values are untouched for uniform mode configuration
        nhlfe = self.device.create_mpls_php_nhlfe(
            self.l3_port_impl.ext_nh.hld_obj)
        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        ingress_packet = {'data': self.INPUT_PACKET_DOUBLE_LABEL, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        egress_packets = []
        egress_packets.append({'data': self.EXPECTED_OUTPUT_POP_PIPE_FLOOD_PACKET, 'slice': T.TX_SLICE_EXT,
                               'ifg': T.TX_IFG_EXT, 'pif': self.l3_port_impl.serdes_ext})
        egress_packets.append({'data': self.EXPECTED_OUTPUT_POP_PIPE_FLOOD_PACKET, 'slice': T.TX_SLICE_EXT,
                               'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES1 + 2})

        U.run_and_compare_list(self, self.device, ingress_packet, egress_packets)

        packet_count, byte_count = self.l2_ext_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        #U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_POP_PIPE_FLOOD_PACKET, byte_count)

        lsr.delete_route(self.INPUT_LABEL)
        self.device.destroy(nhlfe)

    def _test_pop_double_label_uniform_1(self, disable_rx=False, disable_tx=False):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        # TTL and QoS values are untouched for uniform mode configuration
        nhlfe = self.device.create_mpls_php_nhlfe(
            self.l3_port_impl.reg_nh.hld_obj)
        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_DOUBLE_LABEL_1, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_POP_PIPE_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_POP_PIPE_PACKET, byte_count)

        if disable_rx:
            self.l3_port_impl.rx_port.hld_obj.disable()
            U.run_and_drop(self, self.device,
                           self.INPUT_PACKET_DOUBLE_LABEL_1, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        if disable_tx:
            self.l3_port_impl.tx_port.hld_obj.disable()
            U.run_and_drop(self, self.device,
                           self.INPUT_PACKET_DOUBLE_LABEL_1, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        lsr.delete_route(self.INPUT_LABEL)
        self.device.destroy(nhlfe)

    def _test_pop_double_label_uniform_2(self, disable_rx=False, disable_tx=False):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        # TTL and QoS values are untouched for uniform mode configuration
        nhlfe = self.device.create_mpls_php_nhlfe(
            self.l3_port_impl.reg_nh.hld_obj)
        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_DOUBLE_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_POP_UNIFORM_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_POP_UNIFORM_PACKET, byte_count)

        if disable_rx:
            self.l3_port_impl.rx_port.hld_obj.disable()
            U.run_and_drop(self, self.device,
                           self.INPUT_PACKET_DOUBLE_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        if disable_tx:
            self.l3_port_impl.tx_port.hld_obj.disable()
            U.run_and_drop(self, self.device,
                           self.INPUT_PACKET_DOUBLE_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        lsr.delete_route(self.INPUT_LABEL)
        self.device.destroy(nhlfe)

    def _test_remove_busy_nhlfe(self):
        nhlfe = self.device.create_mpls_swap_nhlfe(
            self.l3_port_impl.reg_nh.hld_obj, self.OUTPUT_LABEL)
        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        try:
            self.device.destroy(nhlfe)
            self.assertFail()
        except sdk.BaseException:
            pass

        lsr.delete_route(self.INPUT_LABEL)

    def _test_swap_pop_fwd(self):
        nhlfe = self.device.create_mpls_swap_nhlfe(self.l3_port_impl.reg_nh.hld_obj, self.OUTPUT_LABEL)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)
        decap = lsr.add_vpn_decap(self.INPUT_POP_FWD_LABEL, None)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_POP_FWD, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_SWAP_POP_FWD_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET, T.RX_SLICE)
        self.assertEqual(expected_bytes, expected_bytes)

        lsr.delete_route(self.INPUT_LABEL)

    def _test_swap_pop_fwd_with_l3vpn_decap(self):
        nhlfe = self.device.create_mpls_swap_nhlfe(self.l3_port_impl.reg_nh.hld_obj, self.OUTPUT_LABEL)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)
        decap = lsr.add_vpn_decap(self.INPUT_POP_FWD_LABEL, self.topology.vrf.hld_obj)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_POP_FWD, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_SWAP_POP_FWD_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET, T.RX_SLICE)
        self.assertEqual(expected_bytes, expected_bytes)

        lsr.delete_route(self.INPUT_LABEL)

    def _test_swap(self, disable_rx=False, disable_tx=False):
        nhlfe = self.device.create_mpls_swap_nhlfe(self.l3_port_impl.reg_nh.hld_obj, self.OUTPUT_LABEL)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_SWAP_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET, T.RX_SLICE)
        self.assertEqual(expected_bytes, expected_bytes)

        if disable_rx:
            self.l3_port_impl.rx_port.hld_obj.disable()
            U.run_and_drop(self, self.device,
                           self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        if disable_tx:
            self.l3_port_impl.tx_port.hld_obj.disable()
            U.run_and_drop(self, self.device,
                           self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        lsr.delete_route(self.INPUT_LABEL)

    def _test_swap_double_label(self, disable_rx=False, disable_tx=False):
        nhlfe = self.device.create_mpls_swap_nhlfe(self.l3_port_impl.reg_nh.hld_obj, self.OUTPUT_LABEL)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_DOUBLE_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_SWAP_PACKET_DOUBLE_LABEL, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_SWAP_PACKET_DOUBLE_LABEL, byte_count)

        if disable_rx:
            self.l3_port_impl.rx_port.hld_obj.disable()
            U.run_and_drop(self, self.device,
                           self.INPUT_PACKET_DOUBLE_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        if disable_tx:
            self.l3_port_impl.tx_port.hld_obj.disable()
            U.run_and_drop(self, self.device, self.INPUT_PACKET_DOUBLE_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        lsr.delete_route(self.INPUT_LABEL)
        self.device.destroy(nhlfe)

    def _test_swap_with_vlan(self, disable_rx=False, disable_tx=False):
        tag = sdk.la_vlan_tag_t()
        tag.tpid = 0x8100
        tag.tci.fields.pcp = 0
        tag.tci.fields.dei = 0
        tag.tci.fields.vid = self.OUTPUT_VID

        self.l3_port_impl.tx_port.hld_obj.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)

        nhlfe = self.device.create_mpls_swap_nhlfe(self.l3_port_impl.reg_nh.hld_obj, self.OUTPUT_LABEL)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_SWAP_PACKET_WITH_VLAN, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_SWAP_PACKET_WITH_VLAN, byte_count)

        if disable_rx:
            self.l3_port_impl.rx_port.hld_obj.disable()
            U.run_and_drop(self, self.device,
                           self.INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        if disable_tx:
            self.l3_port_impl.tx_port.hld_obj.disable()
            U.run_and_drop(self, self.device,
                           self.INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_te_midpoint_backup(self, add_lsp_counter=True):
        prot_monitor = T.protection_monitor(self, self.device)

        te_tunnel = T.te_tunnel(self, self.device, mpls_midpoint_base.TE_TUNNEL1_GID, self.l3_port_impl.ext_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.BACKUP_TE_LABEL)
        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, te_labels, te_counter)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            te_tunnel.hld_obj,
            prot_monitor.hld_obj)

        lsr = self.device.get_lsr()

        nhlfe = self.device.create_mpls_tunnel_protection_nhlfe(l3_prot_group.hld_obj, self.PRIMARY_TE_LABEL, self.MP_LABEL)

        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        prot_monitor.hld_obj.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TE_BACKUP, T.TX_SLICE_EXT, T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE_BACKUP, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE_BACKUP, byte_count)

        lsr.delete_route(self.INPUT_LABEL)
        self.device.destroy(nhlfe)

        # Merge Point Label is Implicit-Null
        nhlfe = self.device.create_mpls_tunnel_protection_nhlfe(
            l3_prot_group.hld_obj, self.PRIMARY_TE_LABEL, self.IMPLICIT_NULL_LABEL)

        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TE_BACKUP_MP_NULL, T.TX_SLICE_EXT, T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE_BACKUP_MP_NULL, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE_BACKUP_MP_NULL, byte_count)

        lsr.delete_route(self.INPUT_LABEL)
        self.device.destroy(nhlfe)

        # Backup Label is Implicit-Null
        te_labels = []
        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, te_labels, te_counter)

        nhlfe = self.device.create_mpls_tunnel_protection_nhlfe(l3_prot_group.hld_obj, self.PRIMARY_TE_LABEL, self.MP_LABEL)

        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        prot_monitor.hld_obj.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_TE_BACKUP_BACKUP_NULL,
            T.TX_SLICE_EXT,
            T.TX_IFG_EXT,
            self.l3_port_impl.serdes_ext)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE_BACKUP_BACKUP_NULL, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE_BACKUP_BACKUP_NULL, byte_count)

        lsr.delete_route(self.INPUT_LABEL)
        self.device.destroy(nhlfe)

    def _test_te_midpoint_primary(self, add_lsp_counter=True):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        prot_monitor = T.protection_monitor(self, self.device)

        te_tunnel = T.te_tunnel(self, self.device, mpls_midpoint_base.TE_TUNNEL1_GID, self.l3_port_impl.ext_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.BACKUP_TE_LABEL)
        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, te_labels, te_counter)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            te_tunnel.hld_obj,
            prot_monitor.hld_obj)

        lsr = self.device.get_lsr()

        # Primary TE Label is Valid
        nhlfe = self.device.create_mpls_tunnel_protection_nhlfe(l3_prot_group.hld_obj, self.PRIMARY_TE_LABEL, self.MP_LABEL)

        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_SWAP_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_SWAP_PACKET, byte_count)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_DOUBLE_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_SWAP_PACKET_DOUBLE_LABEL, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_SWAP_PACKET_DOUBLE_LABEL, byte_count)

        lsr.delete_route(self.INPUT_LABEL)
        self.device.destroy(nhlfe)

        # Primary TE Label is Implicit-Null
        nhlfe = self.device.create_mpls_tunnel_protection_nhlfe(l3_prot_group.hld_obj, self.IMPLICIT_NULL_LABEL, self.MP_LABEL)

        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PHP_UNIFORM_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if (self.l3_port_impl.is_svi):
            packet_count, byte_count = self.l2_egress_counter.read(self.protocol, True, True)
            self.assertEqual(packet_count, 1)

        packet_count, byte_count = self.egress_counter.read(self.protocol, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PHP_UNIFORM_PACKET, byte_count)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_DOUBLE_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_POP_UNIFORM_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_POP_UNIFORM_PACKET, byte_count)
