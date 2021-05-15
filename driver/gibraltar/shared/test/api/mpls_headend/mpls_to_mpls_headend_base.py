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
from mpls_headend_base import *
import decor

U.parse_ip_after_mpls()


class mpls_to_mpls_headend_base(sdk_test_case_base):
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
    INPUT_LABEL2 = sdk.la_mpls_label()
    INPUT_LABEL2.label = 0x61
    INPUT_LABEL3 = sdk.la_mpls_label()
    INPUT_LABEL3.label = 0x7
    INPUT_LABEL4 = sdk.la_mpls_label()
    INPUT_LABEL4.label = 0x59
    INPUT_LABEL5 = sdk.la_mpls_label()
    INPUT_LABEL5.label = 0x58
    INPUT_LABEL6 = sdk.la_mpls_label()
    INPUT_LABEL6.label = 0x57
    INPUT_LABEL7 = sdk.la_mpls_label()
    INPUT_LABEL7.label = 0x56
    INPUT_LABEL8 = sdk.la_mpls_label()
    INPUT_LABEL8.label = 0x55
    INPUT_LABEL9 = sdk.la_mpls_label()
    INPUT_LABEL9.label = 0x54
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
    PAYLOAD_SIZE = 40
    l2_packet_count = 0

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            device.set_bool_property(sdk.la_device_property_e_ENABLE_MPLS_SR_ACCOUNTING, True)

    @classmethod
    def setUpClass(cls):
        super(mpls_to_mpls_headend_base, cls).setUpClass(device_config_func=mpls_to_mpls_headend_base.device_config_func)

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

    def _test_bgp_lu_dpe_ecmp_asbr_lsp_to_mpls(self, enable_ldp):
        # Create the ASBR
        asbr1 = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        # Program the LDP labels first
        if (enable_ldp is True):
            lsp_labels = []
            lsp_labels.append(self.LDP_LABEL)
            asbr1.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels,
                                                None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        else:
            asbr1.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, [], None,
                                                sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        # Create the Label Switched Path to reach the ASBR
        asbr_lsp1 = T.asbr_lsp(
            self,
            self.device,
            asbr1.hld_obj,
            self.l3_port_impl.reg_nh.hld_obj)

        # Create an ECMP group and add the ASBR LSP as a member
        asbr_lsp_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(asbr_lsp_ecmp, None)
        asbr_lsp_ecmp.add_member(asbr_lsp1.hld_obj)

        # Create the Destination PE
        dpe = T.destination_pe(self, self.device, self.DPE_GID, asbr_lsp_ecmp)

        asbr_labels = []
        asbr_labels.append(self.BGP_LABEL)

        # Program the BGP labels
        dpe.hld_obj.set_asbr_properties(asbr1.hld_obj, asbr_labels)

        # Rewrite the asbr label stack
        dpe.hld_obj.set_asbr_properties(asbr1.hld_obj, asbr_labels)

        # Program the route for the incoming label
        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, dpe.hld_obj, self.PRIVATE_DATA)

        if (enable_ldp is True):
            U.run_and_compare(self, self.device,
                              self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                              self.EXPECTED_OUTPUT_BGP_LU_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
            packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_BGP_LU_PACKET, byte_count)

        else:
            U.run_and_compare(self, self.device,
                              self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                              self.EXPECTED_OUTPUT_BGP_LU_NO_LDP_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

            packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_BGP_LU_NO_LDP_PACKET, byte_count)

        # Cleanup the objects
        lsr.delete_route(self.INPUT_LABEL0)
        dpe.hld_obj.clear_asbr_properties(asbr1.hld_obj)
        dpe.destroy()
        self.device.destroy(asbr_lsp_ecmp)
        asbr_lsp1.destroy()
        asbr1.destroy()

    def _test_bgp_lu_dpe_ecmp_asbr_lsp_prot_group_to_mpls(self):
        # Create the ASBR
        asbr0 = T.prefix_object(self, self.device, self.PREFIX0_GID, self.l3_port_impl.reg_nh.hld_obj)

        # Update the LDP labels for the Primary and Backup paths
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)
        asbr0.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels, None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        asbr0.hld_obj.set_nh_lsp_properties(self.l3_port_impl.def_nh.hld_obj, lsp_labels, None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        asbr0.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, lsp_labels, None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prot_monitor = T.protection_monitor(self, self.device)

        # Create Protection group
        # Primary - reg_nh
        # Backup - ext_nh
        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor.hld_obj)

        # Create the ASBR LSP with the destination as the Protection group
        asbr_lsp_prot_group = T.asbr_lsp(self, self.device, asbr0.hld_obj,
                                         l3_prot_group.hld_obj)

        # Create an ECMP group and add the ASBR LSP as a member
        asbr_lsp_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(asbr_lsp_ecmp, None)
        asbr_lsp_ecmp.add_member(asbr_lsp_prot_group.hld_obj)

        # Create the Destination PE
        dpe = T.destination_pe(self, self.device, self.DPE_GID, asbr_lsp_ecmp)

        # Set the initial ASBR label
        asbr_labels = []
        asbr_labels.append(self.BGP_LABEL)

        dpe.hld_obj.set_asbr_properties(asbr0.hld_obj, asbr_labels)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, dpe.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_BGP_LU_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_BGP_LU_PACKET, byte_count)

        # Cleanup the objects
        lsr.delete_route(self.INPUT_LABEL0)
        dpe.hld_obj.clear_asbr_properties(asbr0.hld_obj)
        dpe.destroy()
        self.device.destroy(asbr_lsp_ecmp)
        asbr_lsp_prot_group.destroy()
        l3_prot_group.destroy()
        asbr0.destroy()

    def _test_vpn_on_csc_pe_with_1_label(self):
        # Create the Prefix object representing the PE
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)

        # Set the LDP labels
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)
        pfx_obj.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels, None,
                                              sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        m_ecmp_rec = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.assertNotEqual(m_ecmp_rec, None)
        m_ecmp_rec.add_member(pfx_obj.hld_obj)

        # Set the VPN labels
        vpn_labels = []
        vpn_labels.append(self.VPN_LABEL)

        # On the CsC PE, the incoming packet is a MPLS packet. VPN labels are
        # enabled for the VRF on the CsC interface and should be imposed on the
        # outgoing MPLS packet
        pfx_obj.hld_obj.set_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV4, vpn_labels)

        # Program the route for the incoming label
        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, m_ecmp_rec, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_VPN_CSC_PE_PACKET1, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_VPN_CSC_PE_PACKET1, byte_count)

    def _test_vpn_on_csc_pe_with_2_labels(self):
        # Create the Prefix object representing the PE
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)

        # Set the LDP labels
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)
        pfx_obj.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels, None,
                                              sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        m_ecmp_rec = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.assertNotEqual(m_ecmp_rec, None)
        m_ecmp_rec.add_member(pfx_obj.hld_obj)

        # Set the VPN labels
        vpn_labels = []
        vpn_labels.append(self.VPN_LABEL)

        # On the CsC PE, the incoming packet is a MPLS packet. VPN labels are
        # enabled for the VRF on the CsC interface and should be imposed on the
        # outgoing MPLS packet
        pfx_obj.hld_obj.set_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV4, vpn_labels)

        # Program the route for the incoming label
        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, m_ecmp_rec, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_DOUBLE_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_VPN_CSC_PE_PACKET2, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_VPN_CSC_PE_PACKET2, byte_count)

    def _test_bgp_lu_dpe_ecmp_asbr_lsp_drop_nh(self):
        # Set the NH type to a DROP NH
        self.l3_port_impl.reg_nh.hld_obj.set_nh_type(sdk.la_next_hop.nh_type_e_DROP)

        # Create the ASBR
        asbr1 = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        asbr1.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, [], None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        # Create the Label Switched Path to reach the ASBR
        asbr_lsp1 = T.asbr_lsp(
            self,
            self.device,
            asbr1.hld_obj,
            self.l3_port_impl.reg_nh.hld_obj)

        # Create an ECMP group and add the ASBR LSP as a member
        asbr_lsp_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(asbr_lsp_ecmp, None)
        asbr_lsp_ecmp.add_member(asbr_lsp1.hld_obj)

        # Create the Destination PE
        dpe = T.destination_pe(self, self.device, self.DPE_GID, asbr_lsp_ecmp)

        asbr_labels = []
        asbr_labels.append(self.BGP_LABEL)

        # Program the BGP labels
        dpe.hld_obj.set_asbr_properties(asbr1.hld_obj, asbr_labels)

        # Rewrite the asbr label stack
        dpe.hld_obj.set_asbr_properties(asbr1.hld_obj, asbr_labels)

        # Program the route for the incoming label
        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, dpe.hld_obj, self.PRIVATE_DATA)

        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Cleanup the objects
        lsr.delete_route(self.INPUT_LABEL0)
        dpe.hld_obj.clear_asbr_properties(asbr1.hld_obj)
        dpe.destroy()
        self.device.destroy(asbr_lsp_ecmp)
        asbr_lsp1.destroy()
        asbr1.destroy()

    def _test_bgp_lu_transit_asbr_with_vpn(self):
        # Create the ASBR
        asbr1 = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        asbr1.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, [], None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        # Create the Label Switched Path to reach the ASBR
        asbr_lsp1 = T.asbr_lsp(
            self,
            self.device,
            asbr1.hld_obj,
            self.l3_port_impl.reg_nh.hld_obj)

        # Create an ECMP group and add the ASBR LSP as a member
        asbr_lsp_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(asbr_lsp_ecmp, None)
        asbr_lsp_ecmp.add_member(asbr_lsp1.hld_obj)

        # Create the Destination PE
        dpe = T.destination_pe(self, self.device, self.DPE_GID, asbr_lsp_ecmp)

        asbr_labels = []
        asbr_labels.append(self.BGP_LABEL)

        # Program the BGP labels
        dpe.hld_obj.set_asbr_properties(asbr1.hld_obj, asbr_labels)

        # Rewrite the asbr label stack
        dpe.hld_obj.set_asbr_properties(asbr1.hld_obj, asbr_labels)

        # Set the VPN labels
        vpn_labels = []
        vpn_labels.append(self.VPN_LABEL)

        # Associate the VPN labels with VRF2 (any VRF) and enable the VPN
        # labels for the dpe. Enabling VPN functionality should not affect the
        # transit traffic on the Global VRF
        dpe.hld_obj.set_vrf_properties(self.topology.vrf2.hld_obj, sdk.la_ip_version_e_IPV4, vpn_labels)

        # Program the route for the incoming label
        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, dpe.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_GLOBAL_VRF, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3,
                          self.EXPECTED_OUTPUT_BGP_LU_NO_LDP_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_BGP_LU_NO_LDP_PACKET, byte_count)

    def _test_ecmp_swap(self, add_lsp_counter=True, add_dm_counter=False):
        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(self.l3_port_impl.reg_nh.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, nh_ecmp)

        lsp_counter = None
        counter_mode = sdk.la_prefix_object.lsp_counter_mode_e_LABEL

        if add_dm_counter:
            self.topology.rx_eth_port.hld_obj.set_traffic_matrix_interface_type(sdk.la_ethernet_port.traffic_matrix_type_e_EXTERNAL)
            lsp_counter = self.device.create_counter(2)
            counter_mode = sdk.la_prefix_object.lsp_counter_mode_e_TRAFFIC_MATRIX

        elif add_lsp_counter:
            lsp_counter = self.device.create_counter(1)
        lsp_labels = []
        lsp_labels.append(self.OUTPUT_LABEL0)
        pfx_obj.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels, lsp_counter, counter_mode)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_SWAP_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_ext)

        if add_dm_counter:
            packet_count, byte_count = lsp_counter.read(1, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_SWAP_PACKET, byte_count)

        elif add_lsp_counter:
            packet_count, byte_count = lsp_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_SWAP_PACKET, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_SWAP_PACKET, byte_count)

    def _test_prefix_global_ecmp_swap(self, add_lsp_counter=True):
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
        lsp_labels.append(self.OUTPUT_LABEL0)
        pfx_obj.hld_obj.set_global_lsp_properties(lsp_labels, lsp_counter, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_SWAP_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = egress_counter.read(sdk.la_l3_protocol_counter_e_MPLS_SR, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_SWAP_PACKET, byte_count)

    def _test_prefix_global_ecmp_multiple_labels(self, add_lsp_counter=True):
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
        lsp_labels.append(self.OUTPUT_LABEL0)
        lsp_labels.append(self.OUTPUT_LABEL1)
        lsp_labels.append(self.OUTPUT_LABEL2)
        pfx_obj.hld_obj.set_global_lsp_properties(lsp_labels, lsp_counter, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_WITH_EXP, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = egress_counter.read(sdk.la_l3_protocol_counter_e_MPLS_SR, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET, byte_count)

    def _test_sr_global_per_protocol_counters(self, protocol, add_lsp_counter=True):
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
            lsp_counter = self.device.create_counter(2)
        lsp_labels = []
        lsp_labels.append(self.OUTPUT_LABEL0)
        lsp_labels.append(self.OUTPUT_LABEL1)
        lsp_labels.append(self.OUTPUT_LABEL2)
        pfx_obj.hld_obj.set_global_lsp_properties(lsp_labels, lsp_counter, sdk.la_prefix_object.lsp_counter_mode_e_PER_PROTOCOL)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_WITH_EXP, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = lsp_counter.read(protocol, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET, byte_count)

        packet_count, byte_count = egress_counter.read(sdk.la_l3_protocol_counter_e_MPLS_SR, True, True)
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

    def _test_swap(self, add_lsp_counter=True, add_dm_counter=False):
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)

        lsp_counter = None
        counter_mode = sdk.la_prefix_object.lsp_counter_mode_e_LABEL

        if add_dm_counter:
            self.topology.rx_eth_port.hld_obj.set_traffic_matrix_interface_type(sdk.la_ethernet_port.traffic_matrix_type_e_EXTERNAL)
            lsp_counter = self.device.create_counter(2)
            counter_mode = sdk.la_prefix_object.lsp_counter_mode_e_TRAFFIC_MATRIX

        elif add_lsp_counter:
            lsp_counter = self.device.create_counter(1)

        lsp_labels = []
        lsp_labels.append(self.OUTPUT_LABEL0)

        pfx_obj.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels, lsp_counter, counter_mode)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_SWAP_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.ingress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET, T.RX_SLICE)
        self.assertEqual(expected_bytes, expected_bytes)

        if add_dm_counter:
            packet_count, byte_count = lsp_counter.read(1, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_SWAP_PACKET, byte_count)

        elif add_lsp_counter:
            packet_count, byte_count = lsp_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_SWAP_PACKET, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_SWAP_PACKET, byte_count)

    def _test_prefix_global_php_ecmp_uniform(self, add_lsp_counter=True):
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

        packet_count, byte_count = egress_counter.read(sdk.la_l3_protocol_counter_e_MPLS_SR, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PHP_UNIFORM_PACKET, byte_count)

    def _test_swap_double_label(self, add_lsp_counter=True):
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)

        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)
        lsp_labels = []
        lsp_labels.append(self.OUTPUT_LABEL0)

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_DOUBLE_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_SWAP_PACKET_DOUBLE_LABEL, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_SWAP_PACKET_DOUBLE_LABEL, byte_count)

    def _test_swap_with_vlan(self, add_lsp_counter=True):
        tag = sdk.la_vlan_tag_t()
        tag.tpid = 0x8100
        tag.tci.fields.pcp = 0
        tag.tci.fields.dei = 0
        tag.tci.fields.vid = self.OUTPUT_VID

        self.l3_port_impl.tx_port.hld_obj.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)

        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)
        lsp_labels = []
        lsp_labels.append(self.OUTPUT_LABEL0)

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_SWAP_PACKET_WITH_VLAN, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_SWAP_PACKET_WITH_VLAN, byte_count)

    def _test_php_uniform(self, add_lsp_counter=True, add_dm_counter=False):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        lsp_counter = None
        counter_mode = sdk.la_prefix_object.lsp_counter_mode_e_LABEL

        if add_dm_counter:
            self.topology.rx_eth_port.hld_obj.set_traffic_matrix_interface_type(sdk.la_ethernet_port.traffic_matrix_type_e_EXTERNAL)
            lsp_counter = self.device.create_counter(2)
            counter_mode = sdk.la_prefix_object.lsp_counter_mode_e_TRAFFIC_MATRIX
        elif add_lsp_counter:
            lsp_counter = self.device.create_counter(1)
        lsp_labels = []

        pfx_obj.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels, lsp_counter, counter_mode)

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

        if add_dm_counter:
            packet_count, byte_count = lsp_counter.read(1, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PHP_UNIFORM_PACKET, byte_count)
        elif add_lsp_counter:
            packet_count, byte_count = lsp_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.output_packet, byte_count)

    def _test_add_existing_lsr_entry(self):
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        self.assertNotEqual(pfx_obj.hld_obj, None)
        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        try:
            lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)
            self.assertFail()
        except sdk.BaseException:
            pass

    def _test_bgp_lu_error_handling(self):
        # Create the ASBR
        pfx_obj_16b_gid = T.prefix_object(self, self.device, self.PREFIX_16b_GID, self.l3_port_impl.reg_nh.hld_obj)
        asbr0 = T.prefix_object(self, self.device, self.PREFIX0_GID, self.l3_port_impl.reg_nh.hld_obj)
        asbr1 = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        # Set the LDP properties for asbr0
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)
        asbr0.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels, None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        asbr0.hld_obj.set_nh_lsp_properties(self.l3_port_impl.def_nh.hld_obj, lsp_labels, None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        asbr1.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels, None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        # Create the Label Switched Path to reach the ASBR
        asbr_lsp0 = T.asbr_lsp(
            self,
            self.device,
            asbr0.hld_obj,
            self.l3_port_impl.reg_nh.hld_obj)

        asbr_lsp1 = T.asbr_lsp(
            self,
            self.device,
            asbr1.hld_obj,
            self.l3_port_impl.reg_nh.hld_obj)

        asbr_lsp2 = T.asbr_lsp(
            self,
            self.device,
            asbr0.hld_obj,
            self.l3_port_impl.def_nh.hld_obj)

        # Test 1: Creating a ASBR Label Switched Path with an ASBR GID value >
        # 15b should not be permitted
        # the 15b limitation is relevant to pacific only
        if self.device.get_ll_device().is_pacific():
            with self.assertRaises(sdk.InvalException):
                asbr_lsp_test = T.asbr_lsp(
                    self,
                    self.device,
                    pfx_obj_16b_gid.hld_obj,
                    self.l3_port_impl.reg_nh.hld_obj)

        # Test 2: Creating a new lsp with the same pair of objects should not be permitted
        with self.assertRaises(sdk.ExistException):
            asbr_lsp_test = T.asbr_lsp(self, self.device, asbr0.hld_obj, self.l3_port_impl.reg_nh.hld_obj)

        # Test 3: Creating a new lsp with a different pair of objects should be permitted
        asbr0.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, [], None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        asbr_lsp_ext_nh = T.asbr_lsp(self, self.device, asbr0.hld_obj, self.l3_port_impl.ext_nh.hld_obj)
        # Test 4: Cannot add a member which is not an ASBR LSP to an ECMP group which
        # has ASBR LSPs
        asbr_lsp_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(asbr_lsp_ecmp, None)
        asbr_lsp_ecmp.add_member(asbr_lsp0.hld_obj)
        with self.assertRaises(sdk.InvalException):
            asbr_lsp_ecmp.add_member(self.l3_port_impl.def_nh.hld_obj)

        # Test 5: Cannot create an ASBR LSP with a destination which is not an
        # NH or Protection Group.
        with self.assertRaises(sdk.InvalException):
            asbr_lsp_test = T.asbr_lsp(
                self,
                self.device,
                asbr0.hld_obj,
                None)

        te_tunnel = T.te_tunnel(self, self.device, mpls_headend_base.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        with self.assertRaises(sdk.NotImplementedException):
            asbr_lsp_test = T.asbr_lsp(self, self.device, asbr0.hld_obj, te_tunnel.hld_obj)

        # Test 6: If ASBR LSP destination is being updated, the destination can
        # only be set to a NH or a L3 Protection group
        with self.assertRaises(sdk.NotImplementedException):
            asbr_lsp_ext_nh.hld_obj.set_destination(te_tunnel.hld_obj)

        # Test 7: If ASBR LSP destination is a L3 Protection Group, the backup
        # destination of the L3 Protection group can only be a NH
        prot_monitor = T.protection_monitor(self, self.device)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            te_tunnel.hld_obj,
            prot_monitor.hld_obj)

        with self.assertRaises(sdk.NotImplementedException):
            asbr_lsp_test = T.asbr_lsp(self, self.device, asbr0.hld_obj, l3_prot_group.hld_obj)

        # Test 8: If ASBR LSP destination is being updated to a L3 Protection
        # Group, the backup destination of the L3 Protection group can only be
        # a NH
        with self.assertRaises(sdk.NotImplementedException):
            asbr_lsp_ext_nh.hld_obj.set_destination(l3_prot_group.hld_obj)

        l3_prot_group.destroy()

        # Test 9: If ASBR LSP destination is a L3 Protection Group, the backup
        # destination of the L3 Protection group cannot be updaetd to be a
        # TE_TUNNEL

        l3_prot_group = T.l3_protection_group(self, self.device,
                                              self.PROTECTION_GROUP_ID,
                                              self.l3_port_impl.reg_nh.hld_obj,
                                              self.l3_port_impl.ext_nh.hld_obj,
                                              prot_monitor.hld_obj)

        asbr0.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, [], None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        asbr0.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, [], None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        asbr_lsp_prot_group = T.asbr_lsp(self, self.device, asbr0.hld_obj,
                                         l3_prot_group.hld_obj)

        with self.assertRaises(sdk.InvalException):
            l3_prot_group.hld_obj.modify_protection_group(self.l3_port_impl.reg_nh.hld_obj,
                                                          te_tunnel.hld_obj, prot_monitor.hld_obj)

        # Test 10: Cannot create a destination PE whose destination is not a
        # Stage 2 ECMP group.
        with self.assertRaises(sdk.InvalException):
            dpe0 = T.destination_pe(self, self.device, self.DPE_GID, te_tunnel.hld_obj)

        bgp_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.assertNotEqual(bgp_ecmp, None)

        with self.assertRaises(sdk.InvalException):
            dpe0 = T.destination_pe(self, self.device, self.DPE_GID, bgp_ecmp)

        # Test 11: Cannot create a destination PE whose destination is a Stage
        # 2 ECMP group but with members other than ASBR LSPs.
        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(self.l3_port_impl.reg_nh.hld_obj)

        with self.assertRaises(sdk.InvalException):
            dpe0 = T.destination_pe(self, self.device, self.DPE_GID, nh_ecmp)

        # Test 12: Cannot update the destination of DPE to something other than
        # a Stage 2 ECMP group.
        dpe1 = T.destination_pe(self, self.device, self.DPE_GID1, asbr_lsp_ecmp)

        with self.assertRaises(sdk.InvalException):
            dpe1.hld_obj.set_destination(te_tunnel.hld_obj)

        # Test 13: Cannot update the destination of DPE to a Stage 2 ECMP group
        # but with members other than ASBR LSPs.
        with self.assertRaises(sdk.InvalException):
            dpe1.hld_obj.set_destination(nh_ecmp)

        # Test 14: Updating an ASBR Label Switched Path with an ASBR GID value
        # > 15b should not be permitted
        if self.device.get_ll_device().is_pacific():
            with self.assertRaises(sdk.InvalException):
                asbr_lsp0.hld_obj.set_asbr(pfx_obj_16b_gid.hld_obj)

        # Test 15: Updating ASBR of an ASBR LSP with an existing pair of
        # objects should not be permitted
        with self.assertRaises(sdk.ExistException):
            asbr_lsp0.hld_obj.set_asbr(asbr1.hld_obj)

        # Test 16: Updating destination of an ASBR LSP with an existing pair of
        # objects should not be permitted
        with self.assertRaises(sdk.ExistException):
            asbr_lsp0.hld_obj.set_destination(self.l3_port_impl.def_nh.hld_obj)

        # Test 17: LDP properties cannot be cleared until the ASBR LSPs using
        # the NH as a path to the ASBR are all destroyed
        with self.assertRaises(sdk.BusyException):
            asbr1.hld_obj.clear_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj)

        # Test 18: LDP properties can be cleared after the all ASBR LSPs using
        # the NH as a path to the ASBR are destroyed
        asbr_lsp1.destroy()
        asbr1.hld_obj.clear_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj)

        # Test 19: Cannot add an ASBR LSP as a member to a ECMP group which
        # has NHs
        with self.assertRaises(sdk.InvalException):
            nh_ecmp.add_member(asbr_lsp0.hld_obj)

    def _test_bgp_lu_update_asbr_lsp_asbr(self):
        # Create the ASBR
        asbr0 = T.prefix_object(self, self.device, self.PREFIX0_GID, self.l3_port_impl.reg_nh.hld_obj)
        asbr0.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, [], None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        # Create the Label Switched Path to reach the ASBR
        asbr_lsp0 = T.asbr_lsp(
            self,
            self.device,
            asbr0.hld_obj,
            self.l3_port_impl.reg_nh.hld_obj)

        # Create an ECMP group and add the ASBR LSP as a member
        asbr_lsp_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(asbr_lsp_ecmp, None)
        asbr_lsp_ecmp.add_member(asbr_lsp0.hld_obj)

        # Create the Destination PE
        dpe = T.destination_pe(self, self.device, self.DPE_GID, asbr_lsp_ecmp)

        # Set the initial ASBR label
        asbr_labels = []
        asbr_labels.append(self.BGP_LABEL)

        dpe.hld_obj.set_asbr_properties(asbr0.hld_obj, asbr_labels)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, dpe.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_BGP_LU_NO_LDP_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_BGP_LU_NO_LDP_PACKET, byte_count)

        # Verify the ASBR LSP
        asbr_lsp_by_asbr_nh = self.device.get_asbr_lsp(asbr0.hld_obj, self.l3_port_impl.reg_nh.hld_obj)
        self.assertEqual(asbr_lsp_by_asbr_nh.this, asbr_lsp0.hld_obj.this)

        # Create a new ASBR
        asbr1 = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.ext_nh.hld_obj)
        asbr1.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, [], None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        # Clear the properties of the old ASBR
        dpe.hld_obj.clear_asbr_properties(asbr0.hld_obj)

        # Set the new ASBR label
        asbr_labels = []
        asbr_labels.append(self.BGP_LABEL_NEW)

        # Update with the properties of the new ASBR
        dpe.hld_obj.set_asbr_properties(asbr1.hld_obj, asbr_labels)

        # Update the ASBR in the ASBR LSP
        asbr_lsp0.hld_obj.set_asbr(asbr1.hld_obj)

        # Verify the ASBR LSP again
        asbr_lsp_by_asbr_nh = self.device.get_asbr_lsp(asbr1.hld_obj, self.l3_port_impl.reg_nh.hld_obj)
        self.assertEqual(asbr_lsp_by_asbr_nh.this, asbr_lsp0.hld_obj.this)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_BGP_LU_NO_LDP_BGP_LBL_UPDATED_PACKET,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

        lsr.delete_route(self.INPUT_LABEL0)
        dpe.hld_obj.clear_asbr_properties(asbr1.hld_obj)
        dpe.destroy()
        self.device.destroy(asbr_lsp_ecmp)
        asbr_lsp0.destroy()
        asbr0.hld_obj.clear_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj)
        asbr0.destroy()
        asbr1.hld_obj.clear_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj)
        asbr1.destroy()

    def _test_bgp_lu_update_asbr_lsp_destination(self, enable_ldp):
        # Create the ASBR
        asbr0 = T.prefix_object(self, self.device, self.PREFIX0_GID, self.l3_port_impl.reg_nh.hld_obj)

        # Program the LDP labels first for the NEW destination of the ASBR LSP
        lsp_labels = []
        if (enable_ldp is True):
            lsp_labels.append(self.LDP_LABEL)

        asbr0.hld_obj.set_nh_lsp_properties(self.l3_port_impl.def_nh.hld_obj, lsp_labels, None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        asbr0.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels, None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        # Create the Label Switched Path to reach the ASBR
        asbr_lsp0 = T.asbr_lsp(
            self,
            self.device,
            asbr0.hld_obj,
            self.l3_port_impl.reg_nh.hld_obj)

        # Create an ECMP group and add the ASBR LSP as a member
        asbr_lsp_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(asbr_lsp_ecmp, None)
        asbr_lsp_ecmp.add_member(asbr_lsp0.hld_obj)

        # Create the Destination PE
        dpe = T.destination_pe(self, self.device, self.DPE_GID, asbr_lsp_ecmp)

        # Set the initial ASBR label
        asbr_labels = []
        asbr_labels.append(self.BGP_LABEL)

        dpe.hld_obj.set_asbr_properties(asbr0.hld_obj, asbr_labels)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, dpe.hld_obj, self.PRIVATE_DATA)

        if (enable_ldp is True):
            U.run_and_compare(self, self.device,
                              self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                              self.EXPECTED_OUTPUT_BGP_LU_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

            packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_BGP_LU_PACKET, byte_count)
        else:
            U.run_and_compare(self, self.device,
                              self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                              self.EXPECTED_OUTPUT_BGP_LU_NO_LDP_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

            packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_BGP_LU_NO_LDP_PACKET, byte_count)

        # Verify the ASBR LSP
        asbr_lsp_by_asbr_nh = self.device.get_asbr_lsp(asbr0.hld_obj, self.l3_port_impl.reg_nh.hld_obj)
        self.assertEqual(asbr_lsp_by_asbr_nh.this, asbr_lsp0.hld_obj.this)

        # Update the NH destination in the ASBR LSP
        asbr_lsp0.hld_obj.set_destination(self.l3_port_impl.def_nh.hld_obj)

        if (enable_ldp is True):
            U.run_and_compare(
                self,
                self.device,
                self.INPUT_PACKET,
                T.RX_SLICE,
                T.RX_IFG,
                T.FIRST_SERDES,
                self.EXPECTED_OUTPUT_BGP_LU_DEST_UPDATED_PACKET,
                T.TX_SLICE_DEF,
                T.TX_IFG_DEF,
                self.l3_port_impl.serdes_def)
        else:
            U.run_and_compare(
                self,
                self.device,
                self.INPUT_PACKET,
                T.RX_SLICE,
                T.RX_IFG,
                T.FIRST_SERDES,
                self.EXPECTED_OUTPUT_BGP_LU_NO_LDP_DEST_UPDATED_PACKET,
                T.TX_SLICE_DEF,
                T.TX_IFG_DEF,
                self.l3_port_impl.serdes_def)

        lsr.delete_route(self.INPUT_LABEL0)
        dpe.hld_obj.clear_asbr_properties(asbr0.hld_obj)
        dpe.destroy()
        self.device.destroy(asbr_lsp_ecmp)
        asbr_lsp0.destroy()
        asbr0.destroy()

    def _test_bgp_lu_update_dpe_destination(self):
        # Create the ASBRs
        asbr0 = T.prefix_object(self, self.device, self.PREFIX0_GID, self.l3_port_impl.reg_nh.hld_obj)
        asbr0.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, [], None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        asbr1 = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        asbr1.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, [], None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        # Create the Label Switched Path to reach the ASBR
        asbr_lsp0 = T.asbr_lsp(
            self,
            self.device,
            asbr0.hld_obj,
            self.l3_port_impl.reg_nh.hld_obj)
        asbr_lsp1 = T.asbr_lsp(
            self,
            self.device,
            asbr1.hld_obj,
            self.l3_port_impl.reg_nh.hld_obj)

        # Create an ECMP group and add the ASBR LSP as a member
        asbr_lsp_ecmp0 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(asbr_lsp_ecmp0, None)
        asbr_lsp_ecmp0.add_member(asbr_lsp0.hld_obj)

        asbr_lsp_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(asbr_lsp_ecmp1, None)
        asbr_lsp_ecmp1.add_member(asbr_lsp1.hld_obj)

        # Create the Destination PE
        dpe = T.destination_pe(self, self.device, self.DPE_GID, asbr_lsp_ecmp0)

        # Set the initial ASBR label
        asbr_labels = []
        asbr_labels.append(self.BGP_LABEL)

        dpe.hld_obj.set_asbr_properties(asbr0.hld_obj, asbr_labels)

        # Set the updated ASBR label
        asbr_labels = []
        asbr_labels.append(self.BGP_LABEL_NEW)

        dpe.hld_obj.set_asbr_properties(asbr1.hld_obj, asbr_labels)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, dpe.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_BGP_LU_NO_LDP_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        # Update the dpe destination to the second ecmp group which has a
        # different LSP
        dpe.hld_obj.set_destination(asbr_lsp_ecmp1)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_BGP_LU_NO_LDP_BGP_LBL_UPDATED_PACKET,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

    def _test_bgp_lu_update_asbr_lsp_prot_group_destination(self):
        # Create the ASBR
        asbr0 = T.prefix_object(self, self.device, self.PREFIX0_GID, self.l3_port_impl.reg_nh.hld_obj)
        # Update the LDP labels for the Primary and Backup paths
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)
        asbr0.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels, None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        asbr0.hld_obj.set_nh_lsp_properties(self.l3_port_impl.def_nh.hld_obj, lsp_labels, None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        asbr0.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, lsp_labels, None,
                                            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prot_monitor = T.protection_monitor(self, self.device)

        # Create Protection group
        # Primary - reg_nh
        # Backup - ext_nh
        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor.hld_obj)

        # Create the ASBR LSP with the destination as the Protection group
        asbr_lsp_prot_group = T.asbr_lsp(self, self.device, asbr0.hld_obj,
                                         l3_prot_group.hld_obj)

        # Update the Protection group destination
        # Primary - def_nh
        # Backup - reg_nh
        l3_prot_group.hld_obj.modify_protection_group(
            self.l3_port_impl.def_nh.hld_obj,
            self.l3_port_impl.reg_nh.hld_obj,
            prot_monitor.hld_obj)

        # LDP properties can be cleared on the ext_nh
        asbr0.hld_obj.clear_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj)

        # LDP properties cannot be cleared on the def_nh/reg_nh
        with self.assertRaises(sdk.BusyException):
            asbr0.hld_obj.clear_nh_lsp_properties(self.l3_port_impl.def_nh.hld_obj)
        with self.assertRaises(sdk.BusyException):
            asbr0.hld_obj.clear_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj)

        # LDP properties can be cleared on the def_nh/reg_nh after ASBR LSP is
        # destroyed
        asbr_lsp_prot_group.destroy()
        asbr0.hld_obj.clear_nh_lsp_properties(self.l3_port_impl.def_nh.hld_obj)
        asbr0.hld_obj.clear_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj)

    def _test_clear_mappings(self):
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        self.assertNotEqual(pfx_obj.hld_obj, None)
        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        info = lsr.get_route(self.INPUT_LABEL0)

        lsr.clear_all_routes()

        try:
            lsr.get_route(self.INPUT_LABEL0)
            self.assertFail()
        except sdk.BaseException:
            pass

    def _test_get_label_mapping(self):
        lsr = self.device.get_lsr()

        try:
            info = lsr.get_route(self.INPUT_LABEL0)
            self.assertFail()
        except sdk.BaseException:
            pass

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        self.assertNotEqual(pfx_obj.hld_obj, None)
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        info = lsr.get_route(self.INPUT_LABEL0)
        self.assertEqual(info.user_data, self.PRIVATE_DATA)
        self.assertEqual(info.destination.this, pfx_obj.hld_obj.this)

        lsr.delete_route(self.INPUT_LABEL0)

        try:
            info = lsr.get_route(self.INPUT_LABEL0)
            self.assertFail()
        except sdk.BaseException:
            pass

    def _test_remove_busy_prefix_object(self):
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        try:
            pfx_obj.destroy()
            self.assertFail()
        except sdk.BaseException:
            pass

    def _test_pop_double_label_pipe(self, add_lsp_counter=True):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
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
                          self.EXPECTED_OUTPUT_POP_PIPE_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = lsp_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_POP_PIPE_PACKET, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_POP_PIPE_PACKET, byte_count)

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

    def _test_csc_label_check(self):
        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(self.l3_port_impl.reg_nh.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, nh_ecmp)

        lsp_counter = None
        lsp_labels = []
        lsp_labels.append(self.OUTPUT_LABEL0)
        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.l3_port_impl.rx_port.hld_obj.set_csc_enabled(True)
        csc = self.l3_port_impl.rx_port.hld_obj.get_csc_enabled()
        self.assertEqual(csc, True)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, self.topology.vrf.hld_obj, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_SWAP_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def _test_csc_label_check_intf_non_csc(self):
        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(self.l3_port_impl.reg_nh.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, nh_ecmp)

        lsp_counter = None
        lsp_labels = []
        lsp_labels.append(self.OUTPUT_LABEL0)
        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        # CSC is not enabled on the interface so the packet should not drop
        # First enable then disable to test the disable path
        self.l3_port_impl.rx_port.hld_obj.set_csc_enabled(True)
        self.l3_port_impl.rx_port.hld_obj.set_csc_enabled(False)
        csc = self.l3_port_impl.rx_port.hld_obj.get_csc_enabled()
        self.assertEqual(csc, False)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, self.topology.vrf.hld_obj, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_SWAP_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def _test_csc_label_check_label_drop(self):
        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(self.l3_port_impl.reg_nh.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, nh_ecmp)

        lsp_counter = None
        lsp_labels = []
        lsp_labels.append(self.OUTPUT_LABEL0)
        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.l3_port_impl.rx_port.hld_obj.set_csc_enabled(True)

        lsr = self.device.get_lsr()
        # Label is not configured with VRF and CSC is enabled on the interface,
        # packet should drop.
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_csc_label_check_vrf_drop(self):
        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(self.l3_port_impl.reg_nh.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, nh_ecmp)

        lsp_counter = None
        lsp_labels = []
        lsp_labels.append(self.OUTPUT_LABEL0)
        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.l3_port_impl.rx_port.hld_obj.set_csc_enabled(True)

        lsr = self.device.get_lsr()
        # Label is configured with a different vrf (vrf2), packet should drop.
        lsr.add_route(self.INPUT_LABEL0, self.topology.vrf2.hld_obj, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_php_uniform_csc_label_check(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        lsp_counter = None
        lsp_labels = []

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.l3_port_impl.rx_port.hld_obj.set_csc_enabled(True)
        csc = self.l3_port_impl.rx_port.hld_obj.get_csc_enabled()
        self.assertEqual(csc, True)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, self.topology.vrf.hld_obj, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PHP_UNIFORM_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def _test_php_uniform_csc_label_check_intf_non_csc(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        lsp_counter = None
        lsp_labels = []

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        # CSC is not enabled on the interface so the packet should not drop
        # First enable then disable to test the disable path
        self.l3_port_impl.rx_port.hld_obj.set_csc_enabled(True)
        self.l3_port_impl.rx_port.hld_obj.set_csc_enabled(False)
        csc = self.l3_port_impl.rx_port.hld_obj.get_csc_enabled()
        self.assertEqual(csc, False)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, self.topology.vrf.hld_obj, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PHP_UNIFORM_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def _test_php_uniform_csc_label_check_label_drop(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        lsp_counter = None
        lsp_labels = []

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.l3_port_impl.rx_port.hld_obj.set_csc_enabled(True)

        lsr = self.device.get_lsr()
        # Label is not configured with VRF and CSC is enabled on the interface,
        # packet should drop.
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_drop(self, self.device,
                       self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_php_uniform_csc_label_check_vrf_drop(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        lsp_counter = None
        lsp_labels = []

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.l3_port_impl.rx_port.hld_obj.set_csc_enabled(True)

        lsr = self.device.get_lsr()
        # Label is configured with a different vrf (vrf2), packet should drop.
        lsr.add_route(self.INPUT_LABEL0, self.topology.vrf2.hld_obj, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_drop(self, self.device,
                       self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def create_ecmp_group_multipath(self):
        NUM_OF_NH = 10
        NH_GID_BASE = 0x613
        NH_DST_MAC_BASE = T.mac_addr('11:11:11:11:11:00')

        self.nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        nh_list = []
        for nh_num in range(NUM_OF_NH):
            nh = T.next_hop(
                self,
                self.device,
                NH_GID_BASE + nh_num,
                NH_DST_MAC_BASE.create_offset_mac(nh_num),
                self.l3_port_impl.tx_port)
            self.nh_ecmp.add_member(nh.hld_obj)
            nh_list.append(nh)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.nh_ecmp)

        for nh_num in range(NUM_OF_NH):
            lsp_labels = []
            lsp_labels.append(self.OUTPUT_LABEL0)
            pfx_obj.hld_obj.set_nh_lsp_properties(nh_list[nh_num].hld_obj, lsp_labels,
                                                  None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

    def _test_ecmp_hash_multipath_mpls_ip(self):
        self.create_ecmp_group_multipath()

        if self.protocol == sdk.la_l3_protocol_e_IPV4_UC:
            INPUT_PACKET_base = self.INPUT_PACKET_MULTI_LABEL_BASE / \
                IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.IP_TTL) / \
                TCP()
        else:
            INPUT_PACKET_base = self.INPUT_PACKET_MULTI_LABEL_BASE / \
                IPv6(src=self.SIP.addr_str, dst=self.DIP.addr_str, hlim=self.IP_TTL) / \
                TCP()

        INPUT_PACKET_local = INPUT_PACKET_base

        lb_vec_entry_list = []
        hw_lb_vec = sdk.la_lb_vector_t()
        hw_lb_vec.type = sdk.LA_LB_VECTOR_MPLS

        soft_lb_vec = sdk.la_lb_vector_t()
        if self.protocol == sdk.la_l3_protocol_e_IPV4_UC:
            hw_lb_vec.mpls.label = [self.INPUT_LABEL0.label, self.INPUT_LABEL1.label, self.INPUT_LABEL2.label,
                                    self.INPUT_LABEL3.label, self.INPUT_LABEL4.label, self.INPUT_LABEL5.label,
                                    self.INPUT_LABEL6.label, self.INPUT_LABEL7.label, self.INPUT_LABEL8.label,
                                    self.INPUT_LABEL9.label, 0, 0, 0, 0]
            hw_lb_vec.mpls.num_valid_labels = 10

            if decor.is_akpg():
                soft_lb_vec.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV4_L4
            else:
                soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
            soft_lb_vec.ipv4.sip = T.ipv4_addr(INPUT_PACKET_local[IP].src).to_num()
            soft_lb_vec.ipv4.dip = T.ipv4_addr(INPUT_PACKET_local[IP].dst).to_num()
            soft_lb_vec.ipv4.protocol = INPUT_PACKET_local[IP].proto
            soft_lb_vec.ipv4.src_port = INPUT_PACKET_local[TCP].sport
            soft_lb_vec.ipv4.dest_port = INPUT_PACKET_local[TCP].dport
        else:
            hw_lb_vec.mpls.label = [self.INPUT_LABEL0.label, self.INPUT_LABEL1.label, self.INPUT_LABEL2.label,
                                    self.INPUT_LABEL3.label, self.INPUT_LABEL4.label, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            hw_lb_vec.mpls.num_valid_labels = 5

            soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV6_TCP_UDP
            soft_lb_vec.ipv6.sip = U.split_bits(T.ipv6_addr(INPUT_PACKET_local[IPv6].src).to_num(), 32)
            soft_lb_vec.ipv6.dip = U.split_bits(T.ipv6_addr(INPUT_PACKET_local[IPv6].dst).to_num(), 32)
            soft_lb_vec.ipv6.next_header = INPUT_PACKET_local[IPv6].nh
            soft_lb_vec.ipv6.flow_label = INPUT_PACKET_local[IPv6].fl
            soft_lb_vec.ipv6.src_port = INPUT_PACKET_local[TCP].sport
            soft_lb_vec.ipv6.dest_port = INPUT_PACKET_local[TCP].dport

        lb_vec_entry_list.append(hw_lb_vec)
        lb_vec_entry_list.append(soft_lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(self.nh_ecmp, lb_vec_entry_list)
        U.check_forwarding_load_balance_chain(self, out_dest_chain, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        expected_mac = out_dest_chain[0].downcast().get_mac().flat
        expected_mac_str = T.mac_addr.mac_num_to_str(expected_mac)

        if self.protocol == sdk.la_l3_protocol_e_IPV4_UC:
            EXPECTED_PACKET_base = Ether(dst=expected_mac_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
                self.EXPECTED_OUTPUT_PACKET_MULTI_LABEL_BASE / \
                IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.IP_TTL) / \
                TCP()
        else:
            EXPECTED_PACKET_base = Ether(dst=expected_mac_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
                self.EXPECTED_OUTPUT_PACKET_MULTI_LABEL_BASE / \
                IPv6(src=self.SIP.addr_str, dst=self.DIP.addr_str, hlim=self.IP_TTL) / \
                TCP()

        EXPECTED_PACKET_local = EXPECTED_PACKET_base

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_local, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          EXPECTED_PACKET_local, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def _test_ecmp_hash_multipath_mpls_eth(self):
        DMAC = T.mac_addr('50:52:53:54:55:56')
        SMAC = T.mac_addr('60:62:63:64:65:66')
        Ether_type_local = 0x9999
        VLAN_TAG_local = 0x100

        self.create_ecmp_group_multipath()

        # Eth inside MPLS
        raw = Raw()
        raw.load = '\x00' * 4
        INPUT_PACKET_base = self.INPUT_PACKET_MULTI_LABEL_BASE / \
            raw / \
            Ether(dst=DMAC.addr_str, src=SMAC.addr_str, type=Ether_type_local)
        INPUT_PACKET_local = U.add_payload(INPUT_PACKET_base, self.PAYLOAD_SIZE)

        lb_vec_entry_list = []

        if not decor.is_akpg():
            hw_lb_vec = sdk.la_lb_vector_t()
            hw_lb_vec.type = sdk.LA_LB_VECTOR_MPLS
            hw_lb_vec.mpls.label = [self.INPUT_LABEL0.label, self.INPUT_LABEL1.label, self.INPUT_LABEL2.label,
                                    self.INPUT_LABEL3.label, self.INPUT_LABEL4.label, self.INPUT_LABEL5.label,
                                    self.INPUT_LABEL6.label, self.INPUT_LABEL7.label, self.INPUT_LABEL8.label,
                                    self.INPUT_LABEL9.label, 0, 0, 0, 0]
            hw_lb_vec.mpls.num_valid_labels = 10
            lb_vec_entry_list.append(hw_lb_vec)

        soft_lb_vec = sdk.la_lb_vector_t()
        soft_lb_vec.type = sdk.LA_LB_VECTOR_MPLS_CW_ETHERNET
        if decor.is_akpg():
            soft_lb_vec.cw_and_ethernet.ethernet.da = DMAC.hld_obj
            soft_lb_vec.cw_and_ethernet.ethernet.sa = SMAC.hld_obj
            soft_lb_vec.cw_and_ethernet.cw = 0  # should match raw
        else:
            soft_lb_vec.ethernet.da = DMAC.hld_obj
            soft_lb_vec.ethernet.sa = SMAC.hld_obj
            soft_lb_vec.ethernet.ether_type = Ether_type_local
        lb_vec_entry_list.append(soft_lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(self.nh_ecmp, lb_vec_entry_list)
        U.check_forwarding_load_balance_chain(self, out_dest_chain, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        expected_mac = out_dest_chain[0].downcast().get_mac().flat
        expected_mac_str = T.mac_addr.mac_num_to_str(expected_mac)

        EXPECTED_PACKET_base = Ether(dst=expected_mac_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
            self.EXPECTED_OUTPUT_PACKET_MULTI_LABEL_BASE / \
            raw / \
            Ether(dst=DMAC.addr_str, src=SMAC.addr_str, type=Ether_type_local)

        EXPECTED_PACKET_local = U.add_payload(EXPECTED_PACKET_base, self.PAYLOAD_SIZE)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_local, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          EXPECTED_PACKET_local, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        # Eth Vlan inside MPLS
        INPUT_PACKET_vlan_base = self.INPUT_PACKET_MULTI_LABEL_BASE / \
            raw / \
            Ether(dst=DMAC.addr_str, src=SMAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=VLAN_TAG_local, type=Ether_type_local)
        INPUT_PACKET_vlan_local = U.add_payload(INPUT_PACKET_vlan_base, self.PAYLOAD_SIZE)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(self.nh_ecmp, lb_vec_entry_list)
        U.check_forwarding_load_balance_chain(self, out_dest_chain, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        expected_mac = out_dest_chain[0].downcast().get_mac().flat
        expected_mac_str = T.mac_addr.mac_num_to_str(expected_mac)

        EXPECTED_PACKET_vlan_base = Ether(dst=expected_mac_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
            self.EXPECTED_OUTPUT_PACKET_MULTI_LABEL_BASE / \
            raw / \
            Ether(dst=DMAC.addr_str, src=SMAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=VLAN_TAG_local, type=Ether_type_local)

        EXPECTED_PACKET_vlan_local = U.add_payload(EXPECTED_PACKET_vlan_base, self.PAYLOAD_SIZE)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_vlan_local, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          EXPECTED_PACKET_vlan_local, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def _test_ecmp_hash_multipath_mpls_gtp(self):
        IP_LEN = 60
        UDP_SPORT = 4000
        UDP_LEN = 40
        UDP_LEN_V6 = 60
        GTP_PORT = 2152
        GTP_TEID = 0xabcdffff
        GTP_VER_ascii = '\x90\x44\x00\x1c'      # GTP Version + TEID Flag + Message type
        GTP_TEID_ascii = '\xab\xcd\xff\xff'     # Tunnel ID 0xabcdffff in ascii
        GTP_SEQ_ascii = '\x00\x00\x01\x00'      # GTP sequence number

        self.create_ecmp_group_multipath()

        gtp_raw = Raw()
        gtp_raw.load = GTP_VER_ascii + GTP_TEID_ascii + GTP_SEQ_ascii

        if self.protocol == sdk.la_l3_protocol_e_IPV4_UC:
            INPUT_PACKET_local = self.INPUT_PACKET_MULTI_LABEL_BASE_gtp / \
                IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.IP_TTL, len=IP_LEN) / \
                UDP(sport=UDP_SPORT, dport=GTP_PORT, len=UDP_LEN) / \
                gtp_raw / \
                IP()
        else:
            INPUT_PACKET_local = self.INPUT_PACKET_MULTI_LABEL_BASE_gtp / \
                IPv6(src=self.SIP.addr_str, dst=self.DIP.addr_str, hlim=self.IP_TTL) / \
                UDP(sport=UDP_SPORT, dport=GTP_PORT, len=UDP_LEN_V6) / \
                gtp_raw / \
                IPv6()

        lb_vec_entry_list = []
        hw_lb_vec = sdk.la_lb_vector_t()
        hw_lb_vec.type = sdk.LA_LB_VECTOR_MPLS
        hw_lb_vec.mpls.label = [self.INPUT_LABEL0.label, self.INPUT_LABEL1.label, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        hw_lb_vec.mpls.num_valid_labels = 2
        lb_vec_entry_list.append(hw_lb_vec)

        soft_lb_vec = sdk.la_lb_vector_t()
        soft_lb_vec.type = sdk.LA_LB_VECTOR_GTP
        soft_lb_vec.gtp_tunnel_id = GTP_TEID
        lb_vec_entry_list.append(soft_lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(self.nh_ecmp, lb_vec_entry_list)
        U.check_forwarding_load_balance_chain(self, out_dest_chain, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
        expected_mac = out_dest_chain[0].downcast().get_mac().flat
        expected_mac_str = T.mac_addr.mac_num_to_str(expected_mac)

        if self.protocol == sdk.la_l3_protocol_e_IPV4_UC:
            EXPECTED_PACKET_local = Ether(dst=expected_mac_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
                self.EXPECTED_OUTPUT_PACKET_MULTI_LABEL_BASE_gtp / \
                IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.IP_TTL, len=IP_LEN) / \
                UDP(sport=UDP_SPORT, dport=GTP_PORT, len=UDP_LEN) / \
                gtp_raw / \
                IP()
        else:
            EXPECTED_PACKET_local = Ether(dst=expected_mac_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
                self.EXPECTED_OUTPUT_PACKET_MULTI_LABEL_BASE_gtp / \
                IPv6(src=self.SIP.addr_str, dst=self.DIP.addr_str, hlim=self.IP_TTL) / \
                UDP(sport=UDP_SPORT, dport=GTP_PORT, len=UDP_LEN_V6) / \
                gtp_raw / \
                IPv6()

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_local, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          EXPECTED_PACKET_local, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
