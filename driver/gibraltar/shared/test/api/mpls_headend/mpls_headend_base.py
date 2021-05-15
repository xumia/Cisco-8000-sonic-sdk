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
import decor
from leaba import sdk
import ip_test_base
import sim_utils
import topology as T
import packet_test_utils as U
from sdk_test_case_base import *

U.parse_ip_after_mpls()


class mpls_headend_base(sdk_test_case_base):
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
    INPUT_POP_FWD_LABEL = sdk.la_mpls_label()
    INPUT_POP_FWD_LABEL.label = 0x80
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
            device.set_bool_property(sdk.la_device_property_e_ENABLE_MPLS_SR_ACCOUNTING, True)

    @classmethod
    def setUpClass(cls):
        super(mpls_headend_base, cls).setUpClass(device_config_func=mpls_headend_base.device_config_func)

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
            mpls_headend_base.PRIVATE_DATA_DEFAULT)

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
        self.l2_ext2_egress_counter = self.device.create_counter(1)
        self.tx_l2_ac_port_ext2.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l2_ext2_egress_counter)

        self.mc_group = self.device.create_l2_multicast_group(self.MC_GID, sdk.la_replication_paradigm_e_EGRESS)
        system_port = self.topology.tx_svi_eth_port_ext.hld_obj.get_system_port()
        self.mc_group.add(self.topology.tx_l2_ac_port_ext.hld_obj, system_port)
        system_port = self.tx_svi_eth_port_ext2.hld_obj.get_system_port()
        self.mc_group.add(self.tx_l2_ac_port_ext2.hld_obj, system_port)
        self.topology.tx_switch1.hld_obj.set_flood_destination(self.mc_group)
        self.topology.tx_switch1.hld_obj.remove_mac_entry(T.NH_SVI_EXT_MAC.hld_obj)

    def _test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_setup(
            self, is_v4, enable_ldp, add_lsp_counter, asbr_labels_null = False, redir_vrf=None):
        # Create the ASBR
        asbr1 = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        # Program the LDP labels
        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)
        if (enable_ldp is True):
            lsp_labels = []
            lsp_labels.append(self.LDP_LABEL)
            asbr1.hld_obj.set_nh_lsp_properties(
                self.l3_port_impl.reg_nh.hld_obj,
                lsp_labels,
                lsp_counter,
                sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        else:
            lsp_labels = []
            asbr1.hld_obj.set_nh_lsp_properties(
                self.l3_port_impl.reg_nh.hld_obj,
                lsp_labels,
                lsp_counter,
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
        if (not asbr_labels_null):
            asbr_labels.append(self.BGP_LABEL)

        vpn_labels = []
        vpn_labels.append(self.VPN_LABEL)

        # Program the BGP labels
        dpe.hld_obj.set_asbr_properties(asbr1.hld_obj, asbr_labels)

        if (is_v4 is True):
            # Program the VPN labels
            if (redir_vrf is not None):
                dpe.hld_obj.set_vrf_properties(redir_vrf, sdk.la_ip_version_e_IPV4, vpn_labels)
            else:
                dpe.hld_obj.set_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV4, vpn_labels)
        else:
            dpe.hld_obj.set_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6, vpn_labels)

        self.bgp_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.assertNotEqual(self.bgp_ecmp, None)
        self.bgp_ecmp.add_member(dpe.hld_obj)

        self.prefix = self.ip_impl.build_prefix(self.DIP, length=16)

    def _test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_run(self, enable_ldp, asbr_labels_null = False):
        if (enable_ldp):
            expected_packet = self.EXPECTED_OUTPUT_VPN_BGP_LU_PACKET
            if (asbr_labels_null):
                expected_packet = self.EXPECTED_OUTPUT_VPN_BGP_LU_NULL_PACKET
        else:
            expected_packet = self.EXPECTED_OUTPUT_VPN_BGP_LU_NO_LDP_PACKET

        U.run_and_compare(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          expected_packet, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, expected_packet, byte_count)

    def _test_bgp_lu_dpe_vpn_properties(self):
        # Create an ECMP group
        asbr_lsp_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(asbr_lsp_ecmp, None)

        # Create a Destination PE
        dpe = T.destination_pe(self, self.device, self.DPE_GID, asbr_lsp_ecmp)

        vpn_labels = []
        vpn_labels.append(self.VPN_LABEL)
        # Program the IPV4 VPN labels
        dpe.hld_obj.set_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV4, vpn_labels)

        ipv6_vpn_labels = []
        ipv6_vpn_labels.append(self.IP6PE_VPN_LABEL)
        # Program the IPV6 VPN labels
        dpe.hld_obj.set_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6, ipv6_vpn_labels)

        # Check v4 vrf_properties
        res_vpn_labels = []
        (res_vpn_labels) = dpe.hld_obj.get_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV4)
        self.assertEqual(res_vpn_labels[0].label, vpn_labels[0].label)

        # Check v6 vrf_properties
        res_vpn_labels = []
        (res_vpn_labels) = dpe.hld_obj.get_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6)
        self.assertEqual(res_vpn_labels[0].label, ipv6_vpn_labels[0].label)

        # Clear v6 vrf_properties
        dpe.hld_obj.clear_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6)

        # Check v4 vrf_properties to be intact
        res_vpn_labels = []
        (res_vpn_labels) = dpe.hld_obj.get_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV4)
        self.assertEqual(res_vpn_labels[0].label, vpn_labels[0].label)

        # Re-program the IPV6 VPN labels
        dpe.hld_obj.set_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6, ipv6_vpn_labels)

        # Clear v4 vrf_properties
        dpe.hld_obj.clear_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV4)

        # Check v6 vrf_properties to be intact
        res_vpn_labels = []
        (res_vpn_labels) = dpe.hld_obj.get_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6)
        self.assertEqual(res_vpn_labels[0].label, ipv6_vpn_labels[0].label)

        # Clear v4 & v6 vrf_properties
        dpe.hld_obj.clear_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV4)
        dpe.hld_obj.clear_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6)

        res_vpn_labels = []
        with self.assertRaises(sdk.NotFoundException):
            (res_vpn_labels) = dpe.hld_obj.get_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV4)

        res_vpn_labels = []
        with self.assertRaises(sdk.NotFoundException):
            (res_vpn_labels) = dpe.hld_obj.get_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6)

    def _test_ecmp_prefix_nh_to_ip_setup(self, add_lsp_counter=True):
        self.pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)

        self.m_ecmp_rec = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.assertNotEqual(self.m_ecmp_rec, None)
        self.m_ecmp_rec.add_member(self.pfx_obj.hld_obj)

        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)
        lsp_labels = []
        self.pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.prefix = self.ip_impl.build_prefix(self.DIP, length=16)

    def _test_ecmp_prefix_nh_to_ip_run(self):
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

    def _test_ecmp_prefix_nh_to_ip_flood_setup(self, add_lsp_counter=True):
        self.flood_setup()
        self.pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.ext_nh.hld_obj)

        self.m_ecmp_rec = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.assertNotEqual(self.m_ecmp_rec, None)
        self.m_ecmp_rec.add_member(self.pfx_obj.hld_obj)

        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)
        lsp_labels = []
        self.pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.ext_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.prefix = self.ip_impl.build_prefix(self.DIP, length=16)

    def _test_ecmp_prefix_nh_to_ip_flood_run(self):
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        egress_packets = []
        egress_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_IP_FLOOD, 'slice': T.TX_SLICE_EXT,
                               'ifg': T.TX_IFG_EXT, 'pif': self.l3_port_impl.serdes_ext})
        egress_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_IP_FLOOD, 'slice': T.TX_SLICE_EXT,
                               'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES1 + 2})

        U.run_and_compare_list(self, self.device, ingress_packet, egress_packets)

        packet_count, byte_count = self.l2_ext_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.l2_ext2_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.egress_ext_counter.read(self.protocol, True, True)
        self.assertEqual(packet_count, 1)
        #U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_IP_FLOOD, byte_count)

    def _test_ecmp_prefix_nh_to_mpls_setup(self, add_lsp_counter=True):
        self.pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)

        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)

        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        self.pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.m_ecmp_rec = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.assertNotEqual(self.m_ecmp_rec, None)
        self.m_ecmp_rec.add_member(self.pfx_obj.hld_obj)

        self.prefix = self.ip_impl.build_prefix(self.DIP, length=16)

    def _test_ecmp_prefix_nh_to_mpls_run(self):
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

    def _test_ecmp_tenh_to_mpls_setup(self, add_lsp_counter=True):
        self.te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        self.te_counter = None
        if add_lsp_counter:
            self.te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)
        self.te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, self.te_counter)
        self.te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        self.te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(self.te_ecmp, None)
        self.te_ecmp.add_member(self.te_tunnel.hld_obj)

        self.prefix = self.ip_impl.build_prefix(self.DIP, length=16)

    def _test_ecmp_tenh_to_mpls_run(self, check_lsp_counter=True):
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TE, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if check_lsp_counter:
            packet_count, byte_count = self.te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE, byte_count)

    def _test_fec_prefix_nh_to_ip_setup(self, add_lsp_counter=True):
        self.pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)

        self.fec = T.fec(self, self.device, self.pfx_obj)

        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)
        lsp_labels = []
        self.pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.prefix = self.ip_impl.build_prefix(self.DIP, length=16)

    def _test_fec_prefix_nh_to_ip_run(self):
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

    def _test_fec_prefix_nh_to_ip_flood_setup(self, add_lsp_counter=True):
        self.flood_setup()
        self.pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.ext_nh.hld_obj)

        self.fec = T.fec(self, self.device, self.pfx_obj)

        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)
        lsp_labels = []
        self.pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.ext_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.prefix = self.ip_impl.build_prefix(self.DIP, length=16)

    def _test_fec_prefix_nh_to_ip_flood_run(self):
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        egress_packets = []
        egress_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_IP_FLOOD, 'slice': T.TX_SLICE_EXT,
                               'ifg': T.TX_IFG_EXT, 'pif': self.l3_port_impl.serdes_reg})
        egress_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_IP_FLOOD, 'slice': T.TX_SLICE_EXT,
                               'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES1 + 2})

        U.run_and_compare_list(self, self.device, ingress_packet, egress_packets)

        packet_count, byte_count = self.l2_ext_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.l2_ext2_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.egress_ext_counter.read(self.protocol, True, True)
        self.assertEqual(packet_count, 1)
        #U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_IP_FLOOD, byte_count)

    def _test_fec_prefix_nh_to_mpls_setup(self, add_lsp_counter=True):
        self.pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)

        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)

        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        self.pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.fec = T.fec(self, self.device, self.pfx_obj)

        self.prefix = self.ip_impl.build_prefix(self.DIP, length=16)

    def _test_fec_prefix_nh_to_mpls_run(self):
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

    def _test_ip_ecmp_ldp_tenh_to_mpls(self):
        # This tests the case of IP traffic over a LDPoTE tunnel. LDP label is not imposed.
        te_tunnel = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, te_ecmp,
                                                 self.PRIVATE_DATA_DEFAULT, False)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IP_LDPoTE, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = te_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_IP_LDPoTE, byte_count)

    def _test_prefix_ecmp_ldp_tenh_to_mpls(self, add_lsp_counter=True, with_vlan=False):
        if (with_vlan):
            tag = sdk.la_vlan_tag_t()
            tag.tpid = 0x8100
            tag.tci.fields.pcp = 0
            tag.tci.fields.dei = 0
            tag.tci.fields.vid = self.OUTPUT_VID

            self.l3_port_impl.tx_port.hld_obj.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)

        te_tunnel = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)

        lsp_counter = None
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_te_tunnel_lsp_properties(te_tunnel.hld_obj, lsp_labels, lsp_counter)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        if (with_vlan):
            U.run_and_compare(
                self,
                self.device,
                self.INPUT_PACKET,
                T.RX_SLICE,
                T.RX_IFG,
                T.FIRST_SERDES,
                self.EXPECTED_OUTPUT_PACKET_LDPoTE_WITH_VLAN,
                T.TX_SLICE_REG,
                T.TX_IFG_REG,
                self.l3_port_impl.serdes_reg)

            if add_lsp_counter:
                packet_count, byte_count = te_counter.read(0, True, True)
                self.assertEqual(packet_count, 1)
                U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_LDPoTE_WITH_VLAN, byte_count)

        else:
            U.run_and_compare(self, self.device,
                              self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                              self.EXPECTED_OUTPUT_PACKET_LDPoTE, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

            if add_lsp_counter:
                packet_count, byte_count = te_counter.read(0, True, True)
                self.assertEqual(packet_count, 1)
                U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_LDPoTE, byte_count)

    def _test_prefix_ecmp_ldp_tenh_to_mpls_ldp_implicit_null(self):
        te_tunnel = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, None)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)

        pfx_obj.hld_obj.set_te_tunnel_lsp_properties(te_tunnel.hld_obj, [], None)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_LDPoTE_LDP_IMPLICIT_NULL,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

    def _test_prefix_ecmp_ldp_tenh_to_mpls_te_implicit_null(self):
        te_tunnel = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, [], None)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)

        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_te_tunnel_lsp_properties(te_tunnel.hld_obj, lsp_labels, None)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_LDPoTE_TE_IMPLICIT_NULL,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

    def _test_prefix_ecmp_ldp_tenh_to_mpls_ldp_and_te_implicit_null(self):
        te_tunnel = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, [], None)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)

        pfx_obj.hld_obj.set_te_tunnel_lsp_properties(te_tunnel.hld_obj, [], None)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_LDPoTE_LDP_AND_TE_IMPLICIT_NULL,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

    def _test_prefix_ecmp_ldp_tenh_l3_dlp_update(self):
        te_tunnel = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)

        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_te_tunnel_lsp_properties(te_tunnel.hld_obj, lsp_labels, None)

        # Create and set counter-set for accounting to test L3 DLP attributes propagation
        egress_counter = self.device.create_counter(sdk.la_l3_protocol_counter_e_LAST)
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, egress_counter)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_LDPoTE, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_LDPoTE, byte_count)

        packet_count, byte_count = te_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_LDPoTE, byte_count)

    def _test_prefix_ecmp_ldp_tenh_to_mpls_label_2(self, add_lsp_counter=True):
        te_tunnel = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.SR_LABEL0)
        te_labels.append(self.SR_LABEL1)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)

        lsp_counter = None
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_te_tunnel_lsp_properties(te_tunnel.hld_obj, lsp_labels, lsp_counter)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_2, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_2, byte_count)

    def _test_prefix_ecmp_ldp_tenh_to_mpls_label_3(self, add_lsp_counter=True, v6_explicit_null=True):
        te_tunnel = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.SR_LABEL0)
        te_labels.append(self.SR_LABEL1)
        te_labels.append(self.SR_LABEL2)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)
        if v6_explicit_null:
            te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)

        lsp_counter = None
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_te_tunnel_lsp_properties(te_tunnel.hld_obj, lsp_labels, lsp_counter)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        if v6_explicit_null:
            expected_packet = self.EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_3
        else:
            expected_packet = self.EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_3_NO_EXPLICIT_NULL

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          expected_packet, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, expected_packet, byte_count)

    def _test_prefix_ecmp_tenh_to_mpls_vpn_label(self, is_v4 = True, add_lsp_counter=True):
        te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.SR_LABEL0)
        te_labels.append(self.SR_LABEL1)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)

        vpn_labels = []
        vpn_labels.append(self.VPN_LABEL)
        # Program the IPV4 VPN labels
        pfx_obj.hld_obj.set_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV4, vpn_labels)

        ipv6_vpn_labels = []
        ipv6_vpn_labels.append(self.IP6PE_VPN_LABEL)
        # Program the IPV6 VPN labels
        pfx_obj.hld_obj.set_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6, ipv6_vpn_labels)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        ecmp_rec = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.assertNotEqual(ecmp_rec, None)
        ecmp_rec.add_member(pfx_obj.hld_obj)

        if (is_v4):
            self.topology.vrf.hld_obj.add_ipv4_route(prefix, ecmp_rec, self.PRIVATE_DATA_DEFAULT, False)
        else:
            self.topology.vrf.hld_obj.add_ipv6_route(prefix, ecmp_rec, self.PRIVATE_DATA_DEFAULT, False)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TE_VPN_LABEL, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE_VPN_LABEL, byte_count)

    def _test_prefix_ecmp_ldp_tenh_to_mpls_vpn_label(self, is_v4 = True, add_lsp_counter=True):
        te_tunnel = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.SR_LABEL0)
        te_labels.append(self.SR_LABEL1)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)

        lsp_counter = None
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_te_tunnel_lsp_properties(te_tunnel.hld_obj, lsp_labels, lsp_counter)

        vpn_labels = []
        vpn_labels.append(self.VPN_LABEL)
        # Program the IPV4 VPN labels
        pfx_obj.hld_obj.set_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV4, vpn_labels)

        ipv6_vpn_labels = []
        ipv6_vpn_labels.append(self.IP6PE_VPN_LABEL)
        # Program the IPV6 VPN labels
        pfx_obj.hld_obj.set_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6, ipv6_vpn_labels)

        ecmp_rec = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.assertNotEqual(ecmp_rec, None)
        ecmp_rec.add_member(pfx_obj.hld_obj)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        if (is_v4):
            self.topology.vrf.hld_obj.add_ipv4_route(prefix, ecmp_rec, self.PRIVATE_DATA_DEFAULT, False)
        else:
            self.topology.vrf.hld_obj.add_ipv6_route(prefix, ecmp_rec, self.PRIVATE_DATA_DEFAULT, False)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_LDPoTE_VPN_LABEL, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_LDPoTE_VPN_LABEL, byte_count)

    def _test_prefix_ecmp_tenh_to_mpls_vpn_label_4(self, is_v4 = True, add_lsp_counter=True):
        te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.SR_LABEL0)
        te_labels.append(self.SR_LABEL1)
        te_labels.append(self.SR_LABEL2)
        te_labels.append(self.SR_LABEL3)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)

        lsp_counter = None
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        vpn_labels = []
        vpn_labels.append(self.VPN_LABEL)
        # Program the IPV4 VPN labels
        pfx_obj.hld_obj.set_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV4, vpn_labels)

        ipv6_vpn_labels = []
        ipv6_vpn_labels.append(self.IP6PE_VPN_LABEL)
        # Program the IPV6 VPN labels
        pfx_obj.hld_obj.set_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6, ipv6_vpn_labels)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        ecmp_rec = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.assertNotEqual(ecmp_rec, None)
        ecmp_rec.add_member(pfx_obj.hld_obj)

        if (is_v4):
            self.topology.vrf.hld_obj.add_ipv4_route(prefix, ecmp_rec, self.PRIVATE_DATA_DEFAULT, False)
        else:
            self.topology.vrf.hld_obj.add_ipv6_route(prefix, ecmp_rec, self.PRIVATE_DATA_DEFAULT, False)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TE_VPN_LABEL_4, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE_VPN_LABEL_4, byte_count)

    def _test_prefix_ecmp_ldp_tenh_to_mpls_vpn_label_4(self, is_v4 = True, add_lsp_counter=True):
        te_tunnel = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.SR_LABEL0)
        te_labels.append(self.SR_LABEL1)
        te_labels.append(self.SR_LABEL2)
        te_labels.append(self.SR_LABEL3)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)

        lsp_counter = None
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_te_tunnel_lsp_properties(te_tunnel.hld_obj, lsp_labels, lsp_counter)

        vpn_labels = []
        vpn_labels.append(self.VPN_LABEL)
        # Program the IPV4 VPN labels
        pfx_obj.hld_obj.set_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV4, vpn_labels)

        ipv6_vpn_labels = []
        ipv6_vpn_labels.append(self.IP6PE_VPN_LABEL)
        # Program the IPV6 VPN labels
        pfx_obj.hld_obj.set_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6, ipv6_vpn_labels)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        ecmp_rec = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.assertNotEqual(ecmp_rec, None)
        ecmp_rec.add_member(pfx_obj.hld_obj)

        if (is_v4):
            self.topology.vrf.hld_obj.add_ipv4_route(prefix, ecmp_rec, self.PRIVATE_DATA_DEFAULT, False)
        else:
            self.topology.vrf.hld_obj.add_ipv6_route(prefix, ecmp_rec, self.PRIVATE_DATA_DEFAULT, False)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_LDPoTE_VPN_LABEL_4,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_LDPoTE_VPN_LABEL_4, byte_count)

    def _test_prefix_ecmp_ldp_tenh_to_mpls_label_4(self, add_te_counter=True, add_lsp_counter=False):
        te_tunnel = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_te_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.SR_LABEL0)
        te_labels.append(self.SR_LABEL1)
        te_labels.append(self.SR_LABEL2)
        te_labels.append(self.SR_LABEL3)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)

        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_te_tunnel_lsp_properties(te_tunnel.hld_obj, lsp_labels, lsp_counter)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_4, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_te_counter and (not add_lsp_counter):
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_4, byte_count)

        if add_lsp_counter:
            packet_count, byte_count = lsp_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_4, byte_count)

    def _test_prefix_ecmp_ldp_tenh_to_mpls_label_8(self, add_lsp_counter=True):
        te_tunnel = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.SR_LABEL0)
        te_labels.append(self.SR_LABEL1)
        te_labels.append(self.SR_LABEL2)
        te_labels.append(self.SR_LABEL3)
        te_labels.append(self.SR_LABEL4)
        te_labels.append(self.SR_LABEL5)
        te_labels.append(self.SR_LABEL6)
        te_labels.append(self.SR_LABEL7)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)

        lsp_counter = None
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_te_tunnel_lsp_properties(te_tunnel.hld_obj, lsp_labels, lsp_counter)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_8, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_8, byte_count)

    def _test_prefix_ecmp_tenh_to_ip(self, add_lsp_counter=True):
        te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)
        self.assertNotEqual(pfx_obj.hld_obj, None)

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
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.output_packet, byte_count)

    def _test_prefix_ecmp_tenh_to_mpls(self, add_lsp_counter=True):
        te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)
        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TE, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE, byte_count)

    def _test_prefix_ecmp_to_ip(self, add_lsp_counter=True):
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

    def _test_prefix_ecmp_to_mpls(self, add_lsp_counter=True, add_dm_counter=False):
        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(self.l3_port_impl.reg_nh.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, nh_ecmp)
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
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels, lsp_counter, counter_mode)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_dm_counter:
            packet_count, byte_count = lsp_counter.read(1, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

            # Now disable the ingress port marking as external interface. Retest the packet.
            # Counter at offset 0 should increment
            self.topology.rx_eth_port.hld_obj.set_traffic_matrix_interface_type(sdk.la_ethernet_port.traffic_matrix_type_e_INTERNAL)
            U.run_and_compare(self, self.device,
                              self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                              self.EXPECTED_OUTPUT_PACKET_MPLS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
            packet_count, byte_count = lsp_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

        elif add_lsp_counter:
            packet_count, byte_count = lsp_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 2 if add_dm_counter else 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, (byte_count / 2) if add_dm_counter else byte_count)

    def _test_prefix_ecmp_tenh_to_mpls_3_labels(self, add_lsp_counter=True):
        te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.SR_LABEL0)
        te_labels.append(self.SR_LABEL1)
        te_labels.append(self.SR_LABEL2)
        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SR, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR, byte_count)

    def _test_prefix_ecmp_tenh_to_mpls_4_labels(self, add_lsp_counter=True):
        te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.SR_LABEL0)
        te_labels.append(self.SR_LABEL1)
        te_labels.append(self.SR_LABEL2)
        te_labels.append(self.SR_LABEL3)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SR_4_LABELS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, [], None)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_4_LABELS, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_4_LABELS, byte_count)

    def _test_prefix_ecmp_tenh_to_mpls_5_labels(self, add_lsp_counter=True):
        te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.SR_LABEL0)
        te_labels.append(self.SR_LABEL1)
        te_labels.append(self.SR_LABEL2)
        te_labels.append(self.SR_LABEL3)
        te_labels.append(self.SR_LABEL4)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SR_5_LABELS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, [], None)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_5_LABELS, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_5_LABELS, byte_count)

    def _test_prefix_ecmp_tenh_to_mpls_6_labels(self, add_lsp_counter=True):
        te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.SR_LABEL0)
        te_labels.append(self.SR_LABEL1)
        te_labels.append(self.SR_LABEL2)
        te_labels.append(self.SR_LABEL3)
        te_labels.append(self.SR_LABEL4)
        te_labels.append(self.SR_LABEL5)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SR_6_LABELS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_6_LABELS, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_6_LABELS, byte_count)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, [], None)

    def _test_prefix_ecmp_tenh_to_mpls_7_labels(self, add_lsp_counter=True):
        te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.SR_LABEL0)
        te_labels.append(self.SR_LABEL1)
        te_labels.append(self.SR_LABEL2)
        te_labels.append(self.SR_LABEL3)
        te_labels.append(self.SR_LABEL4)
        te_labels.append(self.SR_LABEL5)
        te_labels.append(self.SR_LABEL6)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SR_7_LABELS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_7_LABELS, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_7_LABELS, byte_count)

    def _test_prefix_ecmp_tenh_to_mpls_8_labels(self, add_lsp_counter=True):
        te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.SR_LABEL0)
        te_labels.append(self.SR_LABEL1)
        te_labels.append(self.SR_LABEL2)
        te_labels.append(self.SR_LABEL3)
        te_labels.append(self.SR_LABEL4)
        te_labels.append(self.SR_LABEL5)
        te_labels.append(self.SR_LABEL6)
        te_labels.append(self.SR_LABEL7)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SR_8_LABELS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_8_LABELS, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_8_LABELS, byte_count)

    def _test_prefix_global_ecmp_to_mpls(self, add_lsp_counter=True, add_dm_counter=False):
        nh_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp1, None)
        nh_ecmp1.add_member(self.l3_port_impl.reg_nh.hld_obj)

        pfx_obj = T.global_prefix_object(self, self.device, mpls_headend_base.PREFIX1_GID, nh_ecmp1)
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
        counter_mode = sdk.la_prefix_object.lsp_counter_mode_e_LABEL

        if add_dm_counter:
            self.topology.rx_eth_port.hld_obj.set_traffic_matrix_interface_type(sdk.la_ethernet_port.traffic_matrix_type_e_EXTERNAL)
            lsp_counter = self.device.create_counter(2)
            counter_mode = sdk.la_prefix_object.lsp_counter_mode_e_TRAFFIC_MATRIX

        elif add_lsp_counter:
            lsp_counter = self.device.create_counter(1)

        lsp_labels.append(self.SR_LABEL0)
        lsp_labels.append(self.SR_LABEL1)
        lsp_labels.append(self.SR_LABEL2)

        pfx_obj.hld_obj.set_global_lsp_properties(lsp_labels, lsp_counter, counter_mode)
        pfx_obj.hld_obj.set_ipv6_explicit_null_enabled(True)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               mpls_headend_base.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SR, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_dm_counter:
            packet_count, byte_count = lsp_counter.read(1, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR, byte_count)

            # Now disable the ingress port marking as external interface. Retest the packet.
            # Counter at offset 0 should increment
            self.topology.rx_eth_port.hld_obj.set_traffic_matrix_interface_type(sdk.la_ethernet_port.traffic_matrix_type_e_INTERNAL)
            U.run_and_compare(self, self.device,
                              self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                              self.EXPECTED_OUTPUT_PACKET_SR, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
            packet_count, byte_count = lsp_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR, byte_count)

        elif add_lsp_counter:
            packet_count, byte_count = lsp_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR, byte_count)

        packet_count, byte_count = egress_counter.read(sdk.la_l3_protocol_counter_e_MPLS_SR, True, True)
        self.assertEqual(packet_count, 2 if add_dm_counter else 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR, (byte_count / 2) if add_dm_counter else byte_count)

        pfx_obj.hld_obj.clear_global_lsp_properties()

    def _test_sr_global_with_exp_null_config(self):
        nh_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp1, None)
        nh_ecmp1.add_member(self.l3_port_impl.reg_nh.hld_obj)

        # Create a Prefix Object
        pfx_obj0 = T.global_prefix_object(self, self.device, mpls_headend_base.PREFIX0_GID, nh_ecmp1)
        self.assertNotEqual(pfx_obj0.hld_obj, None)

        pfx_obj0_lsp_labels = []
        pfx_obj0_lsp_labels.append(self.SR_LABEL0)
        pfx_obj0_lsp_labels.append(self.SR_LABEL1)
        pfx_obj0_lsp_labels.append(self.SR_LABEL2)
        pfx_obj0_lsp_labels.append(self.SR_LABEL3)
        pfx_obj0_lsp_labels.append(self.SR_LABEL4)

        prefix_type = pfx_obj0.hld_obj.get_prefix_type()
        self.assertEqual(prefix_type, sdk.la_prefix_object.prefix_type_e_GLOBAL)

        pfx_obj0.hld_obj.set_global_lsp_properties(pfx_obj0_lsp_labels, None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        # Enable IPv6 Explicit Null
        pfx_obj0.hld_obj.set_ipv6_explicit_null_enabled(True)

        # Create a second Prefix Object
        pfx_obj1 = T.global_prefix_object(self, self.device, mpls_headend_base.PREFIX1_GID, nh_ecmp1)
        self.assertNotEqual(pfx_obj1.hld_obj, None)

        prefix_type = pfx_obj1.hld_obj.get_prefix_type()
        self.assertEqual(prefix_type, sdk.la_prefix_object.prefix_type_e_GLOBAL)

        # Assign different properties to this Prefix Object
        pfx_obj1_lsp_labels = []
        pfx_obj1_lsp_labels.append(self.SR_LABEL5)
        pfx_obj1_lsp_labels.append(self.SR_LABEL6)
        pfx_obj1_lsp_labels.append(self.SR_LABEL7)

        pfx_obj1.hld_obj.set_global_lsp_properties(pfx_obj1_lsp_labels, None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        # Also set IPv6 Explicit NULL enabled after LSP properties have been
        # configured. This should trigger the additional_labels_table to be
        # programmed with a new index
        pfx_obj1.hld_obj.set_ipv6_explicit_null_enabled(True)

        # Destroy the old counter set
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, None)
        self.device.destroy(self.egress_counter)

        # Create and set counter set for MPLS SR accounting
        egress_counter = self.device.create_counter(sdk.la_l3_protocol_counter_e_LAST)
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, egress_counter)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj0,
                               mpls_headend_base.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_0_SR_WITH_EXP_NULL,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

        packet_count, byte_count = egress_counter.read(sdk.la_l3_protocol_counter_e_MPLS_SR, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_0_SR_WITH_EXP_NULL, byte_count)

        self.ip_impl.modify_route(self.topology.vrf, prefix, pfx_obj1)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_1_SR_WITH_EXP_NULL,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

        # Disable IPv6 Explicit Null
        # Only the first should release the index assigned for the
        # additional_labels_table
        pfx_obj1.hld_obj.set_ipv6_explicit_null_enabled(False)
        pfx_obj0.hld_obj.set_ipv6_explicit_null_enabled(False)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_1_SR_WITHOUT_EXP_NULL,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

        pfx_obj1.hld_obj.clear_global_lsp_properties()
        pfx_obj0.hld_obj.clear_global_lsp_properties()

    def _test_sr_global_per_protocol_counters(self, protocol, add_lsp_counter=True):
        nh_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp1, None)
        nh_ecmp1.add_member(self.l3_port_impl.reg_nh.hld_obj)

        pfx_obj = T.global_prefix_object(self, self.device, mpls_headend_base.PREFIX1_GID, nh_ecmp1)
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
        counter_mode = sdk.la_prefix_object.lsp_counter_mode_e_LABEL

        # Create a counter-set to account for protocol
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(2)
            counter_mode = sdk.la_prefix_object.lsp_counter_mode_e_PER_PROTOCOL

        lsp_labels.append(self.SR_LABEL0)
        lsp_labels.append(self.SR_LABEL1)
        lsp_labels.append(self.SR_LABEL2)

        pfx_obj.hld_obj.set_global_lsp_properties(lsp_labels, lsp_counter, counter_mode)
        pfx_obj.hld_obj.set_ipv6_explicit_null_enabled(True)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               mpls_headend_base.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SR, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = lsp_counter.read(protocol, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR, byte_count)

        packet_count, byte_count = egress_counter.read(sdk.la_l3_protocol_counter_e_MPLS_SR, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR, byte_count)

        pfx_obj.hld_obj.clear_global_lsp_properties()

    def _test_sr_global_with_4_labels(self):
        nh_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp1, None)
        nh_ecmp1.add_member(self.l3_port_impl.reg_nh.hld_obj)

        pfx_obj = T.global_prefix_object(self, self.device, mpls_headend_base.PREFIX1_GID, nh_ecmp1)
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
        lsp_counter = self.device.create_counter(1)
        lsp_labels.append(self.SR_LABEL0)
        lsp_labels.append(self.SR_LABEL1)
        lsp_labels.append(self.SR_LABEL2)
        lsp_labels.append(self.SR_LABEL3)

        pfx_obj.hld_obj.set_global_lsp_properties(lsp_labels, lsp_counter, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               mpls_headend_base.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SR_4_LABELS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = lsp_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_4_LABELS, byte_count)

        packet_count, byte_count = egress_counter.read(sdk.la_l3_protocol_counter_e_MPLS_SR, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_4_LABELS, byte_count)

        pfx_obj.hld_obj.clear_global_lsp_properties()

    def _test_sr_global_with_5_labels(self):
        nh_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp1, None)
        nh_ecmp1.add_member(self.l3_port_impl.reg_nh.hld_obj)

        pfx_obj = T.global_prefix_object(self, self.device, mpls_headend_base.PREFIX1_GID, nh_ecmp1)
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
        lsp_counter = self.device.create_counter(1)
        lsp_labels.append(self.SR_LABEL0)
        lsp_labels.append(self.SR_LABEL1)
        lsp_labels.append(self.SR_LABEL2)
        lsp_labels.append(self.SR_LABEL3)
        lsp_labels.append(self.SR_LABEL4)

        pfx_obj.hld_obj.set_global_lsp_properties(lsp_labels, lsp_counter, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               mpls_headend_base.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SR_5_LABELS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = lsp_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_5_LABELS, byte_count)

        packet_count, byte_count = egress_counter.read(sdk.la_l3_protocol_counter_e_MPLS_SR, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_5_LABELS, byte_count)

        pfx_obj.hld_obj.clear_global_lsp_properties()

    def _test_sr_global_with_6_labels(self):
        nh_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp1, None)
        nh_ecmp1.add_member(self.l3_port_impl.reg_nh.hld_obj)

        pfx_obj = T.global_prefix_object(self, self.device, mpls_headend_base.PREFIX1_GID, nh_ecmp1)
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
        lsp_counter = self.device.create_counter(1)
        lsp_labels.append(self.SR_LABEL0)
        lsp_labels.append(self.SR_LABEL1)
        lsp_labels.append(self.SR_LABEL2)
        lsp_labels.append(self.SR_LABEL3)
        lsp_labels.append(self.SR_LABEL4)
        lsp_labels.append(self.SR_LABEL5)

        pfx_obj.hld_obj.set_global_lsp_properties(lsp_labels, lsp_counter, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               mpls_headend_base.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SR_6_LABELS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = lsp_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_6_LABELS, byte_count)

        packet_count, byte_count = egress_counter.read(sdk.la_l3_protocol_counter_e_MPLS_SR, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_6_LABELS, byte_count)

        pfx_obj.hld_obj.clear_global_lsp_properties()

    def _test_sr_global_with_7_labels(self, add_dm_counter=False):
        nh_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp1, None)
        nh_ecmp1.add_member(self.l3_port_impl.reg_nh.hld_obj)

        pfx_obj = T.global_prefix_object(self, self.device, mpls_headend_base.PREFIX1_GID, nh_ecmp1)
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
        lsp_counter = self.device.create_counter(1)
        lsp_labels.append(self.SR_LABEL0)
        lsp_labels.append(self.SR_LABEL1)
        lsp_labels.append(self.SR_LABEL2)
        lsp_labels.append(self.SR_LABEL3)
        lsp_labels.append(self.SR_LABEL4)
        lsp_labels.append(self.SR_LABEL5)
        lsp_labels.append(self.SR_LABEL6)

        counter_mode = sdk.la_prefix_object.lsp_counter_mode_e_LABEL

        if add_dm_counter:
            self.topology.rx_eth_port.hld_obj.set_traffic_matrix_interface_type(sdk.la_ethernet_port.traffic_matrix_type_e_EXTERNAL)
            lsp_counter = self.device.create_counter(2)
            counter_mode = sdk.la_prefix_object.lsp_counter_mode_e_TRAFFIC_MATRIX

        pfx_obj.hld_obj.set_global_lsp_properties(lsp_labels, lsp_counter, counter_mode)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               mpls_headend_base.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SR_7_LABELS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_dm_counter:
            packet_count, byte_count = lsp_counter.read(1, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_7_LABELS, byte_count)

            # Now disable the ingress port marking as external interface. Retest the packet.
            # Counter at offset 0 should increment
            self.topology.rx_eth_port.hld_obj.set_traffic_matrix_interface_type(sdk.la_ethernet_port.traffic_matrix_type_e_INTERNAL)
            U.run_and_compare(self, self.device,
                              self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                              self.EXPECTED_OUTPUT_PACKET_SR_7_LABELS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
            packet_count, byte_count = lsp_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_7_LABELS, byte_count)

        else:
            packet_count, byte_count = lsp_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_7_LABELS, byte_count)

        packet_count, byte_count = egress_counter.read(sdk.la_l3_protocol_counter_e_MPLS_SR, True, True)
        self.assertEqual(packet_count, 2 if add_dm_counter else 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_7_LABELS,
                                   (byte_count / 2) if add_dm_counter else byte_count)

        pfx_obj.hld_obj.clear_global_lsp_properties()

    def _test_sr_global_with_8_labels(self):
        nh_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp1, None)
        nh_ecmp1.add_member(self.l3_port_impl.reg_nh.hld_obj)

        pfx_obj = T.global_prefix_object(self, self.device, mpls_headend_base.PREFIX1_GID, nh_ecmp1)
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
        lsp_counter = self.device.create_counter(1)
        lsp_labels.append(self.SR_LABEL0)
        lsp_labels.append(self.SR_LABEL1)
        lsp_labels.append(self.SR_LABEL2)
        lsp_labels.append(self.SR_LABEL3)
        lsp_labels.append(self.SR_LABEL4)
        lsp_labels.append(self.SR_LABEL5)
        lsp_labels.append(self.SR_LABEL6)
        lsp_labels.append(self.SR_LABEL7)

        pfx_obj.hld_obj.set_global_lsp_properties(lsp_labels, lsp_counter, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               mpls_headend_base.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SR_8_LABELS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = lsp_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_8_LABELS, byte_count)

        packet_count, byte_count = egress_counter.read(sdk.la_l3_protocol_counter_e_MPLS_SR, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_8_LABELS, byte_count)

        pfx_obj.hld_obj.clear_global_lsp_properties()

    def _test_sr_global_label_update(self):
        nh_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp1, None)
        nh_ecmp1.add_member(self.l3_port_impl.reg_nh.hld_obj)

        pfx_obj = T.global_prefix_object(self, self.device, mpls_headend_base.PREFIX1_GID, nh_ecmp1)
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
        lsp_counter = self.device.create_counter(1)
        lsp_labels.append(self.SR_LABEL0)
        lsp_labels.append(self.SR_LABEL1)
        lsp_labels.append(self.SR_LABEL2)
        lsp_labels.append(self.SR_LABEL3)

        pfx_obj.hld_obj.set_global_lsp_properties(lsp_labels, lsp_counter, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               mpls_headend_base.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SR_4_LABELS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = lsp_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_4_LABELS, byte_count)

        packet_count, byte_count = egress_counter.read(sdk.la_l3_protocol_counter_e_MPLS_SR, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_4_LABELS, byte_count)

        # Update the label stack with 1 additional labels to test the additional label tables
        # Tests 4 to > 4
        lsp_labels.append(self.SR_LABEL4)
        pfx_obj.hld_obj.set_global_lsp_properties(lsp_labels, lsp_counter, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SR_5_LABELS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = lsp_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_5_LABELS, byte_count)

        packet_count, byte_count = egress_counter.read(sdk.la_l3_protocol_counter_e_MPLS_SR, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_5_LABELS, byte_count)

        pfx_obj.hld_obj.clear_global_lsp_properties()

        # Update the label stack with 1 additional labels to test the additional label tables
        # Tests > 4 to > 4
        lsp_labels.append(self.SR_LABEL5)
        pfx_obj.hld_obj.set_global_lsp_properties(lsp_labels, lsp_counter, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SR_6_LABELS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = lsp_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_6_LABELS, byte_count)

        packet_count, byte_count = egress_counter.read(sdk.la_l3_protocol_counter_e_MPLS_SR, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_6_LABELS, byte_count)

        # Update the label stack with 1 additional labels to test the additional label tables
        # Tests > 4 to < 4
        lsp_labels = []
        lsp_labels.append(self.SR_LABEL0)
        lsp_labels.append(self.SR_LABEL1)
        lsp_labels.append(self.SR_LABEL2)
        lsp_labels.append(self.SR_LABEL3)
        pfx_obj.hld_obj.set_global_lsp_properties(lsp_labels, lsp_counter, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SR_4_LABELS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = lsp_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_4_LABELS, byte_count)

        packet_count, byte_count = egress_counter.read(sdk.la_l3_protocol_counter_e_MPLS_SR, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SR_4_LABELS, byte_count)

        pfx_obj.hld_obj.clear_global_lsp_properties()

    def _test_prefix_global_ecmp_update_destination(self):
        nh_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp1, None)
        nh_ecmp1.add_member(self.l3_port_impl.reg_nh.hld_obj)

        nh_ecmp2 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp2, None)
        nh_ecmp2.add_member(self.l3_port_impl.reg_nh.hld_obj)

        pfx_obj = T.global_prefix_object(self, self.device, mpls_headend_base.PREFIX1_GID, nh_ecmp1)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               mpls_headend_base.PRIVATE_DATA_DEFAULT)

        # Should be able to change the destination to a new ECMP group
        pfx_obj.hld_obj.set_destination(nh_ecmp2)

    def _test_prefix_global_error_handling(self):
        nh_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp1, None)
        nh_ecmp1.add_member(self.l3_port_impl.reg_nh.hld_obj)

        # Create a Global LSP Prefix
        pfx_obj0 = T.global_prefix_object(self, self.device, mpls_headend_base.PREFIX0_GID, nh_ecmp1)
        self.assertNotEqual(pfx_obj0.hld_obj, None)

        nh_ecmp2 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp2, None)
        nh_ecmp2.add_member(self.l3_port_impl.reg_nh.hld_obj)

        # Create a LDP LSP Prefix
        pfx_obj1 = T.prefix_object(self, self.device, mpls_headend_base.PREFIX1_GID, nh_ecmp2)
        self.assertNotEqual(pfx_obj1.hld_obj, None)

        # Cannot change a Global LSP Prefix destination to an ECMP whose parent is a LDP Prefix
        with self.assertRaises(sdk.InvalException):
            pfx_obj0.hld_obj.set_destination(nh_ecmp2)

        # Cannot change a LDP Prefix destination to an ECMP whose parent is a Global LSP Prefix
        with self.assertRaises(sdk.InvalException):
            pfx_obj1.hld_obj.set_destination(nh_ecmp1)

        # Create another Global LSP Prefix with the same destination as pfx_obj0, the first global LSP Prefix
        pfx_obj2 = T.global_prefix_object(self, self.device, mpls_headend_base.PREFIX_OFFSET_2_GID, nh_ecmp1)
        self.assertNotEqual(pfx_obj2.hld_obj, None)

        # Destroy the first Global LSP Prefix
        pfx_obj0.destroy()

        # Cannot create a LDP LSP Prefix whose destination is an ECMP with the parent still being a Global LSP Prefix
        with self.assertRaises(sdk.InvalException):
            pfx_obj3 = T.prefix_object(self, self.device, mpls_headend_base.PREFIX_OFFSET_3_GID, nh_ecmp1)

        # Destroy the second Global LSP Prefix
        pfx_obj2.destroy()

        pfx_obj3 = T.prefix_object(self, self.device, mpls_headend_base.PREFIX_OFFSET_3_GID, nh_ecmp1)
        self.assertNotEqual(pfx_obj3.hld_obj, None)

    def _test_ldp_tenh_error_handling1(self):
        # Create two separate LDPoTE tunnels
        te_tunnel1 = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)
        te_tunnel2 = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL2_GID, self.l3_port_impl.def_nh.hld_obj)

        # Create an ECMP group with the first TE tunnel as a member
        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel1.hld_obj)

        # Create a Prefix Object with the ECMP group sa a destination
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)

        # Update the LDP properties for the Prefix Object
        pfx_obj.hld_obj.set_te_tunnel_lsp_properties(te_tunnel1.hld_obj, [], None)

        # Update the ECMP with a member list having the second TE tunnel
        members = []
        members.append(te_tunnel2.hld_obj)
        te_ecmp.set_members(members)

        # Destroy the TE tunnel. This should fail since the TE tunnel is still
        # being used for LDP Encap entries.
        with self.assertRaises(sdk.BusyException):
            te_tunnel1.destroy()

        pfx_obj.hld_obj.clear_te_tunnel_lsp_properties(te_tunnel1.hld_obj)

        # Destroy the TE tunnel should now pass
        te_tunnel1.destroy()

    def _test_ldp_tenh_error_handling2(self):
        # Create and set counter-set for accounting to test L3 DLP attributes propagation
        egress_counter = self.device.create_counter(sdk.la_l3_protocol_counter_e_LAST)
        self.l3_port_impl.tx_port_ext.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, egress_counter)

        # Create LDPoTE tunnel
        te_tunnel1 = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.ext_nh.hld_obj)

        # Set the tunnel attributes
        te_tunnel1.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, [], None)
        # Set the tunnel attributes a second time to handle attribute dependencies correctly
        te_tunnel1.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, [], None)

        te_tunnel1.hld_obj.clear_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj)

        # Destroy the TE tunnel should now pass
        te_tunnel1.destroy()
        self.l3_port_impl.ext_fec.destroy()
        self.l3_port_impl.ext_nh.destroy()

        # This step below should not trigger attribute handling on the tunnel
        # after the tunnel is destroyed
        self.l3_port_impl.tx_port_ext.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, None)
        self.l3_port_impl.tx_port_ext.destroy()

    def _test_prefix_ldp_tenh_to_mpls(self, add_lsp_counter=True):
        te_tunnel = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_tunnel.hld_obj)

        lsp_counter = None
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_te_tunnel_lsp_properties(te_tunnel.hld_obj, lsp_labels, lsp_counter)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_LDPoTE, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_LDPoTE, byte_count)

    def _test_prefix_ldp_tenh_to_mpls_te_impl_null(self, add_lsp_counter=True):
        te_tunnel = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_tunnel.hld_obj)

        lsp_counter = None
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_te_tunnel_lsp_properties(te_tunnel.hld_obj, lsp_labels, lsp_counter)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_LDPoTE_TE_IMPL_NULL,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_LDPoTE_TE_IMPL_NULL, byte_count)

    def _test_prefix_nh_to_ip(self, add_lsp_counter=True):
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)

        lsp_counter = None
        lsp_labels = []
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

    def _test_prefix_nh_to_ip_flood(self, add_lsp_counter=True):
        self.flood_setup()
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.ext_nh.hld_obj)

        lsp_counter = None
        lsp_labels = []
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
                               'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES1 + 2})

        U.run_and_compare_list(self, self.device, ingress_packet, egress_packets)

        packet_count, byte_count = self.l2_ext_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.l2_ext2_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.egress_ext_counter.read(self.protocol, True, True)
        self.assertEqual(packet_count, 1)
        #U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_IP_FLOOD, byte_count)

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
                               'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES1 + 2})

        U.run_and_compare_list(self, self.device, ingress_packet, egress_packets)

        packet_count, byte_count = self.l2_ext_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.l2_ext2_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.egress_ext_counter.read(self.protocol, True, True)
        self.assertEqual(packet_count, 1)
        #U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_IP_FLOOD, byte_count)

    def _test_prefix_nh_to_mpls(self):
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
                          self.EXPECTED_OUTPUT_PACKET_MPLS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

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

    def _test_prefix_nh_to_mpls_update_label(self, add_lsp_counter=True):
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)

        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

        updated_lsp_labels = []
        updated_lsp_labels.append(self.NEW_LDP_LABEL)

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            updated_lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        # Check get_nh_lsp_properties
        res_lsp_labels = []

        (res_lsp_labels, res_lsp_counter, _) = pfx_obj.hld_obj.get_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj)

        for i in range(0, len(updated_lsp_labels)):
            self.assertEqual(res_lsp_labels[i].label, updated_lsp_labels[i].label)
            if add_lsp_counter:
                self.assertEqual(res_lsp_counter.this, lsp_counter.this)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_UPDATED_MPLS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

    def _test_prefix_tenh_to_ip(self):
        te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_tunnel.hld_obj)

        te_labels = []
        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, None)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        if(self.l3_port_impl.is_svi and self.php_protocol == sdk.la_l3_protocol_e_IPV4_UC):
            self.set_l2_ac_vlan_tag(self.topology.tx_l2_ac_port_reg)
            self.output_packet = self.EXPECTED_OUTPUT_PACKET_IP_NULL_WITH_VLAN
        else:
            self.output_packet = self.EXPECTED_OUTPUT_PACKET_IP_NULL

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.output_packet, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.l2_egress_counter.read(self.php_protocol, True, True)
        self.assertEqual(packet_count, self.l2_packet_count)
        packet_count, byte_count = self.egress_counter.read(self.php_protocol, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.output_packet, byte_count)

    def _test_prefix_tenh_to_ip_flood(self):
        self.flood_setup()
        te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.ext_nh.hld_obj)
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_tunnel.hld_obj)

        te_labels = []
        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, te_labels, None)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        egress_packets = []
        egress_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_IP_FLOOD, 'slice': T.TX_SLICE_EXT,
                               'ifg': T.TX_IFG_EXT, 'pif': self.l3_port_impl.serdes_ext})
        egress_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_IP_FLOOD, 'slice': T.TX_SLICE_EXT,
                               'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES1 + 2})

        U.run_and_compare_list(self, self.device, ingress_packet, egress_packets)

        packet_count, byte_count = self.l2_ext_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.l2_ext2_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.egress_ext_counter.read(self.protocol, True, True)
        self.assertEqual(packet_count, 1)
        #U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_IP_FLOOD, byte_count)

    def _test_prefix_tenh_to_mpls(self):
        self.te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)

        # This uses a te-tunnel with no associated counter. For usage of TE counter, check ecmp test.
        self.te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, None)
        self.te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        self.pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.te_tunnel.hld_obj)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TE, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE, byte_count)

    def _test_prefix_tenh_to_mpls_getter(self):
        self._test_prefix_tenh_to_mpls()

        vrf_by_id = self.device.get_vrf_by_id(T.VRF_GID)
        self.assertEqual(vrf_by_id.this, self.topology.vrf.hld_obj.this)

        prefix_obj_by_id = self.device.get_prefix_object_by_id(mpls_headend_base.PREFIX1_GID)
        self.assertEqual(prefix_obj_by_id.this, self.pfx_obj.hld_obj.this)

        ipv6_explicit_null_enabled = self.te_tunnel.hld_obj.get_ipv6_explicit_null_enabled()
        self.assertEqual(ipv6_explicit_null_enabled, True)

    def _test_swap_ecmp_ldp_tenh_to_mpls(self, add_lsp_counter=True):
        te_tunnel = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)

        lsp_counter = None
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_te_tunnel_lsp_properties(te_tunnel.hld_obj, lsp_labels, lsp_counter)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_MPLS_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SWAP_LDPoTE, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SWAP_LDPoTE, byte_count)

        # add L3VPN POP-And-Fwd entry. Send additional label and reverify.
        lsr.add_vpn_decap(self.INPUT_POP_FWD_LABEL, None)

        U.run_and_compare(self, self.device,
                          self.INPUT_MPLS_PACKET_POP_FWD, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SWAP_LDPoTE, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def _test_swap_ecmp_ldp_tenh_to_mpls_double_label(self, add_lsp_counter=True):
        te_tunnel = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)

        lsp_counter = None
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_te_tunnel_lsp_properties(te_tunnel.hld_obj, lsp_labels, lsp_counter)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_MPLS_PACKET_DOUBLE_LABEL,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_SWAP_DOUBLE_LABEL_LDPoTE,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SWAP_DOUBLE_LABEL_LDPoTE, byte_count)

    def _test_swap_with_vlan_ecmp_ldp_tenh_to_mpls(self, add_lsp_counter=True):
        te_tunnel = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_counter = None
        if add_lsp_counter:
            te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_ecmp)

        lsp_counter = None
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_te_tunnel_lsp_properties(te_tunnel.hld_obj, lsp_labels, lsp_counter)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL0, pfx_obj.hld_obj, self.PRIVATE_DATA)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_MPLS_PACKET_WITH_VLAN,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_SWAP_WITH_VLAN_LDPoTE,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

        if add_lsp_counter:
            packet_count, byte_count = te_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_SWAP_WITH_VLAN_LDPoTE, byte_count)

    def _test_prefix_object_vpn_properties(self):
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)

        vpn_labels = []
        vpn_labels.append(self.VPN_LABEL)
        # Program the IPV4 VPN labels
        pfx_obj.hld_obj.set_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV4, vpn_labels)

        ipv6_vpn_labels = []
        ipv6_vpn_labels.append(self.IP6PE_VPN_LABEL)
        # Program the IPV6 VPN labels
        pfx_obj.hld_obj.set_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6, ipv6_vpn_labels)

        # Check v4 vrf_properties
        res_vpn_labels = []
        (res_vpn_labels) = pfx_obj.hld_obj.get_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV4)
        self.assertEqual(res_vpn_labels[0].label, vpn_labels[0].label)

        # Check v6 vrf_properties
        res_vpn_labels = []
        (res_vpn_labels) = pfx_obj.hld_obj.get_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6)
        self.assertEqual(res_vpn_labels[0].label, ipv6_vpn_labels[0].label)

        # Clear v6 vrf_properties
        pfx_obj.hld_obj.clear_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6)

        # Check v4 vrf_properties to be intact
        res_vpn_labels = []
        (res_vpn_labels) = pfx_obj.hld_obj.get_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV4)
        self.assertEqual(res_vpn_labels[0].label, vpn_labels[0].label)

        # Re-program the IPV6 VPN labels
        pfx_obj.hld_obj.set_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6, ipv6_vpn_labels)

        # Clear v4 vrf_properties
        pfx_obj.hld_obj.clear_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV4)

        # Check v6 vrf_properties to be intact
        res_vpn_labels = []
        (res_vpn_labels) = pfx_obj.hld_obj.get_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6)
        self.assertEqual(res_vpn_labels[0].label, ipv6_vpn_labels[0].label)

        # Clear v4 & v6 vrf_properties
        pfx_obj.hld_obj.clear_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV4)
        pfx_obj.hld_obj.clear_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6)

        res_vpn_labels = []
        with self.assertRaises(sdk.NotFoundException):
            (res_vpn_labels) = pfx_obj.hld_obj.get_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV4)

        res_vpn_labels = []
        with self.assertRaises(sdk.NotFoundException):
            (res_vpn_labels) = pfx_obj.hld_obj.get_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6)

    def _test_ip6pe_fec_prefix_nh_to_mpls_setup(self, add_lsp_counter=True):
        self.pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)

        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)
        lsp_labels = []
        lsp_labels.append(self.IP6PE_LDP_LABEL)

        vpn_labels = []
        vpn_labels.append(self.IP6PE_VPN_LABEL)

        self.pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.fec = T.fec(self, self.device, self.pfx_obj)
        self.pfx_obj.hld_obj.set_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6, vpn_labels)

        self.prefix = self.ip_impl.build_prefix(self.DIP, length=16)

    def _test_ip6pe_fec_prefix_nh_to_mpls_run(self):
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_6PE, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_6PE, byte_count)

    def _test_ip6pe_ecmp_prefix_tenh_to_mpls_setup(self):
        te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)

        # This uses a te-tunnel with no associated counter. For usage of TE counter, check ecmp test.
        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, None)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        self.pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_tunnel.hld_obj)

        vpn_labels = []
        vpn_labels.append(self.IP6PE_VPN_LABEL)

        self.m_ecmp_rec = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.assertNotEqual(self.m_ecmp_rec, None)
        self.m_ecmp_rec.add_member(self.pfx_obj.hld_obj)

        self.prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.pfx_obj.hld_obj.set_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6, vpn_labels)

    def _test_ip6pe_ecmp_prefix_tenh_to_mpls_run(self):
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_6PE_TE, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_6PE, byte_count)

    def _test_ip6pe_ecmp_prefix_nh_to_mpls_setup(self, add_lsp_counter=True):
        self.pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)

        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)
        lsp_labels = []
        lsp_labels.append(self.IP6PE_LDP_LABEL)

        vpn_labels = []
        vpn_labels.append(self.IP6PE_VPN_LABEL)

        self.pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.m_ecmp_rec = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.assertNotEqual(self.m_ecmp_rec, None)
        self.m_ecmp_rec.add_member(self.pfx_obj.hld_obj)

        self.prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.pfx_obj.hld_obj.set_vrf_properties(self.topology.vrf.hld_obj, sdk.la_ip_version_e_IPV6, vpn_labels)

    def _test_ip6pe_ecmp_prefix_nh_to_mpls_run(self):
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_6PE, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_6PE, byte_count)

    def _test_ip6pe_with_global_vrf_setup(self, add_lsp_counter=True):
        self.pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)

        lsp_counter = None
        if add_lsp_counter:
            lsp_counter = self.device.create_counter(1)
        lsp_labels = []

        vpn_labels = []
        vpn_labels.append(self.IP6PE_VPN_LABEL)

        self.pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.m_ecmp_rec = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.assertNotEqual(self.m_ecmp_rec, None)
        self.m_ecmp_rec.add_member(self.pfx_obj.hld_obj)

        self.prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.pfx_obj.hld_obj.set_vrf_properties(self.topology.global_vrf.hld_obj, sdk.la_ip_version_e_IPV6, vpn_labels)

    def _test_ip6pe_with_global_vrf_run(self):
        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET_GLOBAL_VRF,
            T.TX_SLICE_EXT,
            T.TX_IFG_EXT,
            T.FIRST_SERDES_L3,
            self.EXPECTED_OUTPUT_PACKET_6PE_WITH_GLOBAL_VRF,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(self.protocol, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_6PE_WITH_GLOBAL_VRF, byte_count)

    def _test_clear_prefix_ldp_tenh_lsp_properties(self):
        te_tunnel = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_tunnel.hld_obj)

        te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)
        te_labels.append(self.PRIMARY_TE_LABEL)

        # Set the label stack
        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)

        lsp_counter = self.device.create_counter(1)
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_te_tunnel_lsp_properties(te_tunnel.hld_obj, lsp_labels, lsp_counter)

        # Check get_nh_lsp_properties on NH
        res_te_labels = []
        (res_te_labels, res_te_counter) = te_tunnel.hld_obj.get_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj)
        for i in range(0, len(te_labels)):
            self.assertEqual(res_te_labels[i].label, te_labels[i].label)
            self.assertEqual(res_te_counter.this, te_counter.this)

        # Check get_te_tunnel_lsp_properties on prefix_object
        res_lsp_labels = []
        (res_lsp_labels, res_lsp_counter) = pfx_obj.hld_obj.get_te_tunnel_lsp_properties(te_tunnel.hld_obj)
        for i in range(0, len(lsp_labels)):
            self.assertEqual(res_lsp_labels[i].label, lsp_labels[i].label)
            self.assertEqual(res_lsp_counter.this, lsp_counter.this)

        # Clear the te_tunnel-nh entry
        te_tunnel.hld_obj.clear_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj)

        # Clear the te_tunnel-pfx_obj entry
        pfx_obj.hld_obj.clear_te_tunnel_lsp_properties(te_tunnel.hld_obj)

        # get_nh_lsp_properties should not find the te_tunnel-nh entry
        try:
            te_tunnel.hld_obj.get_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj)
            self.assertFail()
        except sdk.BaseException:
            pass

        # get_te_tunnel_lsp_properties should not find the te_tunnel-pfx_obj entry
        try:
            te_tunnel.hld_obj.get_te_tunnel_lsp_properties(te_tunnel.hld_obj)
            self.assertFail()
        except BaseException:
            pass

    def _test_clear_prefix_nh_lsp_properties(self):
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)

        lsp_counter = self.device.create_counter(1)
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        # Set the label stack
        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        # Check get_nh_lsp_properties
        res_lsp_labels = []
        (res_lsp_labels, res_lsp_counter, _) = pfx_obj.hld_obj.get_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj)

        for i in range(0, len(lsp_labels)):
            self.assertEqual(res_lsp_labels[i].label, lsp_labels[i].label)
            self.assertEqual(res_lsp_counter.this, lsp_counter.this)

        # Clear the prefix-nh entry
        pfx_obj.hld_obj.clear_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj)

        # get_nh_lsp_properties should not find the prefix-nh entry
        try:
            pfx_obj.hld_obj.get_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj)
            self.assertFail()
        except sdk.BaseException:
            pass

    def _test_clear_prefix_tenh_lsp_properties(self):
        te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_tunnel.hld_obj)

        te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)
        te_labels.append(self.PRIMARY_TE_LABEL)

        # Set the label stack
        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)

        # Check get_nh_lsp_properties
        res_te_labels = []
        (res_te_labels, res_te_counter) = te_tunnel.hld_obj.get_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj)
        for i in range(0, len(te_labels)):
            self.assertEqual(res_te_labels[i].label, te_labels[i].label)
            self.assertEqual(res_te_counter.this, te_counter.this)

        # get_nh_lsp_properties should fail on prefix-te_tunnel entry
        try:
            te_tunnel.hld_obj.get_nh_lsp_properties(pfx_obj.hld_obj)
            self.assertFail()
        except BaseException:
            pass

        # Clear the te_tunnel-nh entry
        te_tunnel.hld_obj.clear_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj)

        # get_nh_lsp_properties should not find the te_tunnel-nh entry
        try:
            te_tunnel.hld_obj.get_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj)
            self.assertFail()
        except sdk.BaseException:
            pass

    def _test_invalid_prefix(self):
        te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        # Invalid Prefix Object GID
        try:
            pfx_obj = T.prefix_object(self, self.device, self.PREFIX_INVALID_GID, te_tunnel.hld_obj)
            self.assertFail()
        except sdk.BaseException:
            pass

        # Prefix Object GID pointing to a Wide Entry
        pfx_obj0 = T.prefix_object(self, self.device, self.PREFIX_OFFSET_0_GID, te_tunnel.hld_obj)
        # Prefix Object GID pointing to a Wide Entry
        pfx_obj1 = T.prefix_object(self, self.device, self.PREFIX_OFFSET_1_GID, te_tunnel.hld_obj)

        # Prefix Object GID is already Used
        try:
            pfx_obj = T.prefix_object(self, self.device, self.PREFIX_OFFSET_0_GID, te_tunnel.hld_obj)
            self.assertFail()
        except sdk.BaseException:
            pass

        # Invalid Prefix Object GID pointing to a Wide Entry
        try:
            pfx_obj = T.prefix_object(self, self.device, self.PREFIX_OFFSET_2_GID, te_tunnel.hld_obj)
            self.assertFail()
        except sdk.BaseException:
            pass

        # Invalid Prefix Object GID pointing to a Wide Entry
        try:
            pfx_obj = T.prefix_object(self, self.device, self.PREFIX_OFFSET_3_GID, te_tunnel.hld_obj)
            self.assertFail()
        except sdk.BaseException:
            pass

        # Free Prefix ID at Offset 0
        pfx_obj0.destroy()
        # Reallocate valid Prefix Object GID at Offset 0 pointing to a Wide Entry
        pfx_obj0 = T.prefix_object(self, self.device, self.PREFIX_OFFSET_0_GID, te_tunnel.hld_obj)

        # Free Prefix ID at Offset 1
        pfx_obj1.destroy()
        # Reallocate valid Prefix Object GID at Offset 1 pointing to a Wide Entry
        pfx_obj1 = T.prefix_object(self, self.device, self.PREFIX_OFFSET_1_GID, te_tunnel.hld_obj)

        # Free Prefix ID at Offset 0
        pfx_obj0.destroy()
        # Reallocate valid Prefix Object GID at Offset 0 pointing to a Narrow Entry
        try:
            pfx_obj = T.prefix_object(self, self.device, self.PREFIX_OFFSET_0_GID, self.l3_port_impl.reg_nh.hld_obj)
            self.assertFail()

            pfx_obj = T.prefix_object(self, self.device, self.PREFIX_OFFSET_1_GID, self.l3_port_impl.reg_nh.hld_obj)
            self.assertFail()

            pfx_obj = T.prefix_object(self, self.device, self.PREFIX_OFFSET_2_GID, self.l3_port_impl.reg_nh.hld_obj)
            self.assertFail()

            pfx_obj = T.prefix_object(self, self.device, self.PREFIX_OFFSET_3_GID, self.l3_port_impl.reg_nh.hld_obj)
            self.assertFail()
        except sdk.BaseException:
            pass
        # Reallocate valid Prefix Object GID at Offset 0 pointing to a Wide Entry
        pfx_obj0 = T.prefix_object(self, self.device, self.PREFIX_OFFSET_0_GID, te_tunnel.hld_obj)

        # Free Prefix ID at Offset 1
        pfx_obj1.destroy()
        # Reallocate valid Prefix Object GID pointing to a Narrow Entry. This
        # should fail because all the 4 GIDs are consumed by Wide Entries.
        try:
            pfx_obj = T.prefix_object(self, self.device, self.PREFIX_OFFSET_0_GID, self.l3_port_impl.reg_nh.hld_obj)
            self.assertFail()

            pfx_obj = T.prefix_object(self, self.device, self.PREFIX_OFFSET_1_GID, self.l3_port_impl.reg_nh.hld_obj)
            self.assertFail()

            pfx_obj = T.prefix_object(self, self.device, self.PREFIX_OFFSET_2_GID, self.l3_port_impl.reg_nh.hld_obj)
            self.assertFail()

            pfx_obj = T.prefix_object(self, self.device, self.PREFIX_OFFSET_3_GID, self.l3_port_impl.reg_nh.hld_obj)
            self.assertFail()
        except sdk.BaseException:
            pass
        # Reallocate valid Prefix Object GID at Offset 1 pointing to a Wide Entry
        pfx_obj1 = T.prefix_object(self, self.device, self.PREFIX_OFFSET_1_GID, te_tunnel.hld_obj)

        # Free all the WIDE Entries
        pfx_obj0.destroy()
        pfx_obj1.destroy()

        # Allocate Prefix Object pointing to a NARROW Entry
        pfx_obj0 = T.prefix_object(self, self.device, self.PREFIX_OFFSET_0_GID, self.l3_port_impl.reg_nh.hld_obj)

        # Allocate Prefix Object pointing to a NARROW Entry
        pfx_obj1 = T.prefix_object(self, self.device, self.PREFIX_OFFSET_1_GID, self.l3_port_impl.reg_nh.hld_obj)

        # Allocate Prefix Object pointing to a NARROW Entry
        pfx_obj2 = T.prefix_object(self, self.device, self.PREFIX_OFFSET_2_GID, self.l3_port_impl.reg_nh.hld_obj)

        # Allocate Prefix Object pointing to a NARROW Entry
        pfx_obj3 = T.prefix_object(self, self.device, self.PREFIX_OFFSET_3_GID, self.l3_port_impl.reg_nh.hld_obj)

        # Free all Entries
        pfx_obj0.destroy()
        pfx_obj1.destroy()
        pfx_obj2.destroy()
        pfx_obj3.destroy()
        te_tunnel.destroy()

    def _test_prefix_object_destination_entry_format(self):
        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(self.l3_port_impl.reg_nh.hld_obj)

        te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)
        te_tunnel2 = T.te_tunnel(self, self.device, self.TE_TUNNEL2_GID, self.l3_port_impl.reg_nh.hld_obj)

        # Prefix Object GID pointing to a Narrow Entry
        pfx_obj0 = T.prefix_object(self, self.device, self.PREFIX_OFFSET_0_GID, self.l3_port_impl.reg_nh.hld_obj)
        # Prefix Object GID pointing to a Narrow Entry
        pfx_obj1 = T.prefix_object(self, self.device, self.PREFIX_OFFSET_1_GID, nh_ecmp)

        # set the destination to Wide Entry
        with self.assertRaises((sdk.InvalException, sdk.BusyException)):
            pfx_obj0.hld_obj.set_destination(te_tunnel.hld_obj)

        # set the destination to Wide Entry
        with self.assertRaises((sdk.InvalException, sdk.BusyException)):
            pfx_obj1.hld_obj.set_destination(te_tunnel.hld_obj)

        pfx_obj0.destroy()
        pfx_obj1.destroy()

        # Prefix Object GID pointing to a Narrow Entry
        pfx_obj0 = T.prefix_object(self, self.device, self.PREFIX_OFFSET_0_GID, te_tunnel.hld_obj)
        # Prefix Object GID pointing to a Narrow Entry
        pfx_obj1 = T.prefix_object(self, self.device, self.PREFIX_OFFSET_1_GID, te_tunnel2.hld_obj)

        # set the destination to Narrow Entry
        with self.assertRaises((sdk.InvalException, sdk.BusyException)):
            pfx_obj0.hld_obj.set_destination(nh_ecmp)

        # set the destination to Wide Entry
        with self.assertRaises((sdk.InvalException, sdk.BusyException)):
            pfx_obj1.hld_obj.set_destination(nh_ecmp)
        pfx_obj0.destroy()
        pfx_obj1.destroy()

        # Prefix Object GID pointing to a Narrow Entry
        pfx_obj3 = T.prefix_object(self, self.device, self.PREFIX_OFFSET_3_GID, nh_ecmp)
        # set the destination to a Wide Entry
        with self.assertRaises((sdk.InvalException, sdk.BusyException)):
            pfx_obj3.hld_obj.set_destination(te_tunnel2.hld_obj)
        pfx_obj3.destroy()
        te_tunnel.destroy()
        te_tunnel2.destroy()
        self.device.destroy(nh_ecmp)

    def _test_set_prefix_object_destination(self):
        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(self.l3_port_impl.reg_nh.hld_obj)

        te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)
        te_tunnel2 = T.te_tunnel(self, self.device, self.TE_TUNNEL2_GID, self.l3_port_impl.reg_nh.hld_obj)

        # Prefix Object GID at offset 0 pointing to a Narrow Entry
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX_OFFSET_0_GID, self.l3_port_impl.reg_nh.hld_obj)

        lsp_counter = self.device.create_counter(1)
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = lsp_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

        # set destination N->N
        pfx_obj.hld_obj.set_destination(nh_ecmp)
        pfx_obj.hld_obj.set_destination(nh_ecmp)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = lsp_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

        te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)

        # set destination N->W
        pfx_obj.hld_obj.set_destination(te_tunnel.hld_obj)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TE, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = te_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE, byte_count)

        te_tunnel2.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)

        # set destination W->W
        pfx_obj.hld_obj.set_destination(te_tunnel2.hld_obj)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TE, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = te_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE, byte_count)

        # set destination W->N
        pfx_obj.hld_obj.set_destination(nh_ecmp)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = lsp_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        pfx_obj.destroy()

        # Prefix Object GID at offset 1 pointing to a Narrow Entry
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX_OFFSET_1_GID, self.l3_port_impl.reg_nh.hld_obj)

        lsp_counter = self.device.create_counter(1)
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = lsp_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

        # set destination N->N
        pfx_obj.hld_obj.set_destination(nh_ecmp)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = lsp_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

        te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)

        # set destination N->W
        pfx_obj.hld_obj.set_destination(te_tunnel.hld_obj)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TE, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = te_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE, byte_count)

        te_tunnel2.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)

        # set destination W->W
        pfx_obj.hld_obj.set_destination(te_tunnel2.hld_obj)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TE, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = te_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE, byte_count)

        # set destination W->N
        pfx_obj.hld_obj.set_destination(nh_ecmp)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = lsp_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        pfx_obj.destroy()
        te_tunnel.destroy()
        te_tunnel2.destroy()
        self.device.destroy(nh_ecmp)

    def _test_set_te_destination(self):
        te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        pfx_obj_nh0 = T.prefix_object(self, self.device, self.PREFIX0_GID, te_tunnel.hld_obj)

        pfx_obj_nh1 = T.prefix_object(self, self.device, self.PREFIX1_GID, te_tunnel.hld_obj)

        te_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp1, None)
        te_ecmp2 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp2, None)

        te_ecmp1.add_member(te_tunnel.hld_obj)
        te_ecmp1.add_member(te_tunnel.hld_obj)
        te_ecmp2.add_member(te_tunnel.hld_obj)
        te_ecmp2.add_member(te_tunnel.hld_obj)

        pfx_obj_ecmp1 = T.prefix_object(self, self.device, self.PREFIX_OFFSET_0_GID, te_ecmp1)

        pfx_obj_ecmp2 = T.prefix_object(self, self.device, self.PREFIX_OFFSET_1_GID, te_ecmp2)

        prot_monitor = T.protection_monitor(self, self.device)

        l3_prot_group1 = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID1,
            self.l3_port_impl.reg_nh.hld_obj,
            te_tunnel.hld_obj,
            prot_monitor.hld_obj)

        l3_prot_group2 = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID2,
            self.l3_port_impl.reg_nh.hld_obj,
            te_tunnel.hld_obj,
            prot_monitor.hld_obj)

        # Change NH to a different NH on a TE-tunnel
        te_tunnel.hld_obj.set_destination(self.l3_port_impl.ext_nh.hld_obj)
        te_labels = []
        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, te_labels, None)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        # Run traffic for pfx_obj_nh0
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj_nh0,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_IP_UPDATED_DESTINATION,
            T.TX_SLICE_EXT,
            T.TX_IFG_EXT,
            self.l3_port_impl.serdes_ext)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

        # Run traffic for pfx_obj_nh1
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj_nh1,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_IP_UPDATED_DESTINATION,
            T.TX_SLICE_EXT,
            T.TX_IFG_EXT,
            self.l3_port_impl.serdes_ext)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

        # Run traffic for pfx_obj_ecmp1
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj_ecmp1,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_IP_UPDATED_DESTINATION,
            T.TX_SLICE_EXT,
            T.TX_IFG_EXT,
            self.l3_port_impl.serdes_ext)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

        # Run traffic for pfx_obj_ecmp2
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj_ecmp2,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_IP_UPDATED_DESTINATION,
            T.TX_SLICE_EXT,
            T.TX_IFG_EXT,
            self.l3_port_impl.serdes_ext)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

        # Setup the Backup TE Tunnel
        te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.BACKUP_TE_LABEL)
        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, te_labels, te_counter)

        lsr = self.device.get_lsr()

        nhlfe = self.device.create_mpls_tunnel_protection_nhlfe(l3_prot_group1.hld_obj, self.PRIMARY_TE_LABEL, self.MP_LABEL)

        # Run traffic for l3_prot_group1
        lsr.add_route(self.INPUT_LABEL0, nhlfe, self.PRIVATE_DATA)

        prot_monitor.hld_obj.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)

        U.run_and_compare(self, self.device,
                          self.INPUT_MPLS_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TE_BACKUP, T.TX_SLICE_EXT, T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

        packet_count, byte_count = te_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE_BACKUP, byte_count)

        lsr.delete_route(self.INPUT_LABEL0)
        self.device.destroy(nhlfe)

        nhlfe = self.device.create_mpls_tunnel_protection_nhlfe(l3_prot_group2.hld_obj, self.PRIMARY_TE_LABEL, self.MP_LABEL)

        # Run traffic for l3_prot_group2
        lsr.add_route(self.INPUT_LABEL0, nhlfe, self.PRIVATE_DATA)

        prot_monitor.hld_obj.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)

        U.run_and_compare(self, self.device,
                          self.INPUT_MPLS_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TE_BACKUP, T.TX_SLICE_EXT, T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

        packet_count, byte_count = te_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE_BACKUP, byte_count)

        lsr.delete_route(self.INPUT_LABEL0)
        self.device.destroy(nhlfe)

        l3_prot_group1.destroy()
        l3_prot_group2.destroy()
        prot_monitor.destroy()

        prot_monitor1 = T.protection_monitor(self, self.device)

        l3_prot_group1 = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID1,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor1.hld_obj)

        # Change NH to P_NH on a TE-tunnel
        te_tunnel.hld_obj.set_destination(l3_prot_group1.hld_obj)
        te_labels = []
        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, None)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        # Run traffic for pfx_obj_nh0. Traffic should go through the
        # l3_prot_group1 and send the packet to the reg_nh
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj_nh0,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IP, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

        # Run traffic for pfx_obj_nh1
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj_nh1,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IP, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

        # Run traffic for pfx_obj_ecmp1
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj_ecmp1,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IP, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

        # Run traffic for pfx_obj_ecmp2
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj_ecmp2,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IP, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

        prot_monitor2 = T.protection_monitor(self, self.device)

        l3_prot_group2 = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID2,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor2.hld_obj)

        prot_monitor2.hld_obj.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)
        te_labels = []
        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, te_labels, None)

        # Change P_NH to a different P_NH on a TE-tunnel
        te_tunnel.hld_obj.set_destination(l3_prot_group2.hld_obj)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        # Run traffic for pfx_obj_nh0
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj_nh0,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_IP_UPDATED_DESTINATION,
            T.TX_SLICE_EXT,
            T.TX_IFG_EXT,
            self.l3_port_impl.serdes_ext)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

        # Run traffic for pfx_obj_nh1
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj_nh1,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_IP_UPDATED_DESTINATION,
            T.TX_SLICE_EXT,
            T.TX_IFG_EXT,
            self.l3_port_impl.serdes_ext)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

        # Run traffic for pfx_obj_ecmp1
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj_ecmp1,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_IP_UPDATED_DESTINATION,
            T.TX_SLICE_EXT,
            T.TX_IFG_EXT,
            self.l3_port_impl.serdes_ext)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

        # Run traffic for pfx_obj_ecmp2
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj_ecmp2,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_IP_UPDATED_DESTINATION,
            T.TX_SLICE_EXT,
            T.TX_IFG_EXT,
            self.l3_port_impl.serdes_ext)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

        # Change P_NH to a NH on a TE-tunnel
        te_tunnel.hld_obj.set_destination(self.l3_port_impl.reg_nh.hld_obj)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        # Run traffic for pfx_obj_nh0
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj_nh0,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IP, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

        # Run traffic for pfx_obj_nh1
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj_nh1,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IP, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

        # Run traffic for pfx_obj_ecmp1
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj_ecmp1,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IP, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

        # Run traffic for pfx_obj_ecmp2
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj_ecmp2,
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IP, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

        l3_prot_group1.destroy()
        l3_prot_group2.destroy()
        prot_monitor1.destroy()
        prot_monitor2.destroy()

        # To check the reference counting of TE tunnel attribute
        pfx_obj_ecmp1.destroy()
        te_ecmp1.remove_member(te_tunnel.hld_obj)
        te_ecmp1.remove_member(te_tunnel.hld_obj)
        self.device.destroy(te_ecmp1)

        pfx_obj_ecmp2.destroy()
        te_ecmp2.remove_member(te_tunnel.hld_obj)
        te_ecmp2.remove_member(te_tunnel.hld_obj)
        self.device.destroy(te_ecmp2)

        te_tunnel.hld_obj.set_destination(self.l3_port_impl.ext_nh.hld_obj)

    def _test_set_te_type(self):
        te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        # Changing the type after create should pass
        te_tunnel.hld_obj.set_tunnel_type(sdk.la_te_tunnel.tunnel_type_e_LDP_ENABLED)
        te_tunnel.hld_obj.set_tunnel_type(sdk.la_te_tunnel.tunnel_type_e_NORMAL)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, te_tunnel.hld_obj)

        # Setting the tunnel type to LDP_ENABLED should fail because a prefix is using it
        try:
            te_tunnel.hld_obj.set_tunnel_type(sdk.la_te_tunnel.tunnel_type_e_LDP_ENABLED)
            self.assertFail()
        except sdk.BaseException:
            pass

        pfx_obj.destroy()

        # Setting the tunnel type to LDP_ENABLED should pass after the prefix is removed
        te_tunnel.hld_obj.set_tunnel_type(sdk.la_te_tunnel.tunnel_type_e_LDP_ENABLED)
        te_tunnel.hld_obj.set_tunnel_type(sdk.la_te_tunnel.tunnel_type_e_NORMAL)

        te_counter = self.device.create_counter(1)
        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)

        # Set the label stack/counter
        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)

        # Setting the tunnel type to LDP_ENABLED should fail because it
        # has started being used as a NORMAL tunnel (Large-EM contains NH entries)
        try:
            te_tunnel.hld_obj.set_tunnel_type(sdk.la_te_tunnel.tunnel_type_e_LDP_ENABLED)
            self.assertFail()
        except sdk.BaseException:
            pass

        # Clear the te_tunnel-nh entry
        te_tunnel.hld_obj.clear_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj)

        # Change the type to LDP Enabled TE tunnel
        te_tunnel.hld_obj.set_tunnel_type(sdk.la_te_tunnel.tunnel_type_e_LDP_ENABLED)

        # Set the label stack/counter
        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, te_counter)

        # Setting the tunnel type to NORMAL should fail because it has
        # started being used as a LDP Enabled TE tunnel (DLP0-EM contains NH
        # entries)
        try:
            te_tunnel.hld_obj.set_tunnel_type(sdk.la_te_tunnel.tunnel_type_e_NORMAL)
            self.assertFail()
        except sdk.BaseException:
            pass

        # Clear the te_tunnel-nh entry
        te_tunnel.hld_obj.clear_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj)

        # Change the type to NORMAL TE tunnel
        te_tunnel.hld_obj.set_tunnel_type(sdk.la_te_tunnel.tunnel_type_e_NORMAL)
