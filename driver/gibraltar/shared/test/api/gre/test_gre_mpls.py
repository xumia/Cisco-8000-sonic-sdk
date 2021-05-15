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

import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import decor
import topology as T
import packet_test_defs as P
import ip_test_base
from sdk_test_case_base import *
import mtu.mtu_test_utils as MTU
import decor

S.load_contrib('mpls')


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
@unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
class test_gre_mpls(sdk_test_case_base):

    NUM_OF_NH = 10
    NH_GID_BASE = 0x613
    NH_DST_MAC_BASE = T.mac_addr('11:11:11:11:11:00')

    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_MPLS = 0xabcdef1234567890
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    GRE_PORT_GID = 0x901
    GRE_PORT_GID1 = 0x902
    GRE_TUNNEL_DESTINATION_GID = 0x674
    GRE_TUNNEL_DESTINATION_GID1 = 0x675
    GRE_SIP = T.ipv4_addr('12.10.12.11')
    GRE_SIP1 = T.ipv4_addr('14.10.12.11')
    GRE_DIP = T.ipv4_addr('12.1.95.250')
    GRE_DIP1 = T.ipv4_addr('14.1.95.250')
    NEW_TX_L3_AC_DEF_MAC = T.mac_addr('50:52:53:54:55:56')
    NEW_TX_L3_AC_EXT_MAC = T.mac_addr('50:52:53:54:55:56')

    OVL_DIP_ROUTE = T.ipv4_addr('21.1.1.0')
    OVL_SIP_ROUTE = T.ipv4_addr('11.1.1.0')
    OVL_SIP_ROUTE_2 = T.ipv4_addr('11.2.2.0')
    OVL_SIP_ROUTE_IPv6 = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:5555:0000:0000')
    OVL_SIP_ROUTE_IPv6_2 = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:0000')
    OVL_IP_PACKET_DMAC = NEW_TX_L3_AC_DEF_MAC.addr_str
    OVL_IP_PACKET_SMAC = '40:11:22:33:44:55'
    OVL_IP_PACKET_DIP = '21.1.1.1'
    OVL_IP_PACKET_SIP = '11.1.1.1'

    OVL_IP_PACKET_DIP_2 = '21.2.2.2'
    OVL_IP_PACKET_SIP_2 = '11.1.1.1'

    UNL_IP_PACKET_SMAC = '00:11:22:33:44:55'

    PREFIX1_GID = 0x691
    MPLS_TTL = 0x88
    IP_TTL = 0x90
    OVL_IP_TTL = 0x77

    SRC_LABEL = sdk.la_mpls_label()
    SRC_LABEL.label = 0x64
    DST_LABEL = sdk.la_mpls_label()
    DST_LABEL.label = 0xf0065

    SIP_IPv6 = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:5555:7777:2222')
    DIP_IPv6 = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

    SIP_IPv6_2 = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    DIP_IPv6_2 = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

    SR_LABEL0 = sdk.la_mpls_label()
    SR_LABEL0.label = 0x160
    SR_LABEL1 = sdk.la_mpls_label()
    SR_LABEL1.label = 0x161
    SR_LABEL2 = sdk.la_mpls_label()
    SR_LABEL2.label = 0x162

    TUNNEL_ENCAP_TOS = sdk.la_ip_tos()
    TUNNEL_ENCAP_TOS.fields.ecn = 0
    TUNNEL_ENCAP_TOS.fields.dscp = 7

    IN_DSCP = sdk.la_ip_dscp()
    IN_DSCP.value = 63

    OUT_TOS = sdk.la_ip_tos()
    OUT_TOS.fields.ecn = 0
    OUT_TOS.fields.dscp = 5

    # Prepare remarking of IN_DSCP -> OUT_DSCP
    encap_qos_values = sdk.encapsulating_headers_qos_values()
    encap_qos_values.tos = OUT_TOS

    # Egress QoS fields
    OUT_DSCP = sdk.la_ip_dscp()
    OUT_DSCP.value = 62

    QOS_GROUPID = 1

    # Prepare remarking of MPLS_TC -> GROUPID
    mpls_tc = sdk.la_mpls_tc()
    mpls_tc.value = 0

    def setUp(self):
        super().setUp()
        self.ip_impl = ip_test_base.ipv4_test_base
        self.ipv6_impl = ip_test_base.ipv6_test_base
        self.l3_port_impl = T.ip_l3_ac_base(self.topology)

        # enable ipv4/ipv6/MPLS forwarding
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_UC, True)
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_MPLS, True)
        self.topology.tx_l3_ac_def.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_def.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_UC, True)
        self.topology.tx_l3_ac_def.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_MPLS, True)
        self.topology.tx_l3_ac_ext.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_ext.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_UC, True)
        self.topology.tx_l3_ac_ext.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_MPLS, True)

        # make the l3 port address unicast mac address
        self.topology.tx_l3_ac_def.hld_obj.set_mac(
            self.NEW_TX_L3_AC_DEF_MAC.hld_obj)
        self.topology.tx_l3_ac_ext.hld_obj.set_mac(
            self.NEW_TX_L3_AC_EXT_MAC.hld_obj)

        self.ovl_dip_prefix = self.ip_impl.build_prefix(self.OVL_DIP_ROUTE, length=24)
        self.ovl_sip_prefix = self.ip_impl.build_prefix(self.OVL_SIP_ROUTE, length=24)

        self.topology.tx_l3_ac_reg.hld_obj.set_vrf(self.topology.vrf2.hld_obj)

        # set counters on ingress and egress interfaces
        self.ingress_port_counter = self.device.create_counter(1)
        self.topology.tx_l3_ac_reg.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.ingress_port_counter)

        self.egress_port_counter = self.device.create_counter(1)
        self.topology.tx_l3_ac_def.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.egress_port_counter)

        self.add_default_route()

    def tearDown(self):
        self.destroy_default_route()
        super().tearDown()

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf2, prefix,
                               self.l3_port_impl.def_nh,
                               self.PRIVATE_DATA_DEFAULT)
        prefix_ipv6 = self.ipv6_impl.get_default_prefix()
        self.ipv6_impl.add_route(self.topology.vrf2, prefix_ipv6,
                                 self.l3_port_impl.def_nh,
                                 self.PRIVATE_DATA_DEFAULT)
        self.has_default_route = True

    def destroy_default_route(self):
        if self.has_default_route:
            prefix = self.ip_impl.get_default_prefix()
            self.ip_impl.delete_route(self.topology.vrf2, prefix)
            self.has_default_route = False

    def gre_port_setup(self, gid, mode, unl_vrf, sip, dip, vrf):
        gre_tunnel = self.device.create_gre_port(
            gid,
            mode,
            unl_vrf.hld_obj,
            sip.hld_obj,
            dip.hld_obj,
            vrf.hld_obj,
            self.topology.ingress_qos_profile_def.hld_obj,
            self.topology.egress_qos_profile_def.hld_obj)

        # set the counter
        self.l3_egress_counter = self.device.create_counter(1)
        self.l3_ingress_counter = self.device.create_counter(1)
        gre_tunnel.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l3_egress_counter)
        gre_tunnel.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.l3_ingress_counter)

        # set TTL to PIPE mode
        gre_tunnel.set_ttl_inheritance_mode(sdk.la_gre_port.la_ttl_inheritance_mode_e_PIPE)

        # enable ipv4/ipv6/MPLS on gre port
        gre_tunnel.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        gre_tunnel.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        gre_tunnel.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)

        gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)
        return gre_tunnel

    def gre_port_single_path(self, mode=sdk.la_ip_tunnel_mode_e_ENCAP_DECAP):
        self.gre_tunnel = self.gre_port_setup(self.GRE_PORT_GID, mode, self.topology.vrf2,
                                              self.GRE_SIP, self.GRE_DIP, self.topology.vrf)
        self.gre_destination = self.device.create_ip_tunnel_destination(
            self.GRE_TUNNEL_DESTINATION_GID,
            self.gre_tunnel,
            self.topology.nh_l3_ac_reg.hld_obj)

    def gre_port_multi_path(self, mode=sdk.la_ip_tunnel_mode_e_ENCAP_DECAP):
        self.gre_tunnel = self.gre_port_setup(self.GRE_PORT_GID, mode, self.topology.vrf2,
                                              self.GRE_SIP, self.GRE_DIP, self.topology.vrf)
        self.gre_tunnel1 = self.gre_port_setup(self.GRE_PORT_GID1, mode, self.topology.vrf2,
                                               self.GRE_SIP1, self.GRE_DIP1, self.topology.vrf)

        self.l3_egress_counter_tunnel = self.device.create_counter(1)
        self.l3_egress_counter_tunnel1 = self.device.create_counter(1)

        self.gre_tunnel.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l3_egress_counter_tunnel)
        self.gre_tunnel1.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l3_egress_counter_tunnel1)

        # create underlay ecmp group
        self.unl_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.unl_ecmp_attached_members = [self.topology.nh_l3_ac_reg, self.topology.nh_l3_ac_ext]
        for member in self.unl_ecmp_attached_members:
            self.unl_ecmp.add_member(member.hld_obj)

        self.gre_destination = self.device.create_ip_tunnel_destination(
            self.GRE_TUNNEL_DESTINATION_GID,
            self.gre_tunnel,
            self.unl_ecmp)

        self.gre_destination1 = self.device.create_ip_tunnel_destination(
            self.GRE_TUNNEL_DESTINATION_GID1,
            self.gre_tunnel1,
            self.unl_ecmp)

        # create overlay ecmp group
        self.ovl_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.ovl_ecmp_attached_members = [self.gre_destination, self.gre_destination1]
        for member in self.ovl_ecmp_attached_members:
            self.ovl_ecmp.add_member(member)

    def destory_gre_port_single_path(self):
        self.device.destroy(self.gre_destination)
        self.device.destroy(self.gre_tunnel)
        self.device.destroy(self.l3_egress_counter)
        self.device.destroy(self.l3_ingress_counter)

    def destory_gre_port_multi_path(self):
        self.device.destroy(self.ovl_ecmp)
        self.device.destroy(self.gre_destination)
        self.device.destroy(self.gre_destination1)
        self.device.destroy(self.unl_ecmp)
        self.device.destroy(self.gre_tunnel)
        self.device.destroy(self.gre_tunnel1)
        self.device.destroy(self.l3_egress_counter_tunnel)
        self.device.destroy(self.l3_egress_counter_tunnel1)

    def _test_gre_decap_mpls_forwarding_mpls_disable(self):
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)
        #
        #  test mpls label swap
        #
        nhlfe = self.device.create_mpls_swap_nhlfe(self.l3_port_impl.def_nh.hld_obj, self.SRC_LABEL)
        lsr = self.device.get_lsr()
        lsr.add_route(self.DST_LABEL, nhlfe, self.PRIVATE_DATA)

        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=self.IP_TTL) / \
            S.GRE(proto=U.Ethertype.MPLS.value) / \
            MPLS(label=self.DST_LABEL.label,
                 ttl=self.MPLS_TTL) / \
            S.IP(dst=self.OVL_IP_PACKET_SIP,
                 src=self.OVL_IP_PACKET_DIP,
                 ttl=self.OVL_IP_TTL) / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str,
                    type=U.Ethertype.MPLS.value) / \
            MPLS(label=self.SRC_LABEL.label,
                 ttl=self.MPLS_TTL - 1) / \
            S.IP(dst=self.OVL_IP_PACKET_SIP,
                 src=self.OVL_IP_PACKET_DIP,
                 ttl=self.OVL_IP_TTL) / \
            S.TCP()

        input_packet, input_packet_payload_size = U.enlarge_packet_to_min_length(input_packet_base)
        expected_packet = U.add_payload(expected_packet_base, input_packet_payload_size)

        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_MPLS, False)

        U.run_and_compare(self, self.device,
                          input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

    def gre_port_ecmp_path(self):
        mode = sdk.la_ip_tunnel_mode_e_ENCAP_DECAP
        self.gre_tunnel = self.gre_port_setup(self.GRE_PORT_GID, mode, self.topology.vrf2,
                                              self.GRE_SIP, self.GRE_DIP, self.topology.vrf)
        self.gre_destination = self.device.create_ip_tunnel_destination(
            self.GRE_TUNNEL_DESTINATION_GID,
            self.gre_tunnel,
            self.topology.nh_l3_ac_reg.hld_obj)

        l3_port_impl = T.ip_l3_ac_base(self.topology)

        self.ecmp_group = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.nh_list = []
        for nh_num in range(self.NUM_OF_NH):
            nh = T.next_hop(
                self,
                self.device,
                self.NH_GID_BASE + nh_num,
                self.NH_DST_MAC_BASE.create_offset_mac(nh_num),
                l3_port_impl.tx_port)
            self.ecmp_group.add_member(nh.hld_obj)
            self.nh_list.append(nh)

        self.pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.ecmp_group)

        for nh_num in range(self.NUM_OF_NH):
            lsp_labels = []
            lsp_labels.append(self.SRC_LABEL)
            self.pfx_obj.hld_obj.set_nh_lsp_properties(
                self.nh_list[nh_num].hld_obj,
                lsp_labels,
                None,
                sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsr = self.device.get_lsr()
        lsr.add_route(self.DST_LABEL, self.pfx_obj.hld_obj, self.PRIVATE_DATA)

    def destory_gre_port_ecmp_path(self):
        self.device.destroy(self.gre_destination)
        self.device.destroy(self.gre_tunnel)
        self.device.destroy(self.l3_egress_counter)
        self.device.destroy(self.l3_ingress_counter)

    def _test_gre_decap_mpls_forwarding(self, port_inheritance=False, test_counters=False):
        if (port_inheritance):
            self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)
        else:
            self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)
        #
        #  test mpls label swap
        #
        nhlfe = self.device.create_mpls_swap_nhlfe(self.l3_port_impl.def_nh.hld_obj, self.SRC_LABEL)
        lsr = self.device.get_lsr()
        lsr.add_route(self.DST_LABEL, nhlfe, self.PRIVATE_DATA)

        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=self.IP_TTL) / \
            S.GRE(proto=U.Ethertype.MPLS.value) / \
            MPLS(label=self.DST_LABEL.label,
                 ttl=self.MPLS_TTL) / \
            S.IP(dst=self.OVL_IP_PACKET_SIP,
                 src=self.OVL_IP_PACKET_DIP,
                 ttl=self.OVL_IP_TTL) / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str,
                    type=U.Ethertype.MPLS.value) / \
            MPLS(label=self.SRC_LABEL.label,
                 ttl=self.MPLS_TTL - 1) / \
            S.IP(dst=self.OVL_IP_PACKET_SIP,
                 src=self.OVL_IP_PACKET_DIP,
                 ttl=self.OVL_IP_TTL) / \
            S.TCP()

        input_packet, input_packet_payload_size = U.enlarge_packet_to_min_length(input_packet_base)
        input_packet = U.add_payload(input_packet_base, input_packet_payload_size)
        expected_packet = U.add_payload(expected_packet_base, input_packet_payload_size)

        U.run_and_compare(self, self.device,
                          input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        lsr.delete_route(self.DST_LABEL)
        self.device.destroy(nhlfe)

        #
        #  test modify label mapping
        #
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.def_nh.hld_obj)
        lsr.add_route(self.DST_LABEL, pfx_obj.hld_obj, self.PRIVATE_DATA_MPLS)

        nhlfe = self.device.create_mpls_swap_nhlfe(self.l3_port_impl.def_nh.hld_obj, self.SRC_LABEL)
        self.assertNotEqual(nhlfe, None)
        lsr.modify_route(self.DST_LABEL, nhlfe)

        info = lsr.get_route(self.DST_LABEL)
        self.assertEqual(info.user_data, self.PRIVATE_DATA_MPLS)
        self.assertEqual(info.destination.this, nhlfe.this)

        U.run_and_compare(self, self.device,
                          input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        lsr.delete_route(self.DST_LABEL)
        self.device.destroy(nhlfe)

        #
        # test php
        #
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        nhlfe = self.device.create_mpls_php_nhlfe(
            self.l3_port_impl.def_nh.hld_obj)
        lsr.add_route(self.DST_LABEL, nhlfe, self.PRIVATE_DATA)

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(dst=self.OVL_IP_PACKET_SIP,
                 src=self.OVL_IP_PACKET_DIP,
                 ttl=self.OVL_IP_TTL) / \
            S.TCP()

        expected_packet = U.add_payload(expected_packet_base, input_packet_payload_size)

        U.run_and_compare(self, self.device,
                          input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        lsr.delete_route(self.DST_LABEL)
        self.device.destroy(nhlfe)

        packets, _ = self.l3_ingress_counter.read(0, True, True)
        self.assertEqual(packets, 3)

        if test_counters:
            # This works on SIM but fails on HW - uncoment after HW fix
            # packets1, _ = self.ingress_port_counter.read(0, True, True)
            # self.assertEqual(packets1, 3)

            packets2, _ = self.egress_port_counter.read(0, True, True)
            self.assertEqual(packets2, 3)

    def _test_gre_decap_mpls_forwarding_ecmp(self):
        PAYLOAD_SIZE = 60
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)

        # ACL match on the Outer Header

        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)

        DIP = self.GRE_SIP
        k = []
        f = sdk.la_acl_field()
        f.type = sdk.la_acl_field_type_e_IPV4_DIP
        f.val.ipv4_dip.s_addr = DIP.to_num()
        f.mask.ipv4_dip.s_addr = 0xffffffff
        k.append(f)

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV4_DIP
        f1.val.ipv4_dip.s_addr = DIP.to_num()
        f1.mask.ipv4_dip.s_addr = 0
        k1.append(f1)

        commands = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = False
        commands.append(action1)

        acl1.append(k, commands)
        acl1.append(k1, commands)

        ipv4_acls = []
        ipv4_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.tx_l3_ac_reg.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=self.IP_TTL) / \
            S.GRE(proto=U.Ethertype.MPLS.value) / \
            MPLS(label=self.DST_LABEL.label,
                 ttl=self.MPLS_TTL) / \
            S.IP(dst=self.OVL_IP_PACKET_SIP,
                 src=self.OVL_IP_PACKET_DIP,
                 ttl=self.OVL_IP_TTL) / \
            S.TCP()

        input_packet = U.add_payload(input_packet_base, PAYLOAD_SIZE)

        lb_vec_entry_list = []
        hw_lb_vec = sdk.la_lb_vector_t()
        hw_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP
        hw_lb_vec.ipv4.sip = T.ipv4_addr(input_packet[IP].src).to_num()
        hw_lb_vec.ipv4.dip = T.ipv4_addr(input_packet[IP].dst).to_num()
        hw_lb_vec.ipv4.protocol = input_packet[IP].proto
        lb_vec_entry_list.append(hw_lb_vec)

        soft_lb_vec = sdk.la_lb_vector_t()
        soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
        soft_lb_vec.ipv4.sip = T.ipv4_addr(input_packet[GRE][IP].src).to_num()
        soft_lb_vec.ipv4.dip = T.ipv4_addr(input_packet[GRE][IP].dst).to_num()
        soft_lb_vec.ipv4.protocol = input_packet[GRE][IP].proto
        soft_lb_vec.ipv4.src_port = input_packet[TCP].sport
        soft_lb_vec.ipv4.dest_port = input_packet[TCP].dport
        lb_vec_entry_list.append(soft_lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(self.ecmp_group, lb_vec_entry_list)

        expected_mac = out_dest_chain[0].downcast().get_mac().flat
        expected_mac_str = T.mac_addr.mac_num_to_str(expected_mac)

        expected_packet_base = \
            S.Ether(dst=expected_mac_str,
                    src=T.TX_L3_AC_REG_MAC.addr_str,
                    type=U.Ethertype.MPLS.value) / \
            MPLS(label=self.SRC_LABEL.label,
                 ttl=self.MPLS_TTL - 1) / \
            S.IP(dst=self.OVL_IP_PACKET_SIP,
                 src=self.OVL_IP_PACKET_DIP,
                 ttl=self.OVL_IP_TTL) / \
            S.TCP()

        expected_packet = U.add_payload(expected_packet_base, PAYLOAD_SIZE)

        U.run_and_compare(self, self.device,
                          input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.topology.tx_l3_ac_reg.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.device.destroy(acl_group)
        self.device.destroy(acl1)

    def _test_gre_decap_mpls_encap(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.def_nh.hld_obj)
        lsp_labels = []
        lsp_labels.append(self.SRC_LABEL)

        pfx_obj.hld_obj.set_nh_lsp_properties(self.l3_port_impl.def_nh.hld_obj, lsp_labels,
                                              None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.topology.vrf.hld_obj.add_ipv4_route(
            self.ovl_sip_prefix, pfx_obj.hld_obj, self.PRIVATE_DATA, False)

        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=self.IP_TTL) / \
            S.GRE() / \
            S.IP(dst=self.OVL_IP_PACKET_SIP,
                 src=self.OVL_IP_PACKET_DIP,
                 ttl=self.OVL_IP_TTL) / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str,
                    type=U.Ethertype.MPLS.value) / \
            MPLS(label=self.SRC_LABEL.label,
                 ttl=255) / \
            S.IP(dst=self.OVL_IP_PACKET_SIP,
                 src=self.OVL_IP_PACKET_DIP,
                 ttl=self.OVL_IP_TTL - 1) / \
            S.TCP()

        input_packet, input_packet_payload_size = U.enlarge_packet_to_min_length(input_packet_base)
        input_packet = U.add_payload(input_packet_base, input_packet_payload_size)
        expected_packet = U.add_payload(expected_packet_base, input_packet_payload_size)

        U.run_and_compare(self, self.device,
                          input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        #
        #  change mpls_ttl_inheritance_mode to UNIFORM and test again
        #
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str,
                    type=U.Ethertype.MPLS.value) / \
            MPLS(label=self.SRC_LABEL.label,
                 ttl=self.OVL_IP_TTL - 1) / \
            S.IP(dst=self.OVL_IP_PACKET_SIP,
                 src=self.OVL_IP_PACKET_DIP,
                 ttl=self.OVL_IP_TTL - 1) / \
            S.TCP()

        expected_packet = U.add_payload(expected_packet_base, input_packet_payload_size)

        U.run_and_compare(self, self.device,
                          input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        self.topology.vrf.hld_obj.delete_ipv4_route(self.ovl_sip_prefix)

        packets, _ = self.l3_ingress_counter.read(0, True, True)
        self.assertEqual(packets, 2)

    def _test_mpls_decap_gre_encap_single_path(self):
        gre_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        gre_ecmp.add_member(self.gre_destination)

        lsr = self.device.get_lsr()
        lsr.add_route(self.SRC_LABEL, gre_ecmp, self.PRIVATE_DATA)

        input_packet_base = \
            S.Ether(dst=self.OVL_IP_PACKET_DMAC,
                    src=self.OVL_IP_PACKET_SMAC) / \
            MPLS(label=self.SRC_LABEL.label, ttl=self.MPLS_TTL) / \
            S.IP(dst=self.OVL_IP_PACKET_DIP,
                 src=self.OVL_IP_PACKET_SIP,
                 ttl=self.OVL_IP_TTL) / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                    src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(dst=self.GRE_DIP.addr_str,
                 src=self.GRE_SIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) /\
            S.GRE() / \
            S.IP(dst=self.OVL_IP_PACKET_DIP,
                 src=self.OVL_IP_PACKET_SIP,
                 ttl=self.OVL_IP_TTL) / \
            S.TCP()

        input_packet, input_packet_payload_size = U.enlarge_packet_to_min_length(input_packet_base)
        expected_packet = U.add_payload(expected_packet_base, input_packet_payload_size)

        U.run_and_compare(self, self.device,
                          input_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        packets, byte_count = self.l3_egress_counter.read(0, True, True)
        self.assertEqual(packets, 1)
        U.assertPacketLengthEgress(self, expected_packet, byte_count)

        # inTTL 1 should be trapped
        input_packet[MPLS].ttl = 1

        tc = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_TTL_OR_HOP_LIMIT_IS_ONE, 0, tc, None, False, False, True, 0)
        U.run_and_drop(self, self.device,
                       input_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        trap_packet_count = 1
        packets, bytes = tc.read(0,  # sub-counter index
                                     True,  # force_update
                                     True)  # clear_on_read
        if decor.is_pacific() or decor.is_gibraltar():
            # check egress trap counter only or pacific or GB. per Himanshu
            self.assertEqual(packets, trap_packet_count)
        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_TTL_OR_HOP_LIMIT_IS_ONE)

        lsr.delete_route(self.SRC_LABEL)
        self.device.destroy(gre_ecmp)

    def calculate_expected_output(self):
        # both members of ovl_ecmp use unl_ecmp as the destination
        # so it's enough to find the load-balancing result of unl_ecmp and fix the topmost eth header
        dip = T.ipv4_addr(self.input_packet[IP].dst)
        sip = T.ipv4_addr(self.input_packet[IP].src)

        lb_vec_entry_list = []
        hw_lb_vec = sdk.la_lb_vector_t()
        hw_lb_vec.type = sdk.LA_LB_VECTOR_MPLS
        hw_lb_vec.mpls.label = [self.input_packet[MPLS].label, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        hw_lb_vec.mpls.num_valid_labels = 1
        lb_vec_entry_list.append(hw_lb_vec)

        soft_lb_vec = sdk.la_lb_vector_t()
        soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
        soft_lb_vec.ipv4.sip = sip.hld_obj.s_addr
        soft_lb_vec.ipv4.dip = dip.hld_obj.s_addr
        soft_lb_vec.ipv4.protocol = self.input_packet[IP].proto
        soft_lb_vec.ipv4.src_port = self.input_packet[TCP].sport
        soft_lb_vec.ipv4.dest_port = self.input_packet[TCP].dport

        lb_vec_entry_list.append(soft_lb_vec)

        tun_out_dest_chain = self.device.get_forwarding_load_balance_chain(self.ovl_ecmp, lb_vec_entry_list)
        tun_dst = (tun_out_dest_chain[-1]).downcast()
        tun_unl_dst = tun_dst.get_underlay_destination()
        tun_port = (tun_dst.get_ip_tunnel_port()).downcast()
        gre_sip = (tun_port.get_local_ip_addr()).s_addr
        gre_dip = (tun_port.get_remote_ip_addr()).s_addr
        tun_counter = tun_port.get_egress_counter(sdk.la_counter_set.type_e_PORT)
        out_dest_chain = self.device.get_forwarding_load_balance_chain(tun_unl_dst, lb_vec_entry_list)

        ### For Debug purpose:########################################################
        #U.display_forwarding_load_balance_chain(self.unl_ecmp, out_dest_chain)
        #print('nh_reg=%d nh_ext=%d' % (self.topology.nh_l3_ac_reg.hld_obj.oid(),  self.topology.nh_l3_ac_ext.hld_obj.oid()))
        ##############################################################################

        self.assertEqual(out_dest_chain[-1].type(), sdk.la_object.object_type_e_SYSTEM_PORT)
        # find the NH in the chain
        nh_obj = None
        for e in reversed(out_dest_chain):
            if e.type() == sdk.la_object.object_type_e_NEXT_HOP:
                nh_obj = e
                break
        assert nh_obj is not None, 'No next hop in chain'

        out_nh = nh_obj.downcast()
        out_dsp = out_dest_chain[-1].downcast()

        dst = out_nh.get_mac()
        src = out_nh.get_router_port().downcast().get_mac()
        dst_str = T.mac_addr.mac_num_to_str(dst.flat)
        src_str = T.mac_addr.mac_num_to_str(src.flat)

        new_eth_hdr = S.Ether(dst=dst_str, src=src_str)

        out_slice = out_dsp.get_slice()
        out_ifg = out_dsp.get_ifg()
        out_pif = out_dsp.get_base_serdes()

        return new_eth_hdr, out_slice, out_ifg, out_pif, gre_sip, gre_dip, tun_counter

    def _test_mpls_decap_gre_encap_multi_path(self):

        lsr = self.device.get_lsr()
        lsr.add_route(self.SRC_LABEL, self.ovl_ecmp, self.PRIVATE_DATA)

        self.device.set_ecmp_hash_seed(0xa2bf)

        input_packet_base = \
            S.Ether(dst=self.OVL_IP_PACKET_DMAC,
                    src=self.OVL_IP_PACKET_SMAC) / \
            MPLS(label=self.SRC_LABEL.label, ttl=self.MPLS_TTL) / \
            S.IP(dst=self.OVL_IP_PACKET_DIP,
                 src=self.OVL_IP_PACKET_SIP,
                 ttl=self.OVL_IP_TTL) / \
            S.TCP()
        self.input_packet, input_packet_payload_size = U.enlarge_packet_to_min_length(input_packet_base)

        (expected_packet_eth_hdr, out_slice, out_ifg, out_pif, gre_sip, gre_dip, tun_counter) = self.calculate_expected_output()

        expected_packet_base = \
            expected_packet_eth_hdr / \
            S.IP(dst=str(gre_dip),
                 src=str(gre_sip),
                 id=0,
                 flags=2,
                 ttl=255) /\
            S.GRE() / \
            S.IP(dst=self.OVL_IP_PACKET_DIP,
                 src=self.OVL_IP_PACKET_SIP,
                 ttl=self.OVL_IP_TTL) / \
            S.TCP()

        self.expected_packet = U.add_payload(expected_packet_base, input_packet_payload_size)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, out_slice, out_ifg, out_pif)

        lsr.delete_route(self.SRC_LABEL)

        packets, byte_count = tun_counter.read(0, True, True)
        self.assertEqual(packets, 1)
        U.assertPacketLengthEgress(self, self.expected_packet, byte_count)

    def _test_gre_decap_mpls_encap_sr_ipv6(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)
        nh_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp1, None)
        nh_ecmp1.add_member(self.l3_port_impl.def_nh.hld_obj)

        pfx_obj = T.global_prefix_object(self, self.device, self.PREFIX1_GID, nh_ecmp1)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        lsp_labels = []
        lsp_counter = self.device.create_counter(1)
        lsp_labels.append(self.SR_LABEL0)
        lsp_labels.append(self.SR_LABEL1)
        lsp_labels.append(self.SR_LABEL2)

        pfx_obj.hld_obj.set_global_lsp_properties(lsp_labels, lsp_counter, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.ovl_sip_prefix = self.ipv6_impl.build_prefix(self.OVL_SIP_ROUTE_IPv6, length=64)
        self.topology.vrf.hld_obj.add_ipv6_route(
            self.ovl_sip_prefix, pfx_obj.hld_obj, self.PRIVATE_DATA, False)

        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str, src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str, src=self.GRE_DIP.addr_str,
                 id=0, flags=2, ttl=self.IP_TTL) / \
            S.GRE(proto=0x86DD) / \
            S.IPv6(dst=self.SIP_IPv6.addr_str, src=self.DIP_IPv6.addr_str, hlim=self.OVL_IP_TTL, plen=40) / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str,
                    type=U.Ethertype.MPLS.value) / \
            MPLS(label=self.SR_LABEL2.label, ttl=255) / \
            MPLS(label=self.SR_LABEL1.label, ttl=255) / \
            MPLS(label=self.SR_LABEL0.label, ttl=255) / \
            S.IPv6(dst=self.SIP_IPv6.addr_str, src=self.DIP_IPv6.addr_str, hlim=self.OVL_IP_TTL - 1, plen=40) / \
            S.TCP()

        input_packet, input_packet_payload_size = U.enlarge_packet_to_min_length(input_packet_base)
        expected_packet = U.add_payload(expected_packet_base, input_packet_payload_size)

        U.run_and_compare(self, self.device,
                          input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

    def calculate_expected_output_ecmp_sr(self, input_packet, nh_ecmp, proto):
        lb_vec_entry_list = []
        hw_lb_vec = sdk.la_lb_vector_t()

        if proto == sdk.la_l3_protocol_e_IPV4_UC:
            hw_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
            hw_lb_vec.ipv4.sip = T.ipv4_addr(input_packet[GRE][IP].src).to_num()
            hw_lb_vec.ipv4.dip = T.ipv4_addr(input_packet[GRE][IP].dst).to_num()
            hw_lb_vec.ipv4.protocol = input_packet[GRE][IP].proto
            hw_lb_vec.ipv4.src_port = input_packet[TCP].sport
            hw_lb_vec.ipv4.dest_port = input_packet[TCP].dport
        else:
            hw_lb_vec.type = sdk.LA_LB_VECTOR_IPV6_TCP_UDP
            hw_lb_vec.ipv6.sip = U.split_bits(T.ipv6_addr(input_packet[IPv6].src).to_num(), 32)
            hw_lb_vec.ipv6.dip = U.split_bits(T.ipv6_addr(input_packet[IPv6].dst).to_num(), 32)
            hw_lb_vec.ipv6.next_header = input_packet[IPv6].nh
            hw_lb_vec.ipv6.flow_label = input_packet[IPv6].fl
            hw_lb_vec.ipv6.src_port = input_packet[TCP].sport
            hw_lb_vec.ipv6.dest_port = input_packet[TCP].dport
        lb_vec_entry_list.append(hw_lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(nh_ecmp, lb_vec_entry_list)

        # find the NH in the chain
        nh_obj = None
        for e in reversed(out_dest_chain):
            if e.type() == sdk.la_object.object_type_e_NEXT_HOP:
                nh_obj = e
                break
        assert nh_obj is not None, 'No next hop in chain'

        out_nh = nh_obj.downcast()
        out_dsp = out_dest_chain[-1].downcast()

        dst = out_nh.get_mac()
        src = out_nh.get_router_port().downcast().get_mac()
        dst_str = T.mac_addr.mac_num_to_str(dst.flat)
        src_str = T.mac_addr.mac_num_to_str(src.flat)

        out_slice = out_dsp.get_slice()
        out_ifg = out_dsp.get_ifg()
        out_pif = out_dsp.get_base_serdes()

        return dst_str, src_str, out_slice, out_ifg, out_pif

    def _test_gre_decap_mpls_encap_ecmp_sr_ipv6(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)
        nh_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp1, None)
        nh_ecmp1.add_member(self.l3_port_impl.def_nh.hld_obj)
        nh_ecmp1.add_member(self.l3_port_impl.ext_nh.hld_obj)

        pfx_obj = T.global_prefix_object(self, self.device, self.PREFIX1_GID, nh_ecmp1)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        lsp_labels = []
        lsp_counter = self.device.create_counter(1)
        lsp_labels.append(self.SR_LABEL0)
        lsp_labels.append(self.SR_LABEL1)
        lsp_labels.append(self.SR_LABEL2)

        pfx_obj.hld_obj.set_global_lsp_properties(lsp_labels, lsp_counter, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.ovl_sip_prefix = self.ipv6_impl.build_prefix(self.OVL_SIP_ROUTE_IPv6, length=96)
        self.topology.vrf.hld_obj.add_ipv6_route(
            self.ovl_sip_prefix, pfx_obj.hld_obj, self.PRIVATE_DATA, False)

        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str, src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str, src=self.GRE_DIP.addr_str,
                 id=0, flags=2, ttl=self.IP_TTL) / \
            S.GRE(proto=0x86DD) / \
            S.IPv6(dst=self.SIP_IPv6.addr_str, src=self.DIP_IPv6.addr_str, hlim=self.OVL_IP_TTL, plen=40) / \
            S.TCP()

        input_packet, input_packet_payload_size = U.enlarge_packet_to_min_length(input_packet_base)
        (dst_mac_str, src_mac_str, out_slice, out_ifg, out_pif) = self.calculate_expected_output_ecmp_sr(input_packet, nh_ecmp1,
                                                                                                         sdk.la_l3_protocol_e_IPV6_UC)

        expected_packet_base = \
            S.Ether(dst=dst_mac_str,
                    src=src_mac_str,
                    type=U.Ethertype.MPLS.value) / \
            MPLS(label=self.SR_LABEL2.label, ttl=255) / \
            MPLS(label=self.SR_LABEL1.label, ttl=255) / \
            MPLS(label=self.SR_LABEL0.label, ttl=255) / \
            S.IPv6(dst=self.SIP_IPv6.addr_str, src=self.DIP_IPv6.addr_str, hlim=self.OVL_IP_TTL - 1, plen=40) / \
            S.TCP()

        expected_packet = U.add_payload(expected_packet_base, input_packet_payload_size)

        U.run_and_compare(self, self.device,
                          input_packet, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          expected_packet, out_slice, out_ifg, out_pif)

        self.ovl_sip_prefix_2 = self.ipv6_impl.build_prefix(self.OVL_SIP_ROUTE_IPv6_2, length=96)
        self.ipv6_impl.add_route(self.topology.vrf, self.ovl_sip_prefix_2, pfx_obj, self.PRIVATE_DATA_DEFAULT)

        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str, src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str, src=self.GRE_DIP.addr_str,
                 id=0, flags=2, ttl=self.IP_TTL) / \
            S.GRE(proto=0x86DD) / \
            S.IPv6(dst=self.SIP_IPv6_2.addr_str, src=self.DIP_IPv6_2.addr_str, hlim=self.OVL_IP_TTL, plen=40) / \
            S.TCP()

        self.input_packet, input_packet_payload_size = U.enlarge_packet_to_min_length(input_packet_base)
        (dst_mac_str, src_mac_str, out_slice, out_ifg, out_pif) = self.calculate_expected_output_ecmp_sr(self.input_packet, nh_ecmp1,
                                                                                                         sdk.la_l3_protocol_e_IPV6_UC)
        expected_packet_base = \
            S.Ether(dst=dst_mac_str, src=src_mac_str, type=U.Ethertype.MPLS.value) / \
            MPLS(label=self.SR_LABEL2.label, ttl=255) / \
            MPLS(label=self.SR_LABEL1.label, ttl=255) / \
            MPLS(label=self.SR_LABEL0.label, ttl=255) / \
            S.IPv6(dst=self.SIP_IPv6_2.addr_str, src=self.DIP_IPv6_2.addr_str, hlim=self.OVL_IP_TTL - 1, plen=40) / \
            S.TCP()

        self.expected_packet = U.add_payload(expected_packet_base, input_packet_payload_size)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, out_slice, out_ifg, out_pif)

    def _test_gre_decap_mpls_encap_sr_ipv4(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)

        nh_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp1, None)
        nh_ecmp1.add_member(self.l3_port_impl.def_nh.hld_obj)

        pfx_obj = T.global_prefix_object(self, self.device, self.PREFIX1_GID, nh_ecmp1)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        lsp_labels = []
        lsp_counter = self.device.create_counter(1)
        lsp_labels.append(self.SR_LABEL0)
        lsp_labels.append(self.SR_LABEL1)
        lsp_labels.append(self.SR_LABEL2)

        pfx_obj.hld_obj.set_global_lsp_properties(lsp_labels, lsp_counter, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.ovl_sip_prefix = self.ip_impl.build_prefix(self.OVL_SIP_ROUTE, length=24)
        self.topology.vrf.hld_obj.add_ipv4_route(
            self.ovl_sip_prefix, pfx_obj.hld_obj, self.PRIVATE_DATA, False)

        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str, src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str, src=self.GRE_DIP.addr_str,
                 id=0, flags=2, ttl=self.IP_TTL) / \
            S.GRE() / \
            S.IP(dst=self.OVL_IP_PACKET_SIP, src=self.OVL_IP_PACKET_DIP, ttl=self.OVL_IP_TTL) / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str,
                    type=U.Ethertype.MPLS.value) / \
            MPLS(label=self.SR_LABEL2.label, ttl=255) / \
            MPLS(label=self.SR_LABEL1.label, ttl=255) / \
            MPLS(label=self.SR_LABEL0.label, ttl=255) / \
            S.IP(dst=self.OVL_IP_PACKET_SIP, src=self.OVL_IP_PACKET_DIP, ttl=self.OVL_IP_TTL - 1) / \
            S.TCP()

        input_packet, input_packet_payload_size = U.enlarge_packet_to_min_length(input_packet_base)
        expected_packet = U.add_payload(expected_packet_base, input_packet_payload_size)

        U.run_and_compare(self, self.device,
                          input_packet, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          expected_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

    def _test_gre_decap_mpls_encap_ecmp_sr_ipv4(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)
        nh_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp1, None)
        nh_ecmp1.add_member(self.l3_port_impl.def_nh.hld_obj)
        nh_ecmp1.add_member(self.l3_port_impl.ext_nh.hld_obj)

        pfx_obj = T.global_prefix_object(self, self.device, self.PREFIX1_GID, nh_ecmp1)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        lsp_labels = []
        lsp_counter = self.device.create_counter(1)
        lsp_labels.append(self.SR_LABEL0)
        lsp_labels.append(self.SR_LABEL1)
        lsp_labels.append(self.SR_LABEL2)

        pfx_obj.hld_obj.set_global_lsp_properties(lsp_labels, lsp_counter, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.ovl_sip_prefix = self.ip_impl.build_prefix(self.OVL_SIP_ROUTE, length=24)
        self.topology.vrf.hld_obj.add_ipv4_route(
            self.ovl_sip_prefix, pfx_obj.hld_obj, self.PRIVATE_DATA, False)

        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str, src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str, src=self.GRE_DIP.addr_str,
                 id=0, flags=2, ttl=self.IP_TTL) / \
            S.GRE() / \
            S.IP(dst=self.OVL_IP_PACKET_SIP, src=self.OVL_IP_PACKET_DIP, ttl=self.OVL_IP_TTL) / \
            S.TCP()

        input_packet, input_packet_payload_size = U.enlarge_packet_to_min_length(input_packet_base)
        (dst_mac_str, src_mac_str, out_slice, out_ifg, out_pif) = self.calculate_expected_output_ecmp_sr(input_packet, nh_ecmp1,
                                                                                                         sdk.la_l3_protocol_e_IPV4_UC)

        expected_packet_base = \
            S.Ether(dst=dst_mac_str,
                    src=src_mac_str,
                    type=U.Ethertype.MPLS.value) / \
            MPLS(label=self.SR_LABEL2.label, ttl=255) / \
            MPLS(label=self.SR_LABEL1.label, ttl=255) / \
            MPLS(label=self.SR_LABEL0.label, ttl=255) / \
            S.IP(dst=self.OVL_IP_PACKET_SIP, src=self.OVL_IP_PACKET_DIP, ttl=self.OVL_IP_TTL - 1) / \
            S.TCP()

        expected_packet = U.add_payload(expected_packet_base, input_packet_payload_size)

        U.run_and_compare(self, self.device,
                          input_packet, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          expected_packet, out_slice, out_ifg, out_pif)

        self.ovl_sip_prefix_2 = self.ip_impl.build_prefix(self.OVL_SIP_ROUTE_2, length=24)
        self.ip_impl.add_route(self.topology.vrf, self.ovl_sip_prefix_2, pfx_obj, self.PRIVATE_DATA_DEFAULT)

        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str, src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str, src=self.GRE_DIP.addr_str,
                 id=0, flags=2, ttl=self.IP_TTL) / \
            S.GRE() / \
            S.IP(dst=self.OVL_IP_PACKET_SIP_2, src=self.OVL_IP_PACKET_DIP_2, ttl=self.OVL_IP_TTL) / \
            S.TCP()

        self.input_packet, input_packet_payload_size = U.enlarge_packet_to_min_length(input_packet_base)
        (dst_mac_str, src_mac_str, out_slice, out_ifg, out_pif) = self.calculate_expected_output_ecmp_sr(self.input_packet, nh_ecmp1,
                                                                                                         sdk.la_l3_protocol_e_IPV4_UC)

        expected_packet_base = \
            S.Ether(dst=dst_mac_str, src=src_mac_str, type=U.Ethertype.MPLS.value) / \
            MPLS(label=self.SR_LABEL2.label, ttl=255) / \
            MPLS(label=self.SR_LABEL1.label, ttl=255) / \
            MPLS(label=self.SR_LABEL0.label, ttl=255) / \
            S.IP(dst=self.OVL_IP_PACKET_SIP_2, src=self.OVL_IP_PACKET_DIP_2, ttl=self.OVL_IP_TTL - 1) / \
            S.TCP()

        self.expected_packet = U.add_payload(expected_packet_base, input_packet_payload_size)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, out_slice, out_ifg, out_pif)

    def _test_mpls_decap_gre_encap_single_path_qos_tos(self):
        '''
        When the tunnel's encap_qos_mode is set to PIPE,
        the GRE outer IP DSCP should be solely derived from the tunnel's encap_tos.
        '''
        gre_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        gre_ecmp.add_member(self.gre_destination)

        lsr = self.device.get_lsr()
        lsr.add_route(self.SRC_LABEL, gre_ecmp, self.PRIVATE_DATA)

        self.gre_tunnel.set_encap_qos_mode(sdk.la_tunnel_encap_qos_mode_e_PIPE)
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)
        self.gre_tunnel.set_encap_tos(self.TUNNEL_ENCAP_TOS)

        input_packet_base = \
            S.Ether(dst=self.OVL_IP_PACKET_DMAC,
                    src=self.OVL_IP_PACKET_SMAC) / \
            MPLS(label=self.SRC_LABEL.label, ttl=self.MPLS_TTL) / \
            S.IP(dst=self.OVL_IP_PACKET_DIP,
                 src=self.OVL_IP_PACKET_SIP,
                 ttl=self.OVL_IP_TTL) / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                    src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(dst=self.GRE_DIP.addr_str,
                 src=self.GRE_SIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255,
                 tos=self.TUNNEL_ENCAP_TOS.flat) /\
            S.GRE() / \
            S.IP(dst=self.OVL_IP_PACKET_DIP,
                 src=self.OVL_IP_PACKET_SIP,
                 ttl=self.OVL_IP_TTL) / \
            S.TCP()

        input_packet, input_packet_payload_size = U.enlarge_packet_to_min_length(input_packet_base)
        expected_packet = U.add_payload(expected_packet_base, input_packet_payload_size)

        U.run_and_compare(self, self.device,
                          input_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)
        # Change the tunnel inheritance to PORT and execute the same
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)
        U.run_and_compare(self, self.device,
                          input_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        lsr.delete_route(self.SRC_LABEL)
        self.device.destroy(gre_ecmp)

        packets, byte_count = self.l3_egress_counter.read(0, True, True)
        self.assertEqual(packets, 2)

    def _test_mpls_decap_gre_encap_single_path_qos(self, is_port_inheritance_mode):
        '''
        When the tunnel's encap_qos_mode is UNIFORM (by default)
        and we set tunnel's lp_attribute_inheritance_mode to TUNNEL (lp_set = 1),
        the GRE outer IP DSCP should be determined by GRE tunnel port's egress_qos_profile marking
        Test-case 2: Outer DSCP comes from {Outgoing tunnel-qos-id, fwd-qos-tag/qos-group} [IP mapping QoS Tag table] [lp_set = 1]
        lp_set = 1 -> la_lp_attribute_inheritance_mode_e_TUNNEL
        '''
        self.gre_tunnel.set_encap_qos_mode(sdk.la_tunnel_encap_qos_mode_e_UNIFORM)
        gre_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        gre_ecmp.add_member(self.gre_destination)

        lsr = self.device.get_lsr()
        lsr.add_route(self.SRC_LABEL, gre_ecmp, self.PRIVATE_DATA)

        if (is_port_inheritance_mode):
            self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)
        else:
            self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)

        l3_egress_qos_profile = T.egress_qos_profile(self, self.device, sdk.la_egress_qos_marking_source_e_QOS_TAG)
        l3_egress_qos_profile.hld_obj.set_qos_tag_mapping_dscp(self.IN_DSCP, self.OUT_DSCP, self.encap_qos_values)
        if (is_port_inheritance_mode):
            self.topology.tx_l3_ac_reg.hld_obj.set_egress_qos_profile(l3_egress_qos_profile.hld_obj)
        else:
            self.gre_tunnel.set_egress_qos_profile(l3_egress_qos_profile.hld_obj)

        input_packet_base = \
            S.Ether(dst=self.OVL_IP_PACKET_DMAC,
                    src=self.OVL_IP_PACKET_SMAC) / \
            MPLS(label=self.SRC_LABEL.label, ttl=self.MPLS_TTL) / \
            S.IP(dst=self.OVL_IP_PACKET_DIP,
                 src=self.OVL_IP_PACKET_SIP,
                 ttl=self.OVL_IP_TTL,
                 tos=self.IN_DSCP.value << 2) / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                    src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(dst=self.GRE_DIP.addr_str,
                 src=self.GRE_SIP.addr_str,
                 tos=self.OUT_TOS.flat,
                 flags=2, ttl=255, id=0) / \
            S.GRE() / \
            S.IP(dst=self.OVL_IP_PACKET_DIP,
                 src=self.OVL_IP_PACKET_SIP, ttl=self.OVL_IP_TTL,
                 tos=self.IN_DSCP.value << 2) / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        lsr.delete_route(self.SRC_LABEL)
        self.device.destroy(gre_ecmp)

    def _test_mpls_decap_gre_encap_single_path_qos_group_id(self, is_port_inheritance_mode):
        '''
        Tunnel's encap_qos_mode is UNIFORM (by default)
        When tunnel's lp_attribute_inheritance_mode is set to PORT (lp_set = 0),
        the GRE outer IP DSCP should be determined by tx L3 port's egress_qos_profile marking
        Outer DSCP comes from {Outgoing L3-qos-id, qos-group} [IP mapping QoS Tag table]
        When tunnel's lp_attribute_inheritance_mode is set to TUNNEL (lp_set = 1),
        the GRE outer IP DSCP should be determined by Tunnel's egress_qos_profile marking
        Outer DSCP comes from {tunnel-qos-id, qos-group} [IP mapping QoS Tag table]
        '''
        self.gre_tunnel.set_encap_qos_mode(sdk.la_tunnel_encap_qos_mode_e_UNIFORM)
        gre_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        gre_ecmp.add_member(self.gre_destination)

        lsr = self.device.get_lsr()
        lsr.add_route(self.SRC_LABEL, gre_ecmp, self.PRIVATE_DATA)

        if (is_port_inheritance_mode):
            self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)
        else:
            self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)

        self.ingress_qos_profile = T.ingress_qos_profile(self, self.device)
        self.ingress_qos_profile.hld_obj.set_qos_tag_mapping_enabled(True)
        self.ingress_qos_profile.hld_obj.set_qos_group_mapping(self.mpls_tc, self.QOS_GROUPID)
        self.topology.tx_l3_ac_def.hld_obj.set_ingress_qos_profile(self.ingress_qos_profile.hld_obj)

        l3_egress_qos_profile = T.egress_qos_profile(self, self.device, sdk.la_egress_qos_marking_source_e_QOS_GROUP)
        l3_egress_qos_profile.hld_obj.set_qos_group_mapping_dscp(self.QOS_GROUPID, self.OUT_DSCP, self.encap_qos_values)
        if (is_port_inheritance_mode):
            self.topology.tx_l3_ac_reg.hld_obj.set_egress_qos_profile(l3_egress_qos_profile.hld_obj)
        else:
            self.gre_tunnel.set_egress_qos_profile(l3_egress_qos_profile.hld_obj)

        input_packet_base = \
            S.Ether(dst=self.OVL_IP_PACKET_DMAC,
                    src=self.OVL_IP_PACKET_SMAC) / \
            MPLS(label=self.SRC_LABEL.label, ttl=self.MPLS_TTL) / \
            S.IP(dst=self.OVL_IP_PACKET_DIP,
                 src=self.OVL_IP_PACKET_SIP,
                 ttl=self.OVL_IP_TTL,
                 tos=self.IN_DSCP.value << 2) / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                    src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(dst=self.GRE_DIP.addr_str,
                 src=self.GRE_SIP.addr_str,
                 tos=self.OUT_TOS.flat,
                 flags=2, ttl=255, id=0) / \
            S.GRE() / \
            S.IP(dst=self.OVL_IP_PACKET_DIP,
                 src=self.OVL_IP_PACKET_SIP, ttl=self.OVL_IP_TTL,
                 tos=self.IN_DSCP.value << 2) / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        lsr.delete_route(self.SRC_LABEL)
        self.device.destroy(gre_ecmp)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_gre_decap_mpls_forwarding_mpls_disable(self):
        '''
        GRE DECAP followed by MPLS forwarding
        '''
        self.gre_port_single_path()
        self._test_gre_decap_mpls_forwarding_mpls_disable()
        self.destory_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_forwarding(self):
        '''
        GRE DECAP followed by MPLS forwarding
        '''
        self.gre_port_single_path()
        self._test_gre_decap_mpls_forwarding()
        self.destory_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_forwarding_counters(self):
        '''
        GRE DECAP followed by MPLS forwarding
        '''
        self.gre_port_single_path()
        self._test_gre_decap_mpls_forwarding(test_counters=True)
        self.destory_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_gre_decap_mpls_forwarding_port(self):
        '''
        GRE DECAP followed by MPLS forwarding
        '''
        self.gre_port_single_path()
        self._test_gre_decap_mpls_forwarding(port_inheritance=True)
        self.destory_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_gre_decap_mpls_forwarding_port_counters(self):
        '''
        GRE DECAP followed by MPLS forwarding
        '''
        self.gre_port_single_path()
        self._test_gre_decap_mpls_forwarding(port_inheritance=True, test_counters=True)
        self.destory_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_encap(self):
        '''
        GRE DECAP followed by MPLS ENCAP
        '''
        self.gre_port_single_path()
        self._test_gre_decap_mpls_encap()
        self.destory_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_mpls_decap_gre_encap_single_path(self):
        '''
        MPLS terminate then GRE ENCAP
        '''
        self.gre_port_single_path()
        self._test_mpls_decap_gre_encap_single_path()
        self.destory_gre_port_single_path()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mpls_decap_gre_encap_multi_path(self):
        '''
        MPLS terminate then GRE ENCAP ECMP
        '''
        self.gre_port_multi_path()
        self._test_mpls_decap_gre_encap_multi_path()
        self.destory_gre_port_multi_path()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_forwarding_ecmp(self):
        '''
        GRE DECAP followed by MPLS forwarding on ecmp path
        '''
        self.gre_port_ecmp_path()
        self._test_gre_decap_mpls_forwarding_ecmp()
        self.destory_gre_port_ecmp_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_encap_sr_ipv4(self):
        '''
        IPv4 GRE DECAP followed by MPLS SRTE ENCAP
        '''
        self.gre_port_single_path()
        self._test_gre_decap_mpls_encap_sr_ipv4()
        self.destory_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    def test_gre_decap_mpls_encap_ecmp_sr_ipv4(self):
        '''
        IPv4 GRE DECAP followed by MPLS SRTE ENCAP with ECMP
        '''
        self.gre_port_single_path()
        self._test_gre_decap_mpls_encap_ecmp_sr_ipv4()
        self.destory_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_decap_mpls_encap_sr_ipv6(self):
        '''
        IPv6 GRE DECAP followed by MPLS SRTE ENCAP
        '''
        self.gre_port_single_path()
        self._test_gre_decap_mpls_encap_sr_ipv6()
        self.destory_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    def test_gre_decap_mpls_encap_ecmp_sr_ipv6(self):
        '''
        IPv6 GRE DECAP followed by MPLS SRTE ENCAP with ECMP
        '''
        self.gre_port_single_path()
        self._test_gre_decap_mpls_encap_ecmp_sr_ipv6()
        self.destory_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_mpls_decap_gre_encap_single_path_tos(self):
        '''
        MPLS terminate then GRE ENCAP
        '''
        self.gre_port_single_path()
        self._test_mpls_decap_gre_encap_single_path_qos_tos()
        self.destory_gre_port_single_path()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    def test_mpls_decap_gre_encap_single_path_qos_port(self):
        '''
        MPLS terminate then GRE ENCAP with egress QoS on Tx port
        '''
        self.gre_port_single_path()
        is_port_inheritance = True
        self._test_mpls_decap_gre_encap_single_path_qos(is_port_inheritance)
        self.destory_gre_port_single_path()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    def test_mpls_decap_gre_encap_single_path_qos_tunnel(self):
        '''
        MPLS terminate then GRE ENCAP with egress QoS on tunnel
        '''
        self.gre_port_single_path()
        is_port_inheritance = False
        self._test_mpls_decap_gre_encap_single_path_qos(is_port_inheritance)
        self.destory_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_mpls_decap_gre_encap_single_path_qos_group_id_port(self):
        '''
        MPLS terminate then GRE ENCAP with egress QoS on port using group id
        '''
        self.gre_port_single_path()
        is_port_inheritance = True
        self._test_mpls_decap_gre_encap_single_path_qos_group_id(is_port_inheritance)
        self.destory_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_mpls_decap_gre_encap_single_path_qos_group_id_tunnel(self):
        '''
        MPLS terminate then GRE ENCAP with egress QoS on tunnel using group id
        '''
        self.gre_port_single_path()
        is_port_inheritance = False
        self._test_mpls_decap_gre_encap_single_path_qos_group_id(is_port_inheritance)
        self.destory_gre_port_single_path()


if __name__ == '__main__':
    unittest.main()
