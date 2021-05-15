#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import packet_test_utils as U
from scapy.all import *
import sim_utils
from sdk_test_case_base import *

U.parse_ip_after_mpls()


class per_prefix_vpn_base(sdk_test_case_base):
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    NEW_RX_L3_AC_MAC = T.mac_addr('30:32:33:34:35:36')
    PREFIX1_GID = 0x111
    PREFIX2_GID = 0x555
    DPE_GID = 0x1008
    DPE_GID1 = 0x2008
    IP_TTL = 64
    PATH1_LDP_LABEL = 0x123
    PATH2_LDP_LABEL = 0x234
    PATH1_VPN_LABEL = 0x456
    PATH2_VPN_LABEL = 0x567
    BGP_LABEL = 0x71
    PREFIX1_LDP_LABEL = sdk.la_mpls_label()
    PREFIX1_LDP_LABEL.label = PATH1_LDP_LABEL
    PREFIX2_LDP_LABEL = sdk.la_mpls_label()
    PREFIX2_LDP_LABEL.label = PATH2_LDP_LABEL
    PREFIX1_VPN_LABEL = sdk.la_mpls_label()
    PREFIX1_VPN_LABEL.label = PATH1_VPN_LABEL
    PREFIX2_VPN_LABEL = sdk.la_mpls_label()
    PREFIX2_VPN_LABEL.label = PATH2_VPN_LABEL
    PREFIX_BGP_LABEL = sdk.la_mpls_label()
    PREFIX_BGP_LABEL.label = BGP_LABEL
    MPLS_VPN_ENCAP_ID = 0x222
    MPLS_VPN_ENCAP_ID_EXT = 0x223
    VPN_ROUTE = T.ipv4_addr('21.1.1.0')
    VPN_ROUTE32 = T.ipv4_addr('32.1.1.1')
    VPN_ROUTE_v6 = T.ipv6_addr('4000:dddd:eeee:ffff:0000:0000:0000:0000')
    VPN_ROUTE128_v6 = T.ipv6_addr('6000:dddd:eeee:ffff:0000:0000:0000:0001')
    DIP = '21.1.1.1'
    DIP32 = '32.1.1.1'
    SIP = '10.0.0.1'
    DIP_V6 = '4000:dddd:eeee:ffff:0000:0000:0000:0001'
    DIP128_V6 = '6000:dddd:eeee:ffff:0000:0000:0000:0001'
    SIP_V6 = '5000:aaaa:bbbb:cccc:0000:0000:0000:0001'

    def setUp(self):
        super().setUp()

        self.ip_impl = ip_test_base.ipv4_test_base
        self.ipv6_impl = ip_test_base.ipv6_test_base
        self.l3_port_impl = T.ip_l3_ac_base(self.topology)

        self.add_default_route()

        # Create 2 prefix objects
        # the outgoing interface is tx_l3_port_reg
        self.pfx_obj1 = self.create_vpn_nh_prefix(
            per_prefix_vpn_base.PREFIX1_GID,
            self.l3_port_impl.reg_nh.hld_obj,
            per_prefix_vpn_base.PREFIX1_LDP_LABEL)

        # the outgoing interface is tx_l3_port_def
        self.pfx_obj2 = self.create_vpn_nh_prefix(
            per_prefix_vpn_base.PREFIX2_GID,
            self.l3_port_impl.def_nh.hld_obj,
            per_prefix_vpn_base.PREFIX2_LDP_LABEL)

    def tearDown(self):
        self.topology.vrf.hld_obj.delete_ipv4_route(self.vpn_prefix)
        self.topology.vrf.hld_obj.delete_ipv4_route(self.vpn_prefix32)
        self.topology.vrf.hld_obj.delete_ipv6_route(self.vpn_prefix_v6)
        self.topology.vrf.hld_obj.delete_ipv6_route(self.vpn_prefix128_v6)
        self.device.destroy(self.vpn_encap)
        if hasattr(self, 'vpn_ecmp') is True:
            self.device.destroy(self.vpn_ecmp)
        self.clear_bgp_lu_objects()
        self.destroy_prefix_obj(self.pfx_obj1.hld_obj, self.l3_port_impl.reg_nh.hld_obj)
        self.destroy_prefix_obj(self.pfx_obj2.hld_obj, self.l3_port_impl.def_nh.hld_obj)
        self.destroy_default_route()
        super().tearDown()

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix,
                               self.l3_port_impl.def_nh,
                               per_prefix_vpn_base.PRIVATE_DATA_DEFAULT)

    def destroy_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def create_vpn_nh_prefix(self, id, nh, label, add_lsp_counter=True):
        pfx_obj = T.prefix_object(self, self.device, id, nh)
        lsp_counter = self.device.create_counter(1) if add_lsp_counter else None
        pfx_obj.hld_obj.set_nh_lsp_properties(nh, [label], lsp_counter, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        return pfx_obj

    def destroy_prefix_obj(self, prefix, nh):
        labels, counter, _ = prefix.get_nh_lsp_properties(nh)
        self.device.destroy(prefix)
        self.device.destroy(counter)

    def create_vpn_encap(self, id, dest):
        vpn_encap = self.device.create_mpls_vpn_encap(id)
        vpn_encap.set_destination(dest)
        return vpn_encap

    def create_vpn_prefix(self):
        self.vpn_prefix = self.ip_impl.build_prefix(per_prefix_vpn_base.VPN_ROUTE, length=24)
        self.vpn_prefix32 = self.ip_impl.build_prefix(per_prefix_vpn_base.VPN_ROUTE32, length=32)
        self.vpn_prefix_v6 = self.ipv6_impl.build_prefix(per_prefix_vpn_base.VPN_ROUTE_v6, length=64)
        self.vpn_prefix128_v6 = self.ipv6_impl.build_prefix(per_prefix_vpn_base.VPN_ROUTE128_v6, length=128)
        self.topology.vrf.hld_obj.add_ipv4_route(self.vpn_prefix, self.vpn_encap, per_prefix_vpn_base.PRIVATE_DATA, False)
        self.topology.vrf.hld_obj.add_ipv4_route(self.vpn_prefix32, self.vpn_encap, per_prefix_vpn_base.PRIVATE_DATA, True)
        self.topology.vrf.hld_obj.add_ipv6_route(self.vpn_prefix_v6, self.vpn_encap, per_prefix_vpn_base.PRIVATE_DATA, False)
        self.topology.vrf.hld_obj.add_ipv6_route(self.vpn_prefix128_v6, self.vpn_encap, per_prefix_vpn_base.PRIVATE_DATA, True)

    def clear_bgp_lu_objects(self):
        if hasattr(self, 'vpn_encap_ext'):
            self.device.destroy(self.vpn_encap_ext)
        if hasattr(self, 'bgp_ecmp') is True:
            self.device.destroy(self.bgp_ecmp)
        if hasattr(self, 'dpe1') is True:
            self.device.destroy(self.dpe1.hld_obj)
            self.device.destroy(self.asbr_lsp_ecmp1)
            self.device.destroy(self.asbr_lsp1.hld_obj)
        if hasattr(self, 'dpe2') is True:
            self.device.destroy(self.dpe2.hld_obj)
            self.device.destroy(self.asbr_lsp_ecmp2)
            self.device.destroy(self.asbr_lsp2.hld_obj)

    def setup_single_pe_single_path(self):
        # create the mpls vpn encap object
        self.vpn_encap = self.create_vpn_encap(per_prefix_vpn_base.MPLS_VPN_ENCAP_ID, self.pfx_obj1.hld_obj)
        # set vpn label
        self.vpn_encap.set_nh_vpn_properties(
            self.pfx_obj1.hld_obj, sdk.la_ip_version_e_IPV4, [
                per_prefix_vpn_base.PREFIX1_VPN_LABEL])
        self.vpn_encap.set_nh_vpn_properties(
            self.pfx_obj1.hld_obj, sdk.la_ip_version_e_IPV6, [
                per_prefix_vpn_base.PREFIX2_VPN_LABEL])

        # create the prefix
        self.create_vpn_prefix()

    def setup_multi_pe_single_path(self):
        # create ecmp_group
        self.vpn_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.vpn_ecmp.add_member(self.pfx_obj1.hld_obj)
        self.vpn_ecmp.add_member(self.pfx_obj2.hld_obj)

        # create the mpls vpn encap object
        self.vpn_encap = self.create_vpn_encap(per_prefix_vpn_base.MPLS_VPN_ENCAP_ID, self.vpn_ecmp)

        # set vpn label
        self.vpn_encap.set_nh_vpn_properties(
            self.pfx_obj1.hld_obj, sdk.la_ip_version_e_IPV4, [
                per_prefix_vpn_base.PREFIX1_VPN_LABEL])
        self.vpn_encap.set_nh_vpn_properties(
            self.pfx_obj1.hld_obj, sdk.la_ip_version_e_IPV6, [
                per_prefix_vpn_base.PREFIX1_VPN_LABEL])
        self.vpn_encap.set_nh_vpn_properties(
            self.pfx_obj2.hld_obj, sdk.la_ip_version_e_IPV4, [
                per_prefix_vpn_base.PREFIX2_VPN_LABEL])
        self.vpn_encap.set_nh_vpn_properties(
            self.pfx_obj2.hld_obj, sdk.la_ip_version_e_IPV6, [
                per_prefix_vpn_base.PREFIX2_VPN_LABEL])

        # create the prefix
        self.create_vpn_prefix()

    def setup_single_pe_single_path_bgp_lu(self):
        # Create the Label Switched Path to reach the ASBR
        self.asbr_lsp1 = T.asbr_lsp(
            self,
            self.device,
            self.pfx_obj1.hld_obj,
            self.l3_port_impl.reg_nh.hld_obj)

        # Create an ECMP group and add the ASBR LSP as a member
        self.asbr_lsp_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(self.asbr_lsp_ecmp1, None)
        self.asbr_lsp_ecmp1.add_member(self.asbr_lsp1.hld_obj)

        # Create the Destination PE
        self.dpe1 = T.destination_pe(self, self.device, self.DPE_GID, self.asbr_lsp_ecmp1)

        asbr_labels = []
        asbr_labels.append(self.PREFIX_BGP_LABEL)

        # Program the BGP labels
        self.dpe1.hld_obj.set_asbr_properties(self.pfx_obj1.hld_obj, asbr_labels)

        # create the mpls vpn encap object
        self.vpn_encap = self.create_vpn_encap(per_prefix_vpn_base.MPLS_VPN_ENCAP_ID, self.dpe1.hld_obj)
        # set vpn label
        self.vpn_encap.set_nh_vpn_properties(self.dpe1.hld_obj, sdk.la_ip_version_e_IPV4, [per_prefix_vpn_base.PREFIX1_VPN_LABEL])
        self.vpn_encap.set_nh_vpn_properties(self.dpe1.hld_obj, sdk.la_ip_version_e_IPV6, [per_prefix_vpn_base.PREFIX1_VPN_LABEL])

        # create the prefix
        self.create_vpn_prefix()

    def setup_multi_pe_single_path_bgp_lu(self):
        # Create two Label Switched Paths
        self.asbr_lsp1 = T.asbr_lsp(
            self,
            self.device,
            self.pfx_obj1.hld_obj,
            self.l3_port_impl.reg_nh.hld_obj)

        self.asbr_lsp2 = T.asbr_lsp(
            self,
            self.device,
            self.pfx_obj2.hld_obj,
            self.l3_port_impl.def_nh.hld_obj)

        # Create ECMP groups and add the ASBR LSPs as members
        self.asbr_lsp_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(self.asbr_lsp_ecmp1, None)
        self.asbr_lsp_ecmp1.add_member(self.asbr_lsp1.hld_obj)

        self.asbr_lsp_ecmp2 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(self.asbr_lsp_ecmp2, None)
        self.asbr_lsp_ecmp2.add_member(self.asbr_lsp2.hld_obj)

        # Create the Destination PEs
        self.dpe1 = T.destination_pe(self, self.device, self.DPE_GID, self.asbr_lsp_ecmp1)
        self.dpe2 = T.destination_pe(self, self.device, self.DPE_GID1, self.asbr_lsp_ecmp2)

        asbr_labels = []
        asbr_labels.append(self.PREFIX_BGP_LABEL)

        # Program the BGP labels
        self.dpe1.hld_obj.set_asbr_properties(self.pfx_obj1.hld_obj, asbr_labels)
        self.dpe2.hld_obj.set_asbr_properties(self.pfx_obj2.hld_obj, asbr_labels)

        # Create DPE ECMP
        self.bgp_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.assertNotEqual(self.bgp_ecmp, None)
        self.bgp_ecmp.add_member(self.dpe1.hld_obj)
        self.bgp_ecmp.add_member(self.dpe2.hld_obj)

        # create the mpls vpn encap objects
        self.vpn_encap = self.create_vpn_encap(per_prefix_vpn_base.MPLS_VPN_ENCAP_ID, self.bgp_ecmp)
        # set vpn labels
        self.vpn_encap.set_nh_vpn_properties(self.dpe1.hld_obj, sdk.la_ip_version_e_IPV4, [per_prefix_vpn_base.PREFIX1_VPN_LABEL])
        self.vpn_encap.set_nh_vpn_properties(self.dpe1.hld_obj, sdk.la_ip_version_e_IPV6, [per_prefix_vpn_base.PREFIX1_VPN_LABEL])
        self.vpn_encap.set_nh_vpn_properties(self.dpe2.hld_obj, sdk.la_ip_version_e_IPV4, [per_prefix_vpn_base.PREFIX2_VPN_LABEL])
        self.vpn_encap.set_nh_vpn_properties(self.dpe2.hld_obj, sdk.la_ip_version_e_IPV6, [per_prefix_vpn_base.PREFIX2_VPN_LABEL])

        # create the prefix
        self.create_vpn_prefix()

    def setup_single_pe_multi_path_bgp_lu(self):
        # Create the Label Switched Path to reach the ASBR
        self.asbr_lsp1 = T.asbr_lsp(
            self,
            self.device,
            self.pfx_obj1.hld_obj,
            self.l3_port_impl.reg_nh.hld_obj)

        # Create an ECMP group and add the ASBR LSP as a member
        self.asbr_lsp_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(self.asbr_lsp_ecmp1, None)
        self.asbr_lsp_ecmp1.add_member(self.asbr_lsp1.hld_obj)

        # Create the Destination PE
        self.dpe1 = T.destination_pe(self, self.device, self.DPE_GID, self.asbr_lsp_ecmp1)

        asbr_labels = []
        asbr_labels.append(self.PREFIX_BGP_LABEL)

        # Program the BGP labels
        self.dpe1.hld_obj.set_asbr_properties(self.pfx_obj1.hld_obj, asbr_labels)

        # create the mpls vpn encap object
        self.vpn_encap = self.create_vpn_encap(per_prefix_vpn_base.MPLS_VPN_ENCAP_ID, self.dpe1.hld_obj)
        # set vpn label
        self.vpn_encap.set_nh_vpn_properties(self.dpe1.hld_obj, sdk.la_ip_version_e_IPV4, [per_prefix_vpn_base.PREFIX1_VPN_LABEL])
        self.vpn_encap.set_nh_vpn_properties(self.dpe1.hld_obj, sdk.la_ip_version_e_IPV6, [per_prefix_vpn_base.PREFIX1_VPN_LABEL])

        # create second mpls vpn encap object
        self.vpn_encap_ext = self.create_vpn_encap(per_prefix_vpn_base.MPLS_VPN_ENCAP_ID_EXT, self.dpe1.hld_obj)
        # set vpn label
        self.vpn_encap_ext.set_nh_vpn_properties(
            self.dpe1.hld_obj, sdk.la_ip_version_e_IPV4, [
                per_prefix_vpn_base.PREFIX2_VPN_LABEL])
        self.vpn_encap_ext.set_nh_vpn_properties(
            self.dpe1.hld_obj, sdk.la_ip_version_e_IPV6, [
                per_prefix_vpn_base.PREFIX2_VPN_LABEL])

        # create the prefix
        self.create_vpn_prefix()

        # Modify /32 and /128 route to point to new vpn encap
        self.topology.vrf.hld_obj.modify_ipv4_route(self.vpn_prefix32, self.vpn_encap_ext, per_prefix_vpn_base.PRIVATE_DATA)
        self.topology.vrf.hld_obj.modify_ipv6_route(self.vpn_prefix128_v6, self.vpn_encap_ext, per_prefix_vpn_base.PRIVATE_DATA)

    def _test_single_pe_single_path(self):
        self.input_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src='00:11:22:33:44:55', type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP,
               ttl=per_prefix_vpn_base.IP_TTL) / \
            TCP()

        self.expected_packet_base = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            MPLS(label=per_prefix_vpn_base.PATH1_LDP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.PATH1_VPN_LABEL, ttl=255) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP, ttl=(per_prefix_vpn_base.IP_TTL - 1)) / \
            TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(self.input_packet_base, self.expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.RX_SLICE,
                          T.RX_IFG, T.FIRST_SERDES,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.input_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src='00:11:22:33:44:55', type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP32,
               ttl=per_prefix_vpn_base.IP_TTL) / \
            TCP()

        self.expected_packet_base = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            MPLS(label=per_prefix_vpn_base.PATH1_LDP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.PATH1_VPN_LABEL, ttl=255) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP32, ttl=(per_prefix_vpn_base.IP_TTL - 1)) / \
            TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(self.input_packet_base, self.expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.RX_SLICE,
                          T.RX_IFG, T.FIRST_SERDES,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.input_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src='00:11:22:33:44:55', type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IPv6(src=per_prefix_vpn_base.SIP_V6, dst=per_prefix_vpn_base.DIP_V6,
                 hlim=per_prefix_vpn_base.IP_TTL) / \
            TCP()

        self.expected_packet_base = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            MPLS(label=per_prefix_vpn_base.PATH1_LDP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.PATH2_VPN_LABEL, ttl=255) / \
            IPv6(src=per_prefix_vpn_base.SIP_V6, dst=per_prefix_vpn_base.DIP_V6, hlim=(per_prefix_vpn_base.IP_TTL - 1)) / \
            TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(self.input_packet_base, self.expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.RX_SLICE,
                          T.RX_IFG, T.FIRST_SERDES,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.input_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src='00:11:22:33:44:55', type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IPv6(src=per_prefix_vpn_base.SIP_V6, dst=per_prefix_vpn_base.DIP128_V6,
                 hlim=per_prefix_vpn_base.IP_TTL) / \
            TCP()

        self.expected_packet_base = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            MPLS(label=per_prefix_vpn_base.PATH1_LDP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.PATH2_VPN_LABEL, ttl=255) / \
            IPv6(src=per_prefix_vpn_base.SIP_V6, dst=per_prefix_vpn_base.DIP128_V6, hlim=(per_prefix_vpn_base.IP_TTL - 1)) / \
            TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(self.input_packet_base, self.expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.RX_SLICE,
                          T.RX_IFG, T.FIRST_SERDES,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        # Change path to another prefix
        self.vpn_encap.set_nh_vpn_properties(
            self.pfx_obj2.hld_obj, sdk.la_ip_version_e_IPV4, [
                per_prefix_vpn_base.PREFIX2_VPN_LABEL])
        self.vpn_encap.set_nh_vpn_properties(
            self.pfx_obj2.hld_obj, sdk.la_ip_version_e_IPV6, [
                per_prefix_vpn_base.PREFIX2_VPN_LABEL])
        self.vpn_encap.set_destination(self.pfx_obj2.hld_obj)

        self.input_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src='00:11:22:33:44:55', type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP,
               ttl=per_prefix_vpn_base.IP_TTL) / \
            TCP()

        self.expected_packet_base = \
            Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) / \
            MPLS(label=per_prefix_vpn_base.PATH2_LDP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.PATH2_VPN_LABEL, ttl=255) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP, ttl=(per_prefix_vpn_base.IP_TTL - 1)) / \
            TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(self.input_packet_base, self.expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.RX_SLICE,
                          T.RX_IFG, T.FIRST_SERDES,
                          self.expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

    def _test_single_pe_single_path_bgp_lu(self):
        self.input_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src='00:11:22:33:44:55', type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP,
               ttl=per_prefix_vpn_base.IP_TTL) / \
            TCP()

        self.expected_packet_base = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            MPLS(label=per_prefix_vpn_base.PATH1_LDP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.BGP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.PATH1_VPN_LABEL, ttl=255) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP, ttl=(per_prefix_vpn_base.IP_TTL - 1)) / \
            TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(self.input_packet_base, self.expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.RX_SLICE,
                          T.RX_IFG, T.FIRST_SERDES,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.input_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src='00:11:22:33:44:55', type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP32,
               ttl=per_prefix_vpn_base.IP_TTL) / \
            TCP()

        self.expected_packet_base = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            MPLS(label=per_prefix_vpn_base.PATH1_LDP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.BGP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.PATH1_VPN_LABEL, ttl=255) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP32, ttl=(per_prefix_vpn_base.IP_TTL - 1)) / \
            TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(self.input_packet_base, self.expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.RX_SLICE,
                          T.RX_IFG, T.FIRST_SERDES,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.input_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src='00:11:22:33:44:55', type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IPv6(src=per_prefix_vpn_base.SIP_V6, dst=per_prefix_vpn_base.DIP_V6,
                 hlim=per_prefix_vpn_base.IP_TTL) / \
            TCP()

        self.expected_packet_base = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            MPLS(label=per_prefix_vpn_base.PATH1_LDP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.BGP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.PATH1_VPN_LABEL, ttl=255) / \
            IPv6(src=per_prefix_vpn_base.SIP_V6, dst=per_prefix_vpn_base.DIP_V6, hlim=(per_prefix_vpn_base.IP_TTL - 1)) / \
            TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(self.input_packet_base, self.expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.RX_SLICE,
                          T.RX_IFG, T.FIRST_SERDES,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.input_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src='00:11:22:33:44:55', type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IPv6(src=per_prefix_vpn_base.SIP_V6, dst=per_prefix_vpn_base.DIP128_V6,
                 hlim=per_prefix_vpn_base.IP_TTL) / \
            TCP()

        self.expected_packet_base = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            MPLS(label=per_prefix_vpn_base.PATH1_LDP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.BGP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.PATH1_VPN_LABEL, ttl=255) / \
            IPv6(src=per_prefix_vpn_base.SIP_V6, dst=per_prefix_vpn_base.DIP128_V6, hlim=(per_prefix_vpn_base.IP_TTL - 1)) / \
            TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(self.input_packet_base, self.expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.RX_SLICE,
                          T.RX_IFG, T.FIRST_SERDES,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

    def _test_single_pe_multi_path_bgp_lu(self):
        self.input_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src='00:11:22:33:44:55', type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP,
               ttl=per_prefix_vpn_base.IP_TTL) / \
            TCP()

        self.expected_packet_base = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            MPLS(label=per_prefix_vpn_base.PATH1_LDP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.BGP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.PATH1_VPN_LABEL, ttl=255) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP, ttl=(per_prefix_vpn_base.IP_TTL - 1)) / \
            TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(self.input_packet_base, self.expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.RX_SLICE,
                          T.RX_IFG, T.FIRST_SERDES,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.input_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src='00:11:22:33:44:55', type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP32,
               ttl=per_prefix_vpn_base.IP_TTL) / \
            TCP()

        self.expected_packet_base = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            MPLS(label=per_prefix_vpn_base.PATH1_LDP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.BGP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.PATH2_VPN_LABEL, ttl=255) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP32, ttl=(per_prefix_vpn_base.IP_TTL - 1)) / \
            TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(self.input_packet_base, self.expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.RX_SLICE,
                          T.RX_IFG, T.FIRST_SERDES,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.input_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src='00:11:22:33:44:55', type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IPv6(src=per_prefix_vpn_base.SIP_V6, dst=per_prefix_vpn_base.DIP_V6,
                 hlim=per_prefix_vpn_base.IP_TTL) / \
            TCP()

        self.expected_packet_base = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            MPLS(label=per_prefix_vpn_base.PATH1_LDP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.BGP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.PATH1_VPN_LABEL, ttl=255) / \
            IPv6(src=per_prefix_vpn_base.SIP_V6, dst=per_prefix_vpn_base.DIP_V6, hlim=(per_prefix_vpn_base.IP_TTL - 1)) / \
            TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(self.input_packet_base, self.expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.RX_SLICE,
                          T.RX_IFG, T.FIRST_SERDES,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.input_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src='00:11:22:33:44:55', type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IPv6(src=per_prefix_vpn_base.SIP_V6, dst=per_prefix_vpn_base.DIP128_V6,
                 hlim=per_prefix_vpn_base.IP_TTL) / \
            TCP()

        self.expected_packet_base = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            MPLS(label=per_prefix_vpn_base.PATH1_LDP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.BGP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.PATH2_VPN_LABEL, ttl=255) / \
            IPv6(src=per_prefix_vpn_base.SIP_V6, dst=per_prefix_vpn_base.DIP128_V6, hlim=(per_prefix_vpn_base.IP_TTL - 1)) / \
            TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(self.input_packet_base, self.expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.RX_SLICE,
                          T.RX_IFG, T.FIRST_SERDES,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

    def calculate_lb_vec(self, is_ipv4):
        lb_vec = sdk.la_lb_vector_t()

        if is_ipv4:
            dip = T.ipv4_addr(self.input_packet[IP].dst)
            sip = T.ipv4_addr(self.input_packet[IP].src)

            lb_vec.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
            lb_vec.ipv4.sip = sip.hld_obj.s_addr
            lb_vec.ipv4.dip = dip.hld_obj.s_addr
            lb_vec.ipv4.protocol = self.input_packet[IP].proto
            lb_vec.ipv4.src_port = self.input_packet[TCP].sport
            lb_vec.ipv4.dest_port = self.input_packet[TCP].dport
        else:
            dip = T.ipv6_addr(self.input_packet[IPv6].dst).hld_obj.d_addr
            sip = T.ipv6_addr(self.input_packet[IPv6].src).hld_obj.d_addr

            lb_vec.type = sdk.LA_LB_VECTOR_IPV6_TCP_UDP
            lb_vec.ipv6.sip = sip
            lb_vec.ipv6.dip = dip
            lb_vec.ipv6.next_header = self.input_packet[IPv6].nh
            lb_vec.ipv6.src_port = self.input_packet[TCP].sport
            lb_vec.ipv6.dest_port = self.input_packet[TCP].dport
            lb_vec.ipv6.flow_label = 0

        return lb_vec

    def calculate_ecmp_expected_output(self, is_ipv4):

        lb_vec = self.calculate_lb_vec(is_ipv4)
        lb_vec_entry_list = []
        lb_vec_entry_list.append(lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(self.vpn_ecmp, lb_vec_entry_list)

        ### For Debug purpose:########################################################
        #U.display_forwarding_load_balance_chain(self.vpn_ecmp, out_dest_chain)
        #print('pfx_obj1=%d pfx_obj2=%d' % (self.pfx_obj1.hld_obj.oid(),  self.pfx_obj2.hld_obj.oid()))
        ##############################################################################

        self.assertEqual(out_dest_chain[-1].type(), sdk.la_object.object_type_e_PREFIX_OBJECT)

        prefix_obj = out_dest_chain[-1].downcast()

        nh_obj = prefix_obj.get_destination()
        out_nh = nh_obj.downcast()
        out_dsp = out_nh.get_router_port().downcast().get_ethernet_port().get_system_port()

        dst = out_nh.get_mac()
        src = out_nh.get_router_port().downcast().get_mac()
        dst_str = T.mac_addr.mac_num_to_str(dst.flat)
        src_str = T.mac_addr.mac_num_to_str(src.flat)

        ldp_labels, _, _ = prefix_obj.get_nh_lsp_properties(out_nh)
        vpn_labels = self.vpn_encap.get_nh_vpn_properties(prefix_obj, sdk.la_ip_version_e_IPV4)

        new_eth_hdr = Ether(dst=dst_str, src=src_str)
        new_mpls_hdr1 = MPLS(label=ldp_labels[0].label, ttl=255)
        new_mpls_hdr2 = MPLS(label=vpn_labels[0].label, ttl=255)

        expected_packet = new_eth_hdr / new_mpls_hdr1 / new_mpls_hdr2 / self.expected_packet[3]

        out_slice = out_dsp.get_slice()
        out_ifg = out_dsp.get_ifg()
        out_pif = out_dsp.get_base_serdes()

        return expected_packet, out_slice, out_ifg, out_pif

    def calculate_ecmp_expected_output_bgp_lu(self, is_ipv4):

        lb_vec = self.calculate_lb_vec(is_ipv4)
        lb_vec_entry_list = []
        lb_vec_entry_list.append(lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(self.bgp_ecmp, lb_vec_entry_list)

        self.assertEqual(out_dest_chain[-1].type(), sdk.la_object.object_type_e_DESTINATION_PE)

        dpe = out_dest_chain[-1].downcast()
        dpe_ecmp = dpe.get_destination()
        out_dpe_ecmp = dpe_ecmp.downcast()

        asbr = out_dpe_ecmp.get_member(0)
        out_asbr = asbr.downcast()

        pref_obj = out_asbr.get_asbr()

        nh_obj = out_asbr.get_destination()
        out_nh = nh_obj.downcast()
        out_dsp = out_nh.get_router_port().downcast().get_ethernet_port().get_system_port()

        dst = out_nh.get_mac()
        src = out_nh.get_router_port().downcast().get_mac()
        dst_str = T.mac_addr.mac_num_to_str(dst.flat)
        src_str = T.mac_addr.mac_num_to_str(src.flat)

        ldp_labels, _, _ = pref_obj.get_nh_lsp_properties(out_nh)
        vpn_labels = self.vpn_encap.get_nh_vpn_properties(dpe, sdk.la_ip_version_e_IPV4)

        new_eth_hdr = Ether(dst=dst_str, src=src_str)
        new_mpls_hdr1 = MPLS(label=ldp_labels[0].label, ttl=255)
        new_mpls_hdr2 = MPLS(label=per_prefix_vpn_base.BGP_LABEL, ttl=255)
        new_mpls_hdr3 = MPLS(label=vpn_labels[0].label, ttl=255)

        expected_packet = new_eth_hdr / new_mpls_hdr1 / new_mpls_hdr2 / new_mpls_hdr3 / self.expected_packet[4]

        out_slice = out_dsp.get_slice()
        out_ifg = out_dsp.get_ifg()
        out_pif = out_dsp.get_base_serdes()

        return expected_packet, out_slice, out_ifg, out_pif

    def _test_multi_pe_single_path(self):

        self.input_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src='00:11:22:33:44:55',
                  type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP,
               ttl=per_prefix_vpn_base.IP_TTL) / \
            TCP()

        self.expected_packet_base = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            MPLS(label=per_prefix_vpn_base.PATH1_LDP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.PATH1_VPN_LABEL, ttl=255) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP, ttl=(per_prefix_vpn_base.IP_TTL - 1)) / \
            TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(self.input_packet_base, self.expected_packet_base)
        self.expected_packet, out_slice, out_ifg, out_pif = self.calculate_ecmp_expected_output(True)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.expected_packet, out_slice, out_ifg, out_pif)

        self.input_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src='00:11:22:33:44:55', type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IPv6(src=per_prefix_vpn_base.SIP_V6, dst=per_prefix_vpn_base.DIP_V6,
                 hlim=per_prefix_vpn_base.IP_TTL) / \
            TCP()

        self.expected_packet_base = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            MPLS(label=per_prefix_vpn_base.PATH1_LDP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.PATH1_VPN_LABEL, ttl=255) / \
            IPv6(src=per_prefix_vpn_base.SIP_V6, dst=per_prefix_vpn_base.DIP_V6, hlim=(per_prefix_vpn_base.IP_TTL - 1)) / \
            TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(self.input_packet_base, self.expected_packet_base)
        self.expected_packet, out_slice, out_ifg, out_pif = self.calculate_ecmp_expected_output(False)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.expected_packet, out_slice, out_ifg, out_pif)

    def _test_multi_pe_single_path_bgp_lu(self):

        self.input_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src='00:11:22:33:44:55',
                  type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP,
               ttl=per_prefix_vpn_base.IP_TTL) / \
            TCP()

        self.expected_packet_base = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            MPLS(label=per_prefix_vpn_base.PATH1_LDP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.BGP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.PATH1_VPN_LABEL, ttl=255) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP, ttl=(per_prefix_vpn_base.IP_TTL - 1)) / \
            TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(self.input_packet_base, self.expected_packet_base)
        self.expected_packet, out_slice, out_ifg, out_pif = self.calculate_ecmp_expected_output_bgp_lu(True)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.expected_packet, out_slice, out_ifg, out_pif)

        self.input_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src='00:11:22:33:44:55', type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IPv6(src=per_prefix_vpn_base.SIP_V6, dst=per_prefix_vpn_base.DIP_V6,
                 hlim=per_prefix_vpn_base.IP_TTL) / \
            TCP()

        self.expected_packet_base = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            MPLS(label=per_prefix_vpn_base.PATH1_LDP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.BGP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.PATH1_VPN_LABEL, ttl=255) / \
            IPv6(src=per_prefix_vpn_base.SIP_V6, dst=per_prefix_vpn_base.DIP_V6, hlim=(per_prefix_vpn_base.IP_TTL - 1)) / \
            TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(self.input_packet_base, self.expected_packet_base)
        self.expected_packet, out_slice, out_ifg, out_pif = self.calculate_ecmp_expected_output_bgp_lu(False)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.expected_packet, out_slice, out_ifg, out_pif)

    def _test_per_prefix_vpn_getter(self):
        dest = self.vpn_encap.get_destination()
        self.assertEqual(dest.this, self.vpn_ecmp.this)
        vpn_labels = self.vpn_encap.get_nh_vpn_properties(self.pfx_obj2.hld_obj, sdk.la_ip_version_e_IPV4)
        self.assertEqual(vpn_labels[0].label, per_prefix_vpn_base.PATH2_VPN_LABEL)
        all_properties = self.vpn_encap.get_all_nh_vpn_properties()
        for property in all_properties:
            if (property.label[0].label == per_prefix_vpn_base.PATH1_VPN_LABEL and property.bgp_nh.this ==
                    self.pfx_obj1.hld_obj.this):
                found1 = True
            if (property.label[0].label == per_prefix_vpn_base.PATH2_VPN_LABEL and property.bgp_nh.this ==
                    self.pfx_obj2.hld_obj.this):
                found2 = True
        if (not found1 or not found2):
            self.assertFail()

    def _test_per_prefix_vpn_getter_bgp_lu(self):
        dest = self.vpn_encap.get_destination()
        self.assertEqual(dest.this, self.bgp_ecmp.this)
        vpn_labels = self.vpn_encap.get_nh_vpn_properties(self.dpe2.hld_obj, sdk.la_ip_version_e_IPV4)
        self.assertEqual(vpn_labels[0].label, per_prefix_vpn_base.PATH2_VPN_LABEL)
        all_properties = self.vpn_encap.get_all_nh_vpn_properties()
        found1 = False
        found2 = False
        for property in all_properties:
            if (property.label[0].label == per_prefix_vpn_base.PATH1_VPN_LABEL and property.bgp_nh.this == self.dpe1.hld_obj.this):
                found1 = True
            if (property.label[0].label == per_prefix_vpn_base.PATH2_VPN_LABEL and property.bgp_nh.this == self.dpe2.hld_obj.this):
                found2 = True
        if (not found1 or not found2):
            self.assertFail()

    def _test_per_prefix_vpn_no_label(self):
        # Create non-prefix object chain
        self.nh_ecmp_stage2 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.nh_ecmp_stage2.add_member(self.l3_port_impl.reg_nh.hld_obj)
        self.nh_ecmp_stage1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.nh_ecmp_stage1.add_member(self.nh_ecmp_stage2)

        # create the mpls vpn encap object
        self.vpn_encap = self.create_vpn_encap(per_prefix_vpn_base.MPLS_VPN_ENCAP_ID, self.nh_ecmp_stage1)

        # create the prefix
        self.create_vpn_prefix()

        self.input_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src='00:11:22:33:44:55', type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP,
               ttl=per_prefix_vpn_base.IP_TTL) / \
            TCP()

        self.expected_packet_base = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP, ttl=(per_prefix_vpn_base.IP_TTL - 1)) / \
            TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(
            self.input_packet_base, self.expected_packet_base, 68)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.RX_SLICE,
                          T.RX_IFG, T.FIRST_SERDES,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        # Swap to label chain
        self.nh_ecmp_stage1.set_members([self.pfx_obj1.hld_obj])
        self.vpn_encap.set_nh_vpn_properties(
            self.pfx_obj1.hld_obj, sdk.la_ip_version_e_IPV4, [
                per_prefix_vpn_base.PREFIX1_VPN_LABEL])
        self.vpn_encap.set_nh_vpn_properties(
            self.pfx_obj1.hld_obj, sdk.la_ip_version_e_IPV6, [
                per_prefix_vpn_base.PREFIX1_VPN_LABEL])

        # Create MPLS decap
        self.mpls_label = sdk.la_mpls_label()
        self.mpls_label.label = 0x1234

        self.lsr = self.device.get_lsr()
        self.lsr.add_vpn_decap(self.mpls_label, self.topology.vrf.hld_obj)

        self.input_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src='00:11:22:33:44:55', type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            MPLS(label=self.mpls_label.label, ttl=255) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP,
               ttl=per_prefix_vpn_base.IP_TTL) / \
            TCP()

        self.expected_packet_base = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            MPLS(label=per_prefix_vpn_base.PATH1_LDP_LABEL, ttl=255) / \
            MPLS(label=per_prefix_vpn_base.PATH1_VPN_LABEL, ttl=255) / \
            IP(src=per_prefix_vpn_base.SIP, dst=per_prefix_vpn_base.DIP, ttl=(per_prefix_vpn_base.IP_TTL - 1)) / \
            TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(self.input_packet_base, self.expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.RX_SLICE,
                          T.RX_IFG, T.FIRST_SERDES,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        # Clean up objects
        self.vpn_encap.set_destination(self.pfx_obj1.hld_obj)
        self.device.destroy(self.nh_ecmp_stage2)
        self.device.destroy(self.nh_ecmp_stage1)
