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

import decor
from packet_test_utils import *
from collections import namedtuple
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import ip_test_base
import topology as T
from sdk_test_case_base import *

load_contrib('mpls')

# This test assumes that MPLS bottom-of-stack label is followed by Ether
bind_layers(MPLS, Ether, s=1)


class pwe_encap_base(sdk_test_case_base):
    PREFIX1_GID = 0x691
    PREFIX2_GID = 0x692

    DA = T.mac_addr('be:ef:5d:35:8b:46')
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    DIP = T.ipv4_addr('82.81.95.250')
    VLAN = 0xAB9

    PWE_TTL = 0xff  # Set by the SDK

    SYS_PORT_GID_BASE = 50
    AC_PORT_GID_BASE = 10

    LDP_LABEL1 = sdk.la_mpls_label()
    LDP_LABEL1.label = 0x64
    LDP_LABEL2 = sdk.la_mpls_label()
    LDP_LABEL2.label = 0x65

    PWE_LOCAL_LABEL = sdk.la_mpls_label()
    PWE_LOCAL_LABEL.label = 0x62
    PWE_REMOTE_LABEL = sdk.la_mpls_label()
    PWE_REMOTE_LABEL.label = 0x63

    PWE_FLOW_LABEL = sdk.la_mpls_label()
    if (decor.is_pacific()):
        PWE_FLOW_LABEL.label = 0xce2b0
    elif (decor.is_gibraltar()):
        PWE_FLOW_LABEL.label = 0xed0
    else:
        PWE_FLOW_LABEL.label = 0x54c0
    PWE_FLOW_LABEL_TTL = 0xff

    CW = sdk.la_mpls_label()
    CW.label = 0x0
    CW_TTL = 0x0

    TE_TUNNEL1_GID = 0x391
    PRIMARY_TE_LABEL = sdk.la_mpls_label()
    PRIMARY_TE_LABEL.label = 0x66

    DPE_GID = 0x1008
    BGP_LABEL = sdk.la_mpls_label()
    BGP_LABEL.label = 0x71
    VPN_LABEL = sdk.la_mpls_label()
    VPN_LABEL.label = 0x77

    SIP = T.ipv4_addr('12.10.12.10')

    AC_PORT_GID = 0x282
    AC_PORT_VID1 = 0xaaa

    PWE_PORT_GID = 0x292
    PWE_GID = 0x82

    ip_impl_class = ip_test_base.ipv4_test_base
    l3_port_impl_class = T.ip_l3_ac_base
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210

    def create_packets(self):
        cdp_da = '01:00:0C:CC:CC:CC'
        in_packet_base = Ether(dst=cdp_da, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

    INPUT_PACKET_BASE = \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=VLAN, type=Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=PWE_TTL)

    EXPECTED_OUTPUT_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=Ethertype.MPLS.value) / \
        MPLS(label=LDP_LABEL1.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_REMOTE_LABEL.label, ttl=PWE_TTL, s=1) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=VLAN, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=PWE_TTL)

    EXPECTED_OUTPUT_PACKET_PATH2_BASE = \
        Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str, type=Ethertype.MPLS.value) / \
        MPLS(label=LDP_LABEL2.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_REMOTE_LABEL.label, ttl=PWE_TTL, s=1) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=VLAN, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=PWE_TTL)

    EXPECTED_OUTPUT_PACKET_CW_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=Ethertype.MPLS.value) / \
        MPLS(label=LDP_LABEL1.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_REMOTE_LABEL.label, ttl=PWE_TTL, s=1) / \
        PseudowireControlWord() / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=VLAN, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=PWE_TTL)

    EXPECTED_OUTPUT_PACKET_FLOW_LABEL_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=Ethertype.MPLS.value) / \
        MPLS(label=LDP_LABEL1.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_REMOTE_LABEL.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_FLOW_LABEL.label, ttl=PWE_FLOW_LABEL_TTL, s=1) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=VLAN, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=PWE_TTL)

    EXPECTED_OUTPUT_PACKET_CW_FLOW_LABEL_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=Ethertype.MPLS.value) / \
        MPLS(label=LDP_LABEL1.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_REMOTE_LABEL.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_FLOW_LABEL.label, ttl=PWE_FLOW_LABEL_TTL, s=1) / \
        PseudowireControlWord() / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=VLAN, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=PWE_TTL)

    EXPECTED_OUTPUT_PACKET_POP_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=Ethertype.MPLS.value) / \
        MPLS(label=LDP_LABEL1.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_REMOTE_LABEL.label, ttl=PWE_TTL, s=1) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=PWE_TTL)

    EXPECTED_OUTPUT_PACKET_PUSH_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=Ethertype.MPLS.value) / \
        MPLS(label=LDP_LABEL1.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_REMOTE_LABEL.label, ttl=PWE_TTL, s=1) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=0xace, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=VLAN, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=PWE_TTL)

    EXPECTED_OUTPUT_PACKET_TRANSLATE_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=Ethertype.MPLS.value) / \
        MPLS(label=LDP_LABEL1.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_REMOTE_LABEL.label, ttl=PWE_TTL, s=1) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=0xace, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=PWE_TTL)

    EXPECTED_OUTPUT_PACKET_BGP_LU_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=LDP_LABEL1.label, ttl=PWE_TTL) / \
        MPLS(label=BGP_LABEL.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_REMOTE_LABEL.label, ttl=PWE_TTL, s=1) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=VLAN, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=PWE_TTL)

    EXPECTED_OUTPUT_PACKET_TENH_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PRIMARY_TE_LABEL.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_REMOTE_LABEL.label, ttl=PWE_TTL, s=1) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=VLAN, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=PWE_TTL)

    EXPECTED_OUTPUT_PACKET_LDP_TENH_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PRIMARY_TE_LABEL.label, ttl=PWE_TTL) / \
        MPLS(label=LDP_LABEL1.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_REMOTE_LABEL.label, ttl=PWE_TTL, s=1) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=VLAN, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=PWE_TTL)

    INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

    EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_PATH2 = U.add_payload(EXPECTED_OUTPUT_PACKET_PATH2_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_CW = U.add_payload(EXPECTED_OUTPUT_PACKET_CW_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_FLOW_LABEL = U.add_payload(EXPECTED_OUTPUT_PACKET_FLOW_LABEL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_CW_FLOW_LABEL = U.add_payload(EXPECTED_OUTPUT_PACKET_CW_FLOW_LABEL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_POP = U.add_payload(EXPECTED_OUTPUT_PACKET_POP_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_PUSH = U.add_payload(EXPECTED_OUTPUT_PACKET_PUSH_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_TRANSLATE = U.add_payload(EXPECTED_OUTPUT_PACKET_TRANSLATE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_BGP_LU = U.add_payload(EXPECTED_OUTPUT_PACKET_BGP_LU_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_TENH = U.add_payload(EXPECTED_OUTPUT_PACKET_TENH_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDP_TENH = U.add_payload(EXPECTED_OUTPUT_PACKET_LDP_TENH_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

    # Static members
    phy_port = namedtuple('phy_port', 'slice ifg first_serdes last_serdes sys_port_gid ac_port_gid')
    slice_0 = T.get_device_slice(0)
    ifg_0 = T.get_device_ifg(0)
    first_serdes_0 = T.get_device_first_serdes(4)
    last_serdes_0 = T.get_device_last_serdes(5)
    slice_1 = T.get_device_slice(3)
    ifg_1 = T.get_device_ifg(1)
    first_serdes_1 = T.get_device_next_first_serdes(8)
    last_serdes_1 = T.get_device_next_last_serdes(9)
    ports = [phy_port(slice_0, ifg_0, first_serdes_0, last_serdes_0, SYS_PORT_GID_BASE, AC_PORT_GID_BASE),
             phy_port(slice_1, ifg_1, first_serdes_1, last_serdes_1, SYS_PORT_GID_BASE + 1, AC_PORT_GID_BASE + 1)]

    def create_ac_port(self, num):
        self.eth_ports.insert(
            num,
            T.ethernet_port(
                self,
                self.device,
                self.ports[num].slice,
                self.ports[num].ifg,
                self.ports[num].sys_port_gid,
                self.ports[num].first_serdes,
                self.ports[num].last_serdes))
        self.eth_ports[num].set_ac_profile(self.ac_profile)
        self.ac_ports.insert(num,
                             T.l2_ac_port(self, self.device,
                                          self.ports[num].ac_port_gid,
                                          self.topology.filter_group_def,
                                          None,
                                          self.eth_ports[num],
                                          None, self.VLAN, 0x0))

        counter_set_size = 1
        l2_ingress_counter = self.device.create_counter(counter_set_size)
        self.ac_ports[num].hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, l2_ingress_counter)

        l2_egress_counter = self.device.create_counter(counter_set_size)
        self.ac_ports[num].hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, l2_egress_counter)

    def create_ac_ports(self):
        self.eth_ports = []
        self.ac_ports = []

        for i in range(1):
            self.create_ac_port(i)

    def create_pwe_port(self, l3_destination):
        self.pwe_port = T.l2_pwe_port(self, self.device, self.PWE_PORT_GID, self.PWE_LOCAL_LABEL,
                                      self.PWE_REMOTE_LABEL, self.PWE_GID, l3_destination)

        self.pwe_port.hld_obj.set_ac_profile_for_pwe(self.ac_profile.hld_obj)
        self.ac_ports[0].hld_obj.set_destination(self.pwe_port.hld_obj)
        self.pwe_port.hld_obj.set_destination(self.ac_ports[0].hld_obj)

    def destroy_ports(self):
        self.pwe_port.hld_obj.detach()

        for ac_port in self.ac_ports:
            ac_port.hld_obj.detach()

        for ac_port in self.ac_ports:
            ac_port.destroy()

        for eth_port in self.eth_ports:
            eth_port.destroy()

        self.pwe_port.destroy()

    def create_ecmp_ldp_mpls_nh_1(self):
        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(self.l3_port_impl.reg_nh.hld_obj)

        self.pfx_obj1 = T.prefix_object(self, self.device, self.PREFIX1_GID, nh_ecmp)
        self.assertNotEqual(self.pfx_obj1.hld_obj, None)

        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL1)

        self.pfx_obj1.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            None,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

    def create_ecmp_ldp_mpls_nh_2(self):
        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(self.l3_port_impl.def_nh.hld_obj)

        self.pfx_obj2 = T.prefix_object(self, self.device, self.PREFIX2_GID, nh_ecmp)
        self.assertNotEqual(self.pfx_obj2.hld_obj, None)

        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL2)

        self.pfx_obj2.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.def_nh.hld_obj,
            lsp_labels,
            None,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

    def create_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls(self):
        # Create the ASBR
        asbr1 = T.prefix_object(self, self.device, self.PREFIX2_GID, self.l3_port_impl.reg_nh.hld_obj)
        # Program the LDP labels
        lsp_counter = None
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL1)
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
        self.dpe = T.destination_pe(self, self.device, self.DPE_GID, asbr_lsp_ecmp)

        asbr_labels = []
        asbr_labels.append(self.BGP_LABEL)

        # Program the BGP labels
        self.dpe.hld_obj.set_asbr_properties(asbr1.hld_obj, asbr_labels)

        self.bgp_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.assertNotEqual(self.bgp_ecmp, None)
        self.bgp_ecmp.add_member(self.dpe.hld_obj)

    def create_ecmp_tenh_to_mpls(self):
        self.te_tunnel = T.te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        self.te_counter = None
        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)
        self.te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, self.te_counter)
        self.te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        self.te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(self.te_ecmp, None)
        self.te_ecmp.add_member(self.te_tunnel.hld_obj)

    def create_ecmp_ldp_tenh_to_mpls(self):
        self.te_tunnel = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        self.te_counter = None
        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)
        self.te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, self.te_counter)
        self.te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        self.te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(self.te_ecmp, None)
        self.te_ecmp.add_member(self.te_tunnel.hld_obj)

        self.pfx_obj1 = T.prefix_object(self, self.device, self.PREFIX1_GID, self.te_ecmp)

        lsp_counter = None
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL1)

        self.pfx_obj1.hld_obj.set_te_tunnel_lsp_properties(self.te_tunnel.hld_obj, lsp_labels, lsp_counter)

    def setUp(self):
        super().setUp()
        self.ac_profile = T.ac_profile(self, self.device)

        self.ip_impl = self.ip_impl_class()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)
        self.create_ac_ports()
        self.add_default_route()

        self.egress_counter = self.device.create_counter(sdk.la_l3_protocol_e_LAST)
        self.topology.tx_l3_ac_reg.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.egress_counter)

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh, self.PRIVATE_DATA_DEFAULT)

    def tearDown(self):
        self.destroy_ports()
        self.ac_profile.destroy()
        super().tearDown()

    def traffic_run_and_compare(self, input_packet, output_packet):
        U.run_and_compare(self, self.device,
                          input_packet, self.ports[0].slice, self.ports[0].ifg, self.ports[0].first_serdes,
                          output_packet, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)

    def _test_pwe_encap_p2p_attach(self):
        self.create_ecmp_ldp_mpls_nh_1()
        self.create_pwe_port(self.pfx_obj1.hld_obj)
        self.traffic_run_and_compare(self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET)

    def _test_pwe_encap_p2p_change_l3_dest(self):
        self.create_ecmp_ldp_mpls_nh_1()
        self.create_ecmp_ldp_mpls_nh_2()
        self.create_pwe_port(self.pfx_obj1.hld_obj)
        self.traffic_run_and_compare(self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET)

        self.pwe_port.hld_obj.set_l3_destination(self.pfx_obj2.hld_obj)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, self.ports[0].slice, self.ports[0].ifg, self.ports[0].first_serdes,
                          self.EXPECTED_OUTPUT_PACKET_PATH2, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

    def _test_pwe_encap_p2p_detach(self):
        self.create_ecmp_ldp_mpls_nh_1()
        self.create_pwe_port(self.pfx_obj1.hld_obj)
        self.traffic_run_and_compare(self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET)

        self.ac_ports[0].hld_obj.detach()
        U.run_and_drop(self, self.device,
                       self.INPUT_PACKET, self.ports[0].slice, self.ports[0].ifg, self.ports[0].first_serdes)

    def _test_pwe_encap_p2p_cw(self):
        self.create_ecmp_ldp_mpls_nh_1()
        self.create_pwe_port(self.pfx_obj1.hld_obj)
        self.pwe_port.hld_obj.set_control_word_enabled(True)
        self.traffic_run_and_compare(self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET_CW)

    def _test_pwe_encap_p2p_flow_label(self):
        self.create_ecmp_ldp_mpls_nh_1()
        self.create_pwe_port(self.pfx_obj1.hld_obj)
        self.pwe_port.hld_obj.set_flow_label_enabled(True)
        self.traffic_run_and_compare(self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET_FLOW_LABEL)

    def _test_pwe_encap_p2p_cw_flow_label(self):
        self.create_ecmp_ldp_mpls_nh_1()
        self.create_pwe_port(self.pfx_obj1.hld_obj)
        self.pwe_port.hld_obj.set_flow_label_enabled(True)
        self.pwe_port.hld_obj.set_control_word_enabled(True)
        self.traffic_run_and_compare(self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET_CW_FLOW_LABEL)

    def _test_pwe_encap_p2p_bgp_lu(self):
        self.create_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls()
        self.create_pwe_port(self.dpe.hld_obj)
        self.traffic_run_and_compare(self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET_BGP_LU)

    def _test_pwe_encap_p2p_bgp_ecmp(self):
        self.create_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls()
        self.create_pwe_port(self.bgp_ecmp)
        self.traffic_run_and_compare(self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET_BGP_LU)

    def _test_pwe_encap_p2p_tenh(self):
        self.create_ecmp_tenh_to_mpls()
        self.create_pwe_port(self.te_ecmp)
        self.traffic_run_and_compare(self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET_TENH)

    def _test_pwe_encap_p2p_ldp_tenh(self):
        self.create_ecmp_ldp_tenh_to_mpls()
        self.create_pwe_port(self.pfx_obj1.hld_obj)
        self.traffic_run_and_compare(self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET_LDP_TENH)

    def _test_pwe_encap_p2p_ac_vlan_pop_1(self):
        self.create_ecmp_ldp_mpls_nh_1()
        self.create_pwe_port(self.pfx_obj1.hld_obj)
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 0
        eve.num_tags_to_pop = 1
        self.ac_ports[0].hld_obj.set_ingress_vlan_edit_command(eve)

        self.traffic_run_and_compare(self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET_POP)

    def _test_pwe_encap_p2p_ac_vlan_push_1(self):
        self.create_ecmp_ldp_mpls_nh_1()
        self.create_pwe_port(self.pfx_obj1.hld_obj)
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = 0xace
        self.ac_ports[0].hld_obj.set_ingress_vlan_edit_command(eve)

        self.traffic_run_and_compare(self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET_PUSH)

    def _test_pwe_encap_p2p_ac_translate_1_1(self):
        self.create_ecmp_ldp_mpls_nh_1()
        self.create_pwe_port(self.pfx_obj1.hld_obj)
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 1
        eve.tag0.tpid = Ethertype.QinQ.value
        eve.tag0.tci.fields.vid = 0xace
        self.ac_ports[0].hld_obj.set_ingress_vlan_edit_command(eve)

        self.traffic_run_and_compare(self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET_TRANSLATE)
