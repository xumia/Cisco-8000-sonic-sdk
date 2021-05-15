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


class pwe_decap_base(sdk_test_case_base):
    PREFIX1_GID = 0x691
    PREFIX2_GID = 0x692

    DA = T.mac_addr('be:ef:5d:35:8b:46')
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    DIP = T.ipv4_addr('82.81.95.250')
    VLAN = 0xAB9

    PWE_TTL = 0xff  # Set by the SDK

    LDP_LABEL = sdk.la_mpls_label()
    LDP_LABEL.label = 0x64
    LDP_LABEL2 = sdk.la_mpls_label()
    LDP_LABEL2.label = 0x67

    PWE_LOCAL_LABEL = sdk.la_mpls_label()
    PWE_LOCAL_LABEL.label = 0x62
    PWE_REMOTE_LABEL = sdk.la_mpls_label()
    PWE_REMOTE_LABEL.label = 0x63

    PWE_LOCAL_LABEL2 = sdk.la_mpls_label()
    PWE_LOCAL_LABEL2.label = 0x65
    PWE_REMOTE_LABEL2 = sdk.la_mpls_label()
    PWE_REMOTE_LABEL2.label = 0x66

    PWE_FLOW_LABEL = sdk.la_mpls_label()
    PWE_FLOW_LABEL.label = 0xff00
    PWE_FLOW_LABEL_TTL = 0xff

    PWE_FLOW_LABEL2 = sdk.la_mpls_label()
    if (decor.is_pacific()):
        PWE_FLOW_LABEL2.label = 0x2CBB0
    else:
        PWE_FLOW_LABEL2.label = 0x2AF70

    CW = sdk.la_mpls_label()
    CW.label = 0x0
    CW_TTL = 0x0

    SIP = T.ipv4_addr('12.10.12.10')

    AC_PORT_GID = 0x282
    AC_PORT_VID1 = 0xaaa

    PWE_PORT_GID = 0x4000
    PWE_GID = 0x1

    PWE_PORT_GID2 = 0x4001
    PWE_GID2 = 0x2

    DPE_GID = 0x1008
    BGP_LABEL = sdk.la_mpls_label()
    BGP_LABEL.label = 0x71
    VPN_LABEL = sdk.la_mpls_label()
    VPN_LABEL.label = 0x77

    ip_impl_class = ip_test_base.ipv4_test_base
    l3_port_impl_class = T.ip_l3_ac_base
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    SWITCH_BASE_GID = 0x10

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP()

    INPUT_PACKET_NULL_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV4, ttl=PWE_TTL) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP()

    INPUT_PACKET_NULL_TTL_1_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV4, ttl=PWE_TTL) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=1) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP()

    INPUT_PACKET_FLOW_LABEL_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_FLOW_LABEL.label, ttl=PWE_FLOW_LABEL_TTL) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP()

    INPUT_PACKET_CW_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        PseudowireControlWord() / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP()

    INPUT_PACKET_CW_PUNT_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        PseudowireControlWord(channel=0x1) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP()

    INPUT_PACKET_CW_FLOW_LABEL_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_FLOW_LABEL.label, ttl=PWE_FLOW_LABEL_TTL) / \
        PseudowireControlWord() / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP()

    EXPECTED_OUTPUT_PACKET_BASE = \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP()

    EXPECTED_OUTPUT_PACKET_POP_VLAN_BASE = \
        Ether(dst=DA.addr_str, src=SA.addr_str) / \
        IP()

    EXPECTED_OUTPUT_PACKET_PUSH_VLAN_BASE = \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=0xace, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP()

    EXPECTED_OUTPUT_PACKET_TRANSLATE_1_1_BASE = \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=0xace) / \
        IP()

    # PWE to PWE packets
    INPUT_PACKET_BASE2 = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=PWE_TTL)

    INPUT_PACKET_FLOW_LABEL_BASE2 = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_FLOW_LABEL.label, ttl=PWE_FLOW_LABEL_TTL) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=PWE_TTL)

    INPUT_PACKET_CW_BASE2 = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        PseudowireControlWord() / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=PWE_TTL)

    INPUT_PACKET_CW_FLOW_LABEL_BASE_2 = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_FLOW_LABEL.label, ttl=PWE_FLOW_LABEL_TTL) / \
        PseudowireControlWord() / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=PWE_TTL)

    EXPECTED_OUTPUT_PACKET_BASE2 = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=Ethertype.MPLS.value) / \
        MPLS(label=LDP_LABEL2.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_REMOTE_LABEL2.label, ttl=PWE_TTL, s=1) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=PWE_TTL)

    EXPECTED_OUTPUT_PACKET_FLOW_LABEL_BASE2 = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=Ethertype.MPLS.value) / \
        MPLS(label=LDP_LABEL2.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_REMOTE_LABEL2.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_FLOW_LABEL2.label, ttl=PWE_FLOW_LABEL_TTL, s=1) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=PWE_TTL)

    EXPECTED_OUTPUT_PACKET_CW_BASE2 = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=Ethertype.MPLS.value) / \
        MPLS(label=LDP_LABEL2.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_REMOTE_LABEL2.label, ttl=PWE_TTL, s=1) / \
        PseudowireControlWord() / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=PWE_TTL)

    EXPECTED_OUTPUT_PACKET_CW_FLOW_LABEL_BASE2 = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=Ethertype.MPLS.value) / \
        MPLS(label=LDP_LABEL2.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_REMOTE_LABEL2.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_FLOW_LABEL2.label, ttl=PWE_FLOW_LABEL_TTL, s=1) / \
        PseudowireControlWord() / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=PWE_TTL)

    EXPECTED_OUTPUT_PACKET_BGP_LU_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=LDP_LABEL2.label, ttl=PWE_TTL) / \
        MPLS(label=BGP_LABEL.label, ttl=PWE_TTL) / \
        MPLS(label=PWE_REMOTE_LABEL2.label, ttl=PWE_TTL, s=1) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=PWE_TTL)

    INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    INPUT_PACKET_NULL = U.add_payload(INPUT_PACKET_NULL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_NULL_TTL_1 = U.add_payload(INPUT_PACKET_NULL_TTL_1_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_CW = U.add_payload(INPUT_PACKET_CW_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_CW_PUNT = U.add_payload(INPUT_PACKET_CW_PUNT_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_FLOW_LABEL = U.add_payload(INPUT_PACKET_FLOW_LABEL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_CW_FLOW_LABEL = U.add_payload(INPUT_PACKET_CW_FLOW_LABEL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

    EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_POP_VLAN = U.add_payload(EXPECTED_OUTPUT_PACKET_POP_VLAN_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_PUSH_VLAN = U.add_payload(EXPECTED_OUTPUT_PACKET_PUSH_VLAN_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_TRANSLATE_1_1 = U.add_payload(EXPECTED_OUTPUT_PACKET_TRANSLATE_1_1_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

    INPUT_PACKET2 = U.add_payload(INPUT_PACKET_BASE2, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_FLOW_LABEL2 = U.add_payload(INPUT_PACKET_FLOW_LABEL_BASE2, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_CW2 = U.add_payload(INPUT_PACKET_CW_BASE2, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_CW_FLOW_LABEL2 = U.add_payload(INPUT_PACKET_CW_FLOW_LABEL_BASE_2, BASE_INPUT_PACKET_PAYLOAD_SIZE)

    EXPECTED_OUTPUT_PACKET2 = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE2, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_FLOW_LABEL2 = U.add_payload(EXPECTED_OUTPUT_PACKET_FLOW_LABEL_BASE2, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_CW2 = U.add_payload(EXPECTED_OUTPUT_PACKET_CW_BASE2, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_CW_FLOW_LABEL2 = U.add_payload(
        EXPECTED_OUTPUT_PACKET_CW_FLOW_LABEL_BASE2,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_BGP_LU = U.add_payload(EXPECTED_OUTPUT_PACKET_BGP_LU_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

    def create_ldp_mpls_nh(self):
        self.pfx_obj_vpls = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.def_nh.hld_obj)
        self.assertNotEqual(self.pfx_obj_vpls.hld_obj, None)

        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        self.pfx_obj_vpls.hld_obj.set_nh_lsp_properties(self.l3_port_impl.def_nh.hld_obj,
                                                        lsp_labels,
                                                        None,
                                                        sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

    def create_ldp_mpls_nh_2(self):
        self.pfx_obj_vpls_2 = T.prefix_object(self, self.device, self.PREFIX2_GID, self.l3_port_impl.reg_nh.hld_obj)
        self.assertNotEqual(self.pfx_obj_vpls.hld_obj, None)

        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL2)

        self.pfx_obj_vpls_2.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj,
                                                          lsp_labels,
                                                          None,
                                                          sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

    def create_bgp_lu_ip_dpe_ecmp_asbr_lsp_to_mpls(self):
        # Create the ASBR
        asbr1 = T.prefix_object(self, self.device, self.PREFIX2_GID, self.l3_port_impl.reg_nh.hld_obj)
        # Program the LDP labels
        lsp_counter = None
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL2)
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

    def create_second_pw(self, l3_destination):
        self.pwe_port2 = T.l2_pwe_port(self, self.device, self.PWE_PORT_GID2, self.PWE_LOCAL_LABEL2,
                                       self.PWE_REMOTE_LABEL2, self.PWE_GID2, l3_destination)
        self.pwe_port2.hld_obj.attach_to_switch(self.sw1.hld_obj)
        self.pwe_port2.hld_obj.set_ac_profile_for_pwe(self.ac_profile.hld_obj)
        self.sw1.hld_obj.remove_mac_entry(self.DA.hld_obj)
        self.sw1.hld_obj.set_mac_entry(self.DA.hld_obj, self.pwe_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

    def setUp(self):
        super().setUp()
        self.ac_profile = T.ac_profile(self, self.device)

        self.ip_impl = self.ip_impl_class()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)
        self.add_default_route()

        self.ac_port = T.l2_ac_port(self, self.device, self.AC_PORT_GID, self.topology.filter_group_def, None,
                                    self.topology.rx_eth_port, None, self.AC_PORT_VID1, 0x0)

        self.create_ldp_mpls_nh()

        self.pwe_port = T.l2_pwe_port(self, self.device, self.PWE_PORT_GID, self.PWE_LOCAL_LABEL,
                                      self.PWE_REMOTE_LABEL, self.PWE_GID, self.pfx_obj_vpls.hld_obj)
        self.pwe_port2 = None

        self.pwe_port.hld_obj.set_ac_profile_for_pwe(self.ac_profile.hld_obj)

        self.sw1 = T.switch(self, self.device, self.SWITCH_BASE_GID + 1)
        status = self.ac_port.hld_obj.attach_to_switch(self.sw1.hld_obj)
        status = self.pwe_port.hld_obj.attach_to_switch(self.sw1.hld_obj)

        status = self.sw1.hld_obj.set_mac_entry(self.DA.hld_obj, self.ac_port.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        # Create filter groups
        self.grp1 = T.filter_group(self, self.device)
        self.grp2 = T.filter_group(self, self.device)
        self.grp3 = T.filter_group(self, self.device)
        # create counters
        self.ingress_counter = T.counter(self, self.device, 1)
        self.egress_counter = T.counter(self, self.device, 1)

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh, self.PRIVATE_DATA_DEFAULT)

    def destroy_ports(self):
        self.pwe_port.hld_obj.detach()
        self.ac_port.hld_obj.detach()

        self.ac_port.destroy()
        self.pwe_port.destroy()

        if self.pwe_port2 is not None:
            self.pwe_port2.hld_obj.detach()
            self.pwe_port2.destroy()

        self.ac_profile.destroy()

    def destroy_filter_grps(self):
        self.grp1.destroy()
        self.grp2.destroy()

    def tearDown(self):
        self.destroy_ports()
        self.sw1.destroy()
        self.destroy_filter_grps()
        self.ingress_counter.destroy()
        self.egress_counter.destroy()
        super().tearDown()

    def _test_pwe_decap_attach(self):
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_pwe_decap_null_attach(self):
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_NULL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_pwe_decap_detach(self):
        self.pwe_port.hld_obj.detach()
        U.run_and_drop(self, self.device,
                       self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_pwe_decap_cw(self):
        self.pwe_port.hld_obj.set_control_word_enabled(True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_CW, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_pwe_decap_cw_punt(self):
        self.pwe_port.hld_obj.set_control_word_enabled(True)
        U.run_and_drop(self, self.device,
                       self.INPUT_PACKET_CW_PUNT, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_pwe_decap_flow_label(self):
        self.pwe_port.hld_obj.set_flow_label_enabled(True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_FLOW_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_pwe_decap_cw_flow_label(self):
        self.pwe_port.hld_obj.set_flow_label_enabled(True)
        self.pwe_port.hld_obj.set_control_word_enabled(True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_CW_FLOW_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_pwe_decap_ac_vlan_pop_1(self):
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 0
        eve.num_tags_to_pop = 1
        self.ac_port.hld_obj.set_egress_vlan_edit_command(eve)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_POP_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_pwe_decap_ac_vlan_push_1(self):
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = 0xace
        self.ac_port.hld_obj.set_egress_vlan_edit_command(eve)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_PUSH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_pwe_decap_ac_translate_1_1(self):
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 1
        eve.tag0.tpid = Ethertype.QinQ.value
        eve.tag0.tci.fields.vid = 0xace
        self.ac_port.hld_obj.set_egress_vlan_edit_command(eve)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TRANSLATE_1_1, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_pwe_decap_null_drop_ttl_1(self):
        U.run_and_drop(self, self.device,
                       self.INPUT_PACKET_NULL_TTL_1, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_pwe_decap_drop_ttl_1(self):
        input_pkt = self.INPUT_PACKET.copy()
        input_pkt[MPLS].ttl = 1
        U.run_and_drop(self, self.device,
                       input_pkt, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_pwe_scale(self):
        pwe_scale = 512
        l_label = 0x63
        r_label = 0x64
        input_packet = self.INPUT_PACKET.copy()

        for loop in range(2):
            pwe_ports = []
            for i in range(pwe_scale):
                local_label = sdk.la_mpls_label()
                remote_label = sdk.la_mpls_label()
                local_label.label = l_label + i + 1
                remote_label.label = r_label + i + 1

                pwe_ports.append(T.l2_pwe_port(self, self.device, self.PWE_PORT_GID + i + 1, local_label,
                                               remote_label, self.PWE_GID + i + 1, self.pfx_obj.hld_obj))

                pwe_ports[i].hld_obj.set_ac_profile_for_pwe(self.ac_profile.hld_obj)

                pwe_ports[i].hld_obj.set_destination(self.ac_port.hld_obj)
                if (i % 100 == 0):
                    input_packet[MPLS].label = l_label + i + 1
                    U.run_and_compare(self, self.device,
                                      input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                      self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
                pwe_ports[i].hld_obj.detach()

            for i in range(pwe_scale):
                pwe_ports[i].destroy()

    def _test_pwe_2_pwe_attach(self):
        self.create_ldp_mpls_nh_2()
        self.create_second_pw(self.pfx_obj_vpls_2.hld_obj)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET2, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET2, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        # test SHG between PWE to PWE
        self.grp1.hld_obj.set_filtering_mode(self.grp1.hld_obj, True)
        self.pwe_port2.hld_obj.set_filter_group(self.grp1.hld_obj)
        self.pwe_port.hld_obj.set_filter_group(self.grp1.hld_obj)

        U.run_and_drop(self, self.device,
                       self.INPUT_PACKET2, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_pwe_2_pwe_cw(self):
        self.create_ldp_mpls_nh_2()
        self.create_second_pw(self.pfx_obj_vpls_2.hld_obj)
        self.pwe_port2.hld_obj.set_control_word_enabled(True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET2, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_CW2, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def _test_pwe_2_pwe_flow_label(self):
        self.create_ldp_mpls_nh_2()
        self.create_second_pw(self.pfx_obj_vpls_2.hld_obj)
        self.pwe_port2.hld_obj.set_flow_label_enabled(True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET2, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_FLOW_LABEL2, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def _test_pwe_2_pwe_cw_flow_label(self):
        self.create_ldp_mpls_nh_2()
        self.create_second_pw(self.pfx_obj_vpls_2.hld_obj)
        self.pwe_port2.hld_obj.set_control_word_enabled(True)
        self.pwe_port2.hld_obj.set_flow_label_enabled(True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET2, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_CW_FLOW_LABEL2, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def _test_pwe_cw_2_pwe(self):
        self.create_ldp_mpls_nh_2()
        self.create_second_pw(self.pfx_obj_vpls_2.hld_obj)
        self.pwe_port.hld_obj.set_control_word_enabled(True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_CW2, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET2, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def _test_pwe_flow_lable_2_pwe(self):
        self.create_ldp_mpls_nh_2()
        self.create_second_pw(self.pfx_obj_vpls_2.hld_obj)
        self.pwe_port.hld_obj.set_flow_label_enabled(True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_FLOW_LABEL2, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET2, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def _test_pwe_cw_flow_label_2_pwe(self):
        self.create_ldp_mpls_nh_2()
        self.create_second_pw(self.pfx_obj_vpls_2.hld_obj)
        self.pwe_port.hld_obj.set_control_word_enabled(True)
        self.pwe_port.hld_obj.set_flow_label_enabled(True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_CW_FLOW_LABEL2, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET2, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def _test_pwe_2_pwe_bgp_lu(self):
        self.create_bgp_lu_ip_dpe_ecmp_asbr_lsp_to_mpls()
        self.create_second_pw(self.dpe.hld_obj)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET2, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_BGP_LU, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def _test_pwe_2_pwe_shg(self):
        self.create_ldp_mpls_nh_2()
        self.create_second_pw(self.pfx_obj_vpls_2.hld_obj)
        # Deny traffic
        self.grp1.hld_obj.set_filtering_mode(self.grp1.hld_obj, True)
        self.pwe_port2.hld_obj.set_filter_group(self.grp1.hld_obj)
        self.pwe_port.hld_obj.set_filter_group(self.grp1.hld_obj)

        U.run_and_drop(self, self.device,
                       self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Permit traffic
        self.grp1.hld_obj.set_filtering_mode(self.grp1.hld_obj, False)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET2, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET2, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def _test_pwe_decap_shg(self):
        # Deny traffic within grp12 to grp3
        self.grp2.hld_obj.set_filtering_mode(self.grp2.hld_obj, True)
        self.grp3.hld_obj.set_filtering_mode(self.grp3.hld_obj, True)

        self.grp1.hld_obj.set_filtering_mode(self.grp1.hld_obj, False)
        self.grp1.hld_obj.set_filtering_mode(self.grp2.hld_obj, False)
        self.grp1.hld_obj.set_filtering_mode(self.grp3.hld_obj, False)

        self.grp2.hld_obj.set_filtering_mode(self.grp1.hld_obj, False)
        self.grp2.hld_obj.set_filtering_mode(self.grp3.hld_obj, False)

        self.grp3.hld_obj.set_filtering_mode(self.grp1.hld_obj, False)
        self.grp3.hld_obj.set_filtering_mode(self.grp2.hld_obj, False)

        self.ac_port.hld_obj.set_filter_group(self.grp3.hld_obj)
        self.pwe_port.hld_obj.set_filter_group(self.grp3.hld_obj)
        self.pwe_port.hld_obj.set_stp_state(sdk.la_port_stp_state_e_FORWARDING)
        self.ac_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.egress_counter.hld_obj)

        U.run_and_drop(self, self.device,
                       self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # No counter should increment on outgoing on AC for SHG trap drops
        packet_count, byte_count = self.egress_counter.hld_obj.read(0,  # sub-counter index
                                                                    True,  # force_update
                                                                    True)  # clear_on_read
        self.assertEqual(packet_count, 0)

        # Permit traffic from grp2 to grp1
        self.ac_port.hld_obj.set_filter_group(self.grp1.hld_obj)
        self.pwe_port.hld_obj.set_filter_group(self.grp2.hld_obj)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Deny traffic within same group - both PWE and AC in grp2
        # PWE is already part of grp2, just add AC
        self.ac_port.hld_obj.set_filter_group(self.grp2.hld_obj)

        U.run_and_drop(self, self.device,
                       self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def do_test_counter_pwe_2_ac(self, single_counter, prios):
        # Set ingress and Egress counters
        self.pwe_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.ingress_counter.hld_obj)
        self.ac_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.egress_counter.hld_obj)

        # Run the packet
        for prio in prios:
            in_packet, out_packet = self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET
            U.run_and_compare(self, self.device,
                              self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                              self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Check ingress counter
        if single_counter:
            packet_count, byte_count = self.ingress_counter.hld_obj.read(0,  # sub-counter index
                                                                         True,  # force_update
                                                                         True)  # clear_on_read
            self.assertEqual(packet_count, len(prios))
            assertPacketLengthIngress(self, in_packet, T.RX_SLICE, byte_count, num_packets=len(prios))
        else:
            for prio in prios:
                packet_count, byte_count = self.ingress_counter.hld_obj.read(prio,  # sub-counter index
                                                                             True,  # force_update
                                                                             True)  # clear_on_read
                self.assertEqual(packet_count, 1)
                assertPacketLengthIngress(self, in_packet, T.RX_SLICE, byte_count)

        # Check egress counter
        if single_counter:
            packet_count, byte_count = self.egress_counter.hld_obj.read(0,  # sub-counter index
                                                                        True,  # force_update
                                                                        True)  # clear_on_read
            self.assertEqual(packet_count, len(prios))
            assertPacketLengthEgress(self, out_packet, byte_count, num_packets=len(prios))
        else:
            for prio in prios:
                packet_count, byte_count = self.egress_counter.hld_obj.read(prio,  # sub-counter index
                                                                            True,  # force_update
                                                                            True)  # clear_on_read
                self.assertEqual(packet_count, 1)
                assertPacketLengthEgress(self, out_packet, byte_count)
