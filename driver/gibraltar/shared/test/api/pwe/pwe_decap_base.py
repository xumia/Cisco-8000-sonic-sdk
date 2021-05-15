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

from packet_test_utils import *
from scapy.all import *
from scapy.contrib.ospf import *
import unittest
from leaba import sdk
import sim_utils
import ip_test_base
import topology as T
from sdk_test_case_base import *
import decor
load_contrib('mpls')

# This test assumes that MPLS bottom-of-stack label is followed by Ether
bind_layers(MPLS, Ether, s=1)


class pwe_decap_base(sdk_test_case_base):
    PREFIX1_GID = 0x691

    DA = T.mac_addr('be:ef:5d:35:8b:46')
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"

    IN_SLICE = T.get_device_slice(2)
    IN_IFG = 0
    IN_SERDES_FIRST = T.get_device_next_first_serdes(4)
    IN_SERDES_LAST = IN_SERDES_FIRST + 1
    MAC_PORT_FIRST_SERDES = T.get_device_first_serdes(6)
    MAC_PORT_LAST_SERDES = T.get_device_last_serdes(7)

    PWE_TTL = 0xff  # Set by the SDK

    LDP_LABEL = sdk.la_mpls_label()
    LDP_LABEL.label = 0x64

    PWE_LOCAL_LABEL = sdk.la_mpls_label()
    PWE_LOCAL_LABEL.label = 0x62
    PWE_REMOTE_LABEL = sdk.la_mpls_label()
    PWE_REMOTE_LABEL.label = 0x63

    PWE_LOCAL_LABEL_2 = sdk.la_mpls_label()
    PWE_LOCAL_LABEL_2.label = 0x66
    PWE_REMOTE_LABEL_2 = sdk.la_mpls_label()
    PWE_REMOTE_LABEL_2.label = 0x67

    PWE_FLOW_LABEL = sdk.la_mpls_label()
    PWE_FLOW_LABEL.label = 0xff00
    PWE_FLOW_LABEL_TTL = 0xff

    CW = sdk.la_mpls_label()
    CW.label = 0x0
    CW_TTL = 0x0

    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')

    AC_PORT_GID = 0x282
    AC_PORT_VID1 = 0xaaa

    PWE_PORT_GID = 0x4000
    PWE_GID = 0x1
    SYSPORT_GID = 99
    OUT_SP_GID = SYSPORT_GID + 1
    INJECT_SP_GID = SYSPORT_GID + 2
    INJECT_PIF_FIRST = T.get_device_next_first_serdes(8)
    INJECT_PIF_LAST = INJECT_PIF_FIRST + 1

    ip_impl_class = ip_test_base.ipv4_test_base
    l3_port_impl_class = T.ip_l3_ac_base
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP()

    INPUT_PACKET_BASE_2 = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL_2.label, ttl=PWE_TTL) / \
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

    INPUT_PACKET_V4_UNTAGGED_BASE = \
        Ether(dst=T.TX_L3_AC_REG_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        Ether(dst=DA.addr_str, src=SA.addr_str) / \
        IP()
    EXPECTED_OUTPUT_PACKET_V4_BASE = \
        Ether(dst=DA.addr_str, src=SA.addr_str) / \
        IP()

    INPUT_PACKET_V6_REWRITE_BASE = \
        Ether(dst=T.TX_L3_AC_REG_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        Ether(dst=DA.addr_str, src=SA.addr_str) / \
        IPv6()
    EXPECTED_OUTPUT_PACKET_V6_BASE = \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IPv6()

    INPUT_PACKET_SPA_BASE = \
        Ether(dst= T.TX_L3_AC_REG_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        Ether(dst=DA.addr_str, src=SA.addr_str) / \
        IPv6()
    EXPECTED_OUTPUT_PACKET_SPA_BASE = \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=0xace, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=0xbae) / \
        IPv6()

    INPUT_PACKET_SPA_POP_BASE = \
        Ether(dst= T.TX_L3_AC_REG_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        Ether(dst=DA.addr_str, src=SA.addr_str) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IPv6()
    EXPECTED_OUTPUT_PACKET_SPA_BASE_2 = \
        Ether(dst=DA.addr_str, src=SA.addr_str) / \
        IPv6()

    INPUT_PACKET_SPA_MPLS_POP_BASE = \
        Ether(dst=T.TX_L3_AC_REG_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1, type=U.Ethertype.MPLS.value) / \
        MPLS(label=0x55, ttl=33) /\
        IP()
    EXPECTED_OUTPUT_PACKET_SPA_MPLS_POP_BASE = \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=0x55, ttl=33) /\
        IP()

    INPUT_PACKET_SPA_DHCP_TRANSLATE_BASE = \
        Ether(dst=T.TX_L3_AC_REG_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP(src="0.0.0.0", dst="255.255.255.255") /\
        UDP(sport=68, dport=67) /\
        BOOTP() /\
        DHCP(options=[("message-type", "discover"), "end"])
    EXPECTED_OUTPUT_PACKET_SPA_DHCP_TRANSLATE_BASE = \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP(src="0.0.0.0", dst="255.255.255.255") /\
        UDP(sport=68, dport=67) /\
        BOOTP() /\
        DHCP(options=[("message-type", "discover"), "end"])
    EXPECTED_OUTPUT_PACKET_SPA_DHCP_TRANSLATE_BASE_2 = \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP(src="0.0.0.0", dst="255.255.255.255") /\
        UDP(sport=68, dport=67) /\
        BOOTP() /\
        DHCP(options=[("message-type", "discover"), "end"])

    INPUT_PACKET_MPLS_EGRESS_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1, type=U.Ethertype.MPLS.value) / \
        MPLS(label=0x55, ttl=33) /\
        IP()
    EXPECTED_OUTPUT_MPLS_EGRESS_BASE = \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1, type=U.Ethertype.MPLS.value) / \
        MPLS(label=0x55, ttl=33) /\
        IP()

    INPUT_PACKET_MPLS_EGRESS_BASE_2 = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=0xace, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1, type=U.Ethertype.MPLS.value) / \
        MPLS(label=0x55, ttl=33) /\
        IP()
    EXPECTED_OUTPUT_MPLS_EGRESS_BASE_2 = \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=0xace, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1, type=U.Ethertype.MPLS.value) / \
        MPLS(label=0x55, ttl=33) /\
        IP()

    INPUT_PACKET_ICMP_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP() /\
        ICMP()
    EXPECTED_OUTPUT_ICMP_EGRESS_BASE = \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP() /\
        ICMP()

    INPUT_PACKET_DHCP_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        Ether(dst="ff:ff:ff:ff:ff:ff", src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP(src="0.0.0.0", dst="255.255.255.255") /\
        UDP(sport=68, dport=67) /\
        BOOTP() /\
        DHCP(options=[("message-type", "discover"), "end"])
    EXPECTED_OUTPUT_PACKET_DHCP_BASE = \
        Ether(dst="ff:ff:ff:ff:ff:ff", src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP(src="0.0.0.0", dst="255.255.255.255") /\
        UDP(sport=68, dport=67) /\
        BOOTP() /\
        DHCP(options=[("message-type", "discover"), "end"])

    INPUT_PACKET_ARP_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        Ether(dst="ff:ff:ff:ff:ff:ff", src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        ARP()
    EXPECTED_OUTPUT_PACKET_ARP_BASE = \
        Ether(dst="ff:ff:ff:ff:ff:ff", src=SA.addr_str) / \
        ARP()

    INPUT_PACKET_STP_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        LLC() /\
        STP()
    EXPECTED_OUTPUT_PACKET_STP_BASE = \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        LLC() /\
        STP()

    INPUT_PACKET_OSPF_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
        MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
        Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=AC_PORT_VID1) / \
        IP(proto=89) /\
        OSPF_Hdr()  /\
        OSPF_Hello()
    EXPECTED_OUTPUT_PACKET_OSPF_BASE = \
        Ether(dst=DA.addr_str, src=SA.addr_str) / \
        IP(proto=89) /\
        OSPF_Hdr() /\
        OSPF_Hello()

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

    INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    INPUT_PACKET_2, BASE_INPUT_PACKET_PAYLOAD_SIZE_2 = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE_2)
    INPUT_PACKET_NULL = U.add_payload(INPUT_PACKET_NULL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_NULL_TTL_1 = U.add_payload(INPUT_PACKET_NULL_TTL_1_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_CW = U.add_payload(INPUT_PACKET_CW_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_CW_PUNT = U.add_payload(INPUT_PACKET_CW_PUNT_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_FLOW_LABEL = U.add_payload(INPUT_PACKET_FLOW_LABEL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_CW_FLOW_LABEL = U.add_payload(INPUT_PACKET_CW_FLOW_LABEL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_V4 = U.add_payload(INPUT_PACKET_V4_UNTAGGED_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_V6 = U.add_payload(INPUT_PACKET_V6_REWRITE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_MPLS_EGRESS = U.add_payload(INPUT_PACKET_MPLS_EGRESS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_MPLS_EGRESS_2 = U.add_payload(INPUT_PACKET_MPLS_EGRESS_BASE_2, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_ICMP = U.add_payload(INPUT_PACKET_ICMP_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

    EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_POP_VLAN = U.add_payload(EXPECTED_OUTPUT_PACKET_POP_VLAN_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_PUSH_VLAN = U.add_payload(EXPECTED_OUTPUT_PACKET_PUSH_VLAN_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_TRANSLATE_1_1 = U.add_payload(EXPECTED_OUTPUT_PACKET_TRANSLATE_1_1_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_V4 = U.add_payload(EXPECTED_OUTPUT_PACKET_V4_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_V6 = U.add_payload(EXPECTED_OUTPUT_PACKET_V6_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_MPLS_EGRESS = U.add_payload(EXPECTED_OUTPUT_MPLS_EGRESS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_MPLS_EGRESS_2 = U.add_payload(EXPECTED_OUTPUT_MPLS_EGRESS_BASE_2, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_ICMP = U.add_payload(EXPECTED_OUTPUT_ICMP_EGRESS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

    INPUT_PACKET_DHCP, DHCP_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_DHCP_BASE)
    EXPECTED_OUTPUT_PACKET_DHCP = U.add_payload(EXPECTED_OUTPUT_PACKET_DHCP_BASE, DHCP_PAYLOAD_SIZE)

    INPUT_PACKET_ARP = U.add_payload(INPUT_PACKET_ARP_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_ARP = U.add_payload(EXPECTED_OUTPUT_PACKET_ARP_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

    INPUT_PACKET_STP, STP_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_STP_BASE)
    EXPECTED_OUTPUT_PACKET_STP = U.add_payload(EXPECTED_OUTPUT_PACKET_STP_BASE, STP_PAYLOAD_SIZE)

    INPUT_PACKET_OSPF = U.add_payload(INPUT_PACKET_OSPF_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_OSPF = U.add_payload(EXPECTED_OUTPUT_PACKET_OSPF_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

    INPUT_PACKET_SPA, BASE_INPUT_PACKET_SPA = U.enlarge_packet_to_min_length(INPUT_PACKET_SPA_BASE)
    EXPECTED_OUTPUT_PACKET_SPA = U.add_payload(EXPECTED_OUTPUT_PACKET_SPA_BASE_2, BASE_INPUT_PACKET_SPA)
    EXPECTED_OUTPUT_PACKET_SPA_PUSH_2 = U.add_payload(EXPECTED_OUTPUT_PACKET_SPA_BASE, BASE_INPUT_PACKET_SPA)

    INPUT_PACKET_SPA_POP, BASE_INPUT_PACKET_SPA_POP = U.enlarge_packet_to_min_length(INPUT_PACKET_SPA_POP_BASE)
    EXPECTED_OUTPUT_PACKET_SPA_POP = U.add_payload(EXPECTED_OUTPUT_PACKET_SPA_BASE_2, BASE_INPUT_PACKET_SPA_POP)

    INPUT_PACKET_SPA_MPLS_POP, INPUT_PACKET_SPA_MPLS_POP_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_SPA_MPLS_POP_BASE)
    EXPECTED_OUTPUT_PACKET_SPA_MPLS_POP = U.add_payload(EXPECTED_OUTPUT_PACKET_SPA_MPLS_POP_BASE, INPUT_PACKET_SPA_MPLS_POP_SIZE)

    INPUT_PACKET_SPA_DHCP_TRANSLATE, INPUT_PACKET_SPA_DHCP_TRANSLATE_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(
        INPUT_PACKET_SPA_DHCP_TRANSLATE_BASE)
    EXPECTED_OUTPUT_PACKET_SPA_DHCP_TRANSLATE = U.add_payload(
        EXPECTED_OUTPUT_PACKET_SPA_DHCP_TRANSLATE_BASE,
        INPUT_PACKET_SPA_DHCP_TRANSLATE_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SPA_DHCP_TRANSLATE_2 = U.add_payload(
        EXPECTED_OUTPUT_PACKET_SPA_DHCP_TRANSLATE_BASE_2,
        INPUT_PACKET_SPA_DHCP_TRANSLATE_PAYLOAD_SIZE)

    def create_ecmp_to_mpls(self):
        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(self.l3_port_impl.reg_nh.hld_obj)

        self.pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, nh_ecmp)
        self.assertNotEqual(self.pfx_obj.hld_obj, None)

        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        self.pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            None,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

    def setUp(self):
        super().setUp()
        self.ac_profile = T.ac_profile(self, self.device)

        self.ip_impl = self.ip_impl_class()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)
        self.add_default_route()

        self.ac_port = T.l2_ac_port(self, self.device, self.AC_PORT_GID, self.topology.filter_group_def, None,
                                    self.topology.rx_eth_port, None, self.AC_PORT_VID1, 0x0)

        self.create_ecmp_to_mpls()
        self.pwe_port = T.l2_pwe_port(self, self.device, self.PWE_PORT_GID, self.PWE_LOCAL_LABEL,
                                      self.PWE_REMOTE_LABEL, self.PWE_GID, self.pfx_obj.hld_obj)

        self.pwe_port.hld_obj.set_ac_profile_for_pwe(self.ac_profile.hld_obj)
        self.pwe_port.hld_obj.set_destination(self.ac_port.hld_obj)

        self.ingress_counter = self.device.create_counter(sdk.la_l3_protocol_e_LAST)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.ingress_counter)

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh, self.PRIVATE_DATA_DEFAULT)

    def destroy_ports(self):
        self.pwe_port.hld_obj.detach()
        self.ac_port.destroy()
        self.pwe_port.destroy()

        self.ac_profile.destroy()

    def tearDown(self):
        self.destroy_ports()
        super().tearDown()

    def _test_pwe_decap_p2p_attach(self):
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        packet_count, byte_count = self.ingress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)

    def _test_pwe_decap_p2p_null_attach(self):
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_NULL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        packet_count, byte_count = self.ingress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)

    def _test_pwe_decap_p2p_detach(self):
        self.pwe_port.hld_obj.detach()
        U.run_and_drop(self, self.device,
                       self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_pwe_decap_p2p_cw(self):
        self.pwe_port.hld_obj.set_control_word_enabled(True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_CW, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        packet_count, byte_count = self.ingress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)

    def _test_pwe_decap_p2p_cw_punt(self):
        self.pwe_port.hld_obj.set_control_word_enabled(True)
        U.run_and_drop(self, self.device,
                       self.INPUT_PACKET_CW_PUNT, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_pwe_decap_p2p_flow_label(self):
        self.pwe_port.hld_obj.set_flow_label_enabled(True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_FLOW_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        packet_count, byte_count = self.ingress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)

    def _test_pwe_decap_p2p_cw_flow_label(self):
        self.pwe_port.hld_obj.set_flow_label_enabled(True)
        self.pwe_port.hld_obj.set_control_word_enabled(True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_CW_FLOW_LABEL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        packet_count, byte_count = self.ingress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)

    def _test_pwe_decap_p2p_ac_vlan_pop_1(self):
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 0
        eve.num_tags_to_pop = 1
        self.ac_port.hld_obj.set_egress_vlan_edit_command(eve)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_POP_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        packet_count, byte_count = self.ingress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)

    def _test_pwe_decap_p2p_ac_vlan_push_1(self):
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = 0xace
        self.ac_port.hld_obj.set_egress_vlan_edit_command(eve)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_PUSH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        packet_count, byte_count = self.ingress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)

    def _test_pwe_decap_p2p_ac_translate_1_1(self):
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 1
        eve.tag0.tpid = Ethertype.QinQ.value
        eve.tag0.tci.fields.vid = 0xace
        self.ac_port.hld_obj.set_egress_vlan_edit_command(eve)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TRANSLATE_1_1, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        packet_count, byte_count = self.ingress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)

    def _test_pwe_decap_p2p_null_drop_ttl_1(self):
        U.run_and_drop(self, self.device,
                       self.INPUT_PACKET_NULL_TTL_1, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_pwe_decap_p2p_drop_ttl_1(self):
        input_pkt = self.INPUT_PACKET.copy()
        input_pkt[MPLS].ttl = 1
        U.run_and_drop(self, self.device,
                       input_pkt, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_pwe_decap_p2p_multicast_payload(self):
        SIP = T.ipv4_addr('12.10.12.10')
        MC_GROUP_ADDR = T.ipv4_addr('225.1.2.3')

        def get_mc_sa_addr_str(ip_addr):
            octets = ip_addr.addr_str.split('.')
            assert(len(octets) == 4)
            sa_addr_str = '01:00:5e'
            sa_addr_str += ':%02x' % (0x7f & int(octets[1]))
            for o in octets[2:]:
                sa_addr_str += ':%02x' % (int(o))
            return sa_addr_str

        # 1 label no CW no VLAN
        INPUT_PACKET_MULTICAST_BASE = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.SA.addr_str, type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
            MPLS(label=self.PWE_LOCAL_LABEL.label, ttl=self.PWE_TTL) / \
            Ether(dst=get_mc_sa_addr_str(MC_GROUP_ADDR), src=self.SA.addr_str) / \
            IP(src=SIP.addr_str, dst=MC_GROUP_ADDR.addr_str) / TCP() / Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_MULTICAST_BASE = Ether(dst=get_mc_sa_addr_str(MC_GROUP_ADDR), src=self.SA.addr_str) /\
            IP(src=SIP.addr_str, dst=MC_GROUP_ADDR.addr_str) / TCP() / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET_MULTICAST, EXPECTED_OUTPUT_PACKET_MULTICAST = U.pad_input_and_output_packets(
            INPUT_PACKET_MULTICAST_BASE, EXPECTED_OUTPUT_PACKET_MULTICAST_BASE)
        U.run_and_compare(self, self.device,
                          INPUT_PACKET_MULTICAST, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          EXPECTED_OUTPUT_PACKET_MULTICAST, 5, 0, T.FIRST_SERDES)

        # no CW 2 label no inner vlan
        INPUT_PACKET_MULTICAST_BASE = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.SA.addr_str, type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
            MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV4, ttl=self.PWE_TTL) / \
            MPLS(label=self.PWE_LOCAL_LABEL.label, ttl=self.PWE_TTL) / \
            Ether(dst=get_mc_sa_addr_str(MC_GROUP_ADDR), src=self.SA.addr_str) / \
            IP(src=SIP.addr_str, dst=MC_GROUP_ADDR.addr_str) / TCP() / Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_MULTICAST_BASE = Ether(dst=get_mc_sa_addr_str(MC_GROUP_ADDR), src=self.SA.addr_str) /\
            IP(src=SIP.addr_str, dst=MC_GROUP_ADDR.addr_str) / TCP() / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET_MULTICAST, EXPECTED_OUTPUT_PACKET_MULTICAST = U.pad_input_and_output_packets(
            INPUT_PACKET_MULTICAST_BASE, EXPECTED_OUTPUT_PACKET_MULTICAST_BASE)
        U.run_and_compare(self, self.device,
                          INPUT_PACKET_MULTICAST, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          EXPECTED_OUTPUT_PACKET_MULTICAST, 5, 0, T.FIRST_SERDES)

        # 2 Label No CW  with Inner Vlan
        INPUT_PACKET_MULTICAST_BASE = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.SA.addr_str, type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
            MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV4, ttl=self.PWE_TTL) / \
            MPLS(label=self.PWE_LOCAL_LABEL.label, ttl=self.PWE_TTL) / \
            Ether(dst=get_mc_sa_addr_str(MC_GROUP_ADDR), src=self.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1) / \
            IP(src=SIP.addr_str, dst=MC_GROUP_ADDR.addr_str) / TCP() / Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_MULTICAST_BASE = Ether(dst=get_mc_sa_addr_str(MC_GROUP_ADDR),
                                                      src=self.SA.addr_str,
                                                      type=U.Ethertype.Dot1Q.value) / Dot1Q(vlan=T.RX_L3_AC_PORT_VID1) / IP(src=SIP.addr_str,
                                                                                                                            dst=MC_GROUP_ADDR.addr_str) / TCP() / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET_MULTICAST, EXPECTED_OUTPUT_PACKET_MULTICAST = U.pad_input_and_output_packets(
            INPUT_PACKET_MULTICAST_BASE, EXPECTED_OUTPUT_PACKET_MULTICAST_BASE)
        U.run_and_compare(self, self.device,
                          INPUT_PACKET_MULTICAST, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          EXPECTED_OUTPUT_PACKET_MULTICAST, 5, 0, T.FIRST_SERDES)

        self.pwe_port.hld_obj.set_control_word_enabled(True)

        # 1 label CW with no vlan
        INPUT_PACKET_MULTICAST_BASE = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.SA.addr_str, type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
            MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV4, ttl=self.PWE_TTL) / \
            MPLS(label=self.PWE_LOCAL_LABEL.label, ttl=self.PWE_TTL) / \
            PseudowireControlWord() / \
            Ether(dst=get_mc_sa_addr_str(MC_GROUP_ADDR), src=self.SA.addr_str) / \
            IP(src=SIP.addr_str, dst=MC_GROUP_ADDR.addr_str) / TCP() / Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_MULTICAST_BASE = Ether(dst=get_mc_sa_addr_str(MC_GROUP_ADDR), src=self.SA.addr_str) /\
            IP(src=SIP.addr_str, dst=MC_GROUP_ADDR.addr_str) / TCP() / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET_MULTICAST, EXPECTED_OUTPUT_PACKET_MULTICAST = U.pad_input_and_output_packets(
            INPUT_PACKET_MULTICAST_BASE, EXPECTED_OUTPUT_PACKET_MULTICAST_BASE)
        U.run_and_compare(self, self.device,
                          INPUT_PACKET_MULTICAST, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          EXPECTED_OUTPUT_PACKET_MULTICAST, 5, 0, T.FIRST_SERDES)

        # 2 Label CW with no Inner vlan
        INPUT_PACKET_MULTICAST_BASE = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.SA.addr_str, type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
            MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV4, ttl=self.PWE_TTL) / \
            MPLS(label=self.PWE_LOCAL_LABEL.label, ttl=self.PWE_TTL) / \
            PseudowireControlWord() / \
            Ether(dst=get_mc_sa_addr_str(MC_GROUP_ADDR), src=self.SA.addr_str) / \
            IP(src=SIP.addr_str, dst=MC_GROUP_ADDR.addr_str) / TCP() / Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_MULTICAST_BASE = Ether(dst=get_mc_sa_addr_str(MC_GROUP_ADDR), src=self.SA.addr_str) /\
            IP(src=SIP.addr_str, dst=MC_GROUP_ADDR.addr_str) / TCP() / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET_MULTICAST, EXPECTED_OUTPUT_PACKET_MULTICAST = U.pad_input_and_output_packets(
            INPUT_PACKET_MULTICAST_BASE, EXPECTED_OUTPUT_PACKET_MULTICAST_BASE)
        U.run_and_compare(self, self.device,
                          INPUT_PACKET_MULTICAST, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          EXPECTED_OUTPUT_PACKET_MULTICAST, 5, 0, T.FIRST_SERDES)

        # 2 label CW with inner vlan
        INPUT_PACKET_MULTICAST_BASE = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.SA.addr_str, type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
            MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV4, ttl=self.PWE_TTL) / \
            MPLS(label=self.PWE_LOCAL_LABEL.label, ttl=self.PWE_TTL) / \
            PseudowireControlWord() / \
            Ether(dst=get_mc_sa_addr_str(MC_GROUP_ADDR), src=self.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1) / \
            IP(src=SIP.addr_str, dst=MC_GROUP_ADDR.addr_str) / TCP() / Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_MULTICAST_BASE = Ether(dst=get_mc_sa_addr_str(MC_GROUP_ADDR),
                                                      src=self.SA.addr_str,
                                                      type=U.Ethertype.Dot1Q.value) / Dot1Q(vlan=T.RX_L3_AC_PORT_VID1) / IP(src=SIP.addr_str,
                                                                                                                            dst=MC_GROUP_ADDR.addr_str) / TCP() / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET_MULTICAST, EXPECTED_OUTPUT_PACKET_MULTICAST = U.pad_input_and_output_packets(
            INPUT_PACKET_MULTICAST_BASE, EXPECTED_OUTPUT_PACKET_MULTICAST_BASE)
        U.run_and_compare(self, self.device,
                          INPUT_PACKET_MULTICAST, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          EXPECTED_OUTPUT_PACKET_MULTICAST, 5, 0, T.FIRST_SERDES)

        # 2 label with CW with inner vlan and pop
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 0
        eve.num_tags_to_pop = 1
        self.ac_port.hld_obj.set_egress_vlan_edit_command(eve)

    def _test_pwe_decap_p2p_mpls(self):
        # Egress MPLS payload with no rewrite and 1 vlan header
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_MPLS_EGRESS, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_MPLS_EGRESS, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Egress MPLS payload with no rewrite and 2 vlan header
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_MPLS_EGRESS_2, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_MPLS_EGRESS_2, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_pwe_decap_p2p_icmp_translate_1(self):
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 0
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = 0xace
        self.ac_port.hld_obj.set_egress_vlan_edit_command(eve)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_ICMP, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_ICMP, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_pwe_decap_p2p_dhcp_translate_1(self):
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 1
        eve.tag0.tpid = Ethertype.QinQ.value
        eve.tag0.tci.fields.vid = 0xaaa
        self.ac_port.hld_obj.set_egress_vlan_edit_command(eve)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_DHCP, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_DHCP, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_pwe_decap_p2p_arp_pop_1(self):
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 0
        eve.num_tags_to_pop = 1
        self.ac_port.hld_obj.set_egress_vlan_edit_command(eve)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_ARP, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_ARP, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        packet_count, byte_count = self.ingress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)

    def _test_pwe_decap_p2p_stp_norewrite(self):
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_STP, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_STP, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        packet_count, byte_count = self.ingress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)

    def _test_pwe_decap_p2p_ospf(self):
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 0
        eve.num_tags_to_pop = 2
        self.ac_port.hld_obj.set_egress_vlan_edit_command(eve)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_OSPF, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_OSPF, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        packet_count, byte_count = self.ingress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)

    def _test_pwe_decap_p2p_inject(self):
        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.IN_SLICE,
            self.IN_IFG,
            self.INJECT_SP_GID,
            T.FIRST_SERDES,
            self.PUNT_INJECT_PORT_MAC_ADDR)

        dest_id = sdk.la_get_destination_id_from_gid(sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP, self.AC_PORT_GID)
        data = 'University of Texas at San Antonio,University of Texas at San Antonio,University of Texas at San Antonio,University of Texas at San Antonio'
        output_packet_base = Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.AC_PORT_VID1) / \
            IP() /\
            Raw(load=data)

        inject_packet_base = Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Inject.value) / \
            InjectDown(dest=dest_id, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            output_packet_base

        inject_packet, out_packet = U.pad_input_and_output_packets(inject_packet_base, output_packet_base)

        U.run_and_compare(self, self.device,
                          inject_packet, self.IN_SLICE, self.IN_IFG, T.FIRST_SERDES,
                          out_packet, 0, 0, T.FIRST_SERDES)

    def _test_pwe_decap_p2p_l3_ac_ingress(self):
        ETH_PORT_GID = 0x100
        L3_AC_PORT_GID   = 0x200
        VRF_GID = 0x11 if not decor.is_gibraltar() else 0xF00
        mac_port_member_1 = T.mac_port(
            self,
            self.device,
            T.RX_SLICE,
            T.RX_IFG,
            self.IN_SERDES_FIRST,
            self.IN_SERDES_LAST)
        sys_port = T.system_port(self, self.device, 100, mac_port_member_1)
        eth_port = T.sa_ethernet_port(self, self.device, sys_port)
        vrf = T.vrf(self, self.device, VRF_GID)

        l3_ac = T.l3_ac_port(
            self,
            self.device,
            L3_AC_PORT_GID,
            eth_port,
            vrf,
            T.TX_L3_AC_REG_MAC)
        l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = ip_test_base.ipv4_test_base.apply_prefix_mask(self.DIP.to_num(), 16)
        prefix.length = 16
        vrf.hld_obj.add_ipv4_route(prefix, self.topology.fec_l3_ac_reg.hld_obj,
                                   self.PRIVATE_DATA_DEFAULT, False)
        # IPv4 Payload
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_V4, T.RX_SLICE, T.RX_IFG, self.IN_SERDES_FIRST,
                          self.EXPECTED_OUTPUT_PACKET_V4, T.RX_SLICE, T.RX_IFG, 0)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 2
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = T.RX_L3_AC_PORT_VID2
        eve.tag1.tpid = Ethertype.Dot1Q.value
        eve.tag1.tci.fields.vid = self.AC_PORT_VID1
        self.ac_port.hld_obj.set_egress_vlan_edit_command(eve)

        # IPv6 Payload
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_V6, T.RX_SLICE, T.RX_IFG, self.IN_SERDES_FIRST,
                          self.EXPECTED_OUTPUT_PACKET_V6, T.RX_SLICE, T.RX_IFG, 0)

    def _test_pwe_decap_p2p_port_channel_ingress_pop_1(self):
        ETH_PORT_GID = 0x100
        L3_AC_PORT_GID   = 0x200
        VRF_GID = 0x11 if not decor.is_gibraltar() else 0xF00
        mac_port_member_1 = T.mac_port(
            self,
            self.device,
            T.RX_SLICE,
            T.RX_IFG,
            self.IN_SERDES_FIRST,
            self.IN_SERDES_LAST)
        sys_port = T.system_port(self, self.device, 100, mac_port_member_1)
        eth_port = T.sa_ethernet_port(self, self.device, sys_port)
        vrf = T.vrf(self, self.device, VRF_GID)

        l3_ac = T.l3_ac_port(
            self,
            self.device,
            L3_AC_PORT_GID,
            eth_port,
            vrf,
            T.TX_L3_AC_REG_MAC,
            T.RX_L3_AC_PORT_VID1)
        l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = ip_test_base.ipv4_test_base.apply_prefix_mask(self.DIP.to_num(), 16)
        prefix.length = 16
        vrf.hld_obj.add_ipv4_route(prefix, self.topology.fec_l3_ac_reg.hld_obj,
                                   self.PRIVATE_DATA_DEFAULT, False)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 0
        eve.num_tags_to_pop = 1
        self.ac_port.hld_obj.set_egress_vlan_edit_command(eve)
        out_slice = T.get_device_slice(5)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_SPA_MPLS_POP, T.RX_SLICE, T.RX_IFG, self.IN_SERDES_FIRST,
                          self.EXPECTED_OUTPUT_PACKET_SPA_MPLS_POP, out_slice, 0, T.FIRST_SERDES)

    def _test_pwe_decap_p2p_port_channel_ingress_translate_2(self):
        ETH_PORT_GID = 0x100
        L3_AC_PORT_GID   = 0x200
        VRF_GID = 0x11 if not decor.is_gibraltar() else 0xF00
        mac_port_member_1 = T.mac_port(
            self,
            self.device,
            T.RX_SLICE,
            T.RX_IFG,
            self.IN_SERDES_FIRST,
            self.IN_SERDES_LAST)
        sys_port = T.system_port(self, self.device, 100, mac_port_member_1)
        eth_port = T.sa_ethernet_port(self, self.device, sys_port)
        vrf = T.vrf(self, self.device, VRF_GID)

        l3_ac = T.l3_ac_port(
            self,
            self.device,
            L3_AC_PORT_GID,
            eth_port,
            vrf,
            T.TX_L3_AC_REG_MAC,
            T.RX_L3_AC_PORT_VID1,
            T.RX_L3_AC_PORT_VID2)
        l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = ip_test_base.ipv4_test_base.apply_prefix_mask(self.DIP.to_num(), 16)
        prefix.length = 16
        vrf.hld_obj.add_ipv4_route(prefix, self.topology.fec_l3_ac_reg.hld_obj,
                                   self.PRIVATE_DATA_DEFAULT, False)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 0
        eve.num_tags_to_pop = 0
        eve.tag1.tpid = Ethertype.Dot1Q.value
        eve.tag1.tci.fields.vid = 0xbae
        self.ac_port.hld_obj.set_egress_vlan_edit_command(eve)
        out_slice = T.get_device_slice(5)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_SPA_DHCP_TRANSLATE, T.RX_SLICE, T.RX_IFG, self.IN_SERDES_FIRST,
                          self.EXPECTED_OUTPUT_PACKET_SPA_DHCP_TRANSLATE_2, out_slice, 0, T.FIRST_SERDES)

    def _test_pwe_decap_p2p_port_channel_ingress(self):

        ETH_PORT_GID = 0x100
        L3_AC_PORT_GID   = 0x200
        VRF_GID = 0x11 if not decor.is_gibraltar() else 0xF00
        mac_port_member_1 = T.mac_port(
            self,
            self.device,
            T.RX_SLICE,
            T.RX_IFG,
            self.IN_SERDES_FIRST,
            self.IN_SERDES_LAST)
        sys_port = T.system_port(self, self.device, 100, mac_port_member_1)
        spa_port = T.spa_port(self, self.device, 123)
        spa_port.add(sys_port)
        eth_port = T.sa_ethernet_port(self, self.device, spa_port)
        vrf = T.vrf(self, self.device, VRF_GID)

        l3_ac = T.l3_ac_port(
            self,
            self.device,
            L3_AC_PORT_GID,
            eth_port,
            vrf,
            T.TX_L3_AC_REG_MAC)
        l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = ip_test_base.ipv4_test_base.apply_prefix_mask(self.DIP.to_num(), 16)
        prefix.length = 16
        vrf.hld_obj.add_ipv4_route(prefix, self.topology.fec_l3_ac_reg.hld_obj,
                                   self.PRIVATE_DATA_DEFAULT, False)
        # No re-write
        out_slice = T.get_device_slice(5)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_SPA, T.RX_SLICE, T.RX_IFG, self.IN_SERDES_FIRST,
                          self.EXPECTED_OUTPUT_PACKET_SPA, out_slice, 0, T.FIRST_SERDES)

        # push 2
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 2
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = 0xace
        eve.tag1.tpid = Ethertype.Dot1Q.value
        eve.tag1.tci.fields.vid = 0xbae
        self.ac_port.hld_obj.set_egress_vlan_edit_command(eve)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_SPA, T.RX_SLICE, T.RX_IFG, self.IN_SERDES_FIRST,
                          self.EXPECTED_OUTPUT_PACKET_SPA_PUSH_2, out_slice, 0, T.FIRST_SERDES)

    def _test_pwe_decap_p2p_port_channel_egress(self):
        TH_PORT_GID = 0x100
        L3_AC_PORT_GID   = 0x200
        VRF_GID = 0x11 if not decor.is_gibraltar() else 0xF00
        mac_port_member_1 = T.mac_port(
            self,
            self.device,
            T.RX_SLICE,
            T.RX_IFG,
            self.IN_SERDES_FIRST,
            self.IN_SERDES_LAST)
        sys_port = T.system_port(self, self.device, 100, mac_port_member_1)
        spa_port = T.spa_port(self, self.device, 123)
        spa_port.add(sys_port)
        eth_port = T.sa_ethernet_port(self, self.device, spa_port)
        # vrf = T.vrf(self, self.device, VRF_GID)
        ac_port = T.l2_ac_port(self, self.device, self.AC_PORT_GID + 1, self.topology.filter_group_def, None,
                               eth_port, None, self.AC_PORT_VID1, 0x0)

        pwe_port = T.l2_pwe_port(self, self.device, self.PWE_PORT_GID + 1, self.PWE_LOCAL_LABEL_2,
                                 self.PWE_REMOTE_LABEL_2, self.PWE_GID + 1, self.pfx_obj.hld_obj)

        ac_profile = T.ac_profile(self, self.device)
        pwe_port.hld_obj.set_ac_profile_for_pwe(ac_profile.hld_obj)
        pwe_port.hld_obj.set_destination(ac_port.hld_obj)
        out_slice = T.get_device_slice(5)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_2, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, out_slice, 0, self.IN_SERDES_FIRST)

    def _test_pwe_decap_p2p_multicast_ipv6_payload(self):
        SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
        MC_GROUP_ADDR = T.ipv6_addr('ff01:0:0:0:0:1:ffe8:658f')

        def get_mc_sa_addr_str(ip_addr):
            # https://tools.ietf.org/html/rfc2464#section-7
            shorts = ip_addr.addr_str.split(':')
            assert(len(shorts) == T.ipv6_addr.NUM_OF_SHORTS)
            sa_addr_str = '33:33'
            for s in shorts[-2:]:
                sl = int(s, 16) & 0xff
                sh = (int(s, 16) >> 8) & 0xff
                sa_addr_str += ':%02x:%02x' % (sh, sl)
            return sa_addr_str
        EXPECTED_OUTPUT_PACKET_DEF_BASE = Ether(dst=get_mc_sa_addr_str(MC_GROUP_ADDR),
                                                src=T.TX_L3_AC_DEF_MAC.addr_str) / IPv6(src=SIP.addr_str,
                                                                                        dst=MC_GROUP_ADDR.addr_str,
                                                                                        hlim=self.PWE_TTL - 1,
                                                                                        plen=40) / TCP() / Raw(load=RAW_PAYLOAD)
        INPUT_PACKET_MULTICAST_BASE = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.SA.addr_str, type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
            MPLS(label=self.PWE_LOCAL_LABEL.label, ttl=self.PWE_TTL) / \
            PseudowireControlWord() / \
            EXPECTED_OUTPUT_PACKET_DEF_BASE
        INPUT_PACKET, EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(
            INPUT_PACKET_MULTICAST_BASE, EXPECTED_OUTPUT_PACKET_DEF_BASE)

        self.pwe_port.hld_obj.set_control_word_enabled(True)
        out_slice = T.get_device_slice(5)
        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          EXPECTED_OUTPUT_PACKET, out_slice, 0, T.FIRST_SERDES)

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
