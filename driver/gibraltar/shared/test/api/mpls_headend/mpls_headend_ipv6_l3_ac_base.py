#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

from mpls_headend.mpls_headend_base import *
import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
import ip_test_base


class mpls_headend_ipv6_l3_ac_base(mpls_headend_base):
    protocol = sdk.la_l3_protocol_e_IPV6_UC
    php_protocol = sdk.la_l3_protocol_e_MPLS
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl_class = ip_test_base.ipv6_test_base
    SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL, plen=40)

    INPUT_MPLS_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL, plen=40)

    INPUT_MPLS_PACKET_BASE_POP_FWD = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=mpls_headend_base.INPUT_POP_FWD_LABEL.label, ttl=mpls_headend_base.MPLS_TTL, s=0) / \
        MPLS(label=mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL, plen=40)

    INPUT_MPLS_PACKET_DOUBLE_LABEL_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.INPUT_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL, plen=40)

    INPUT_MPLS_PACKET_WITH_VLAN_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL, plen=40)

    EXPECTED_OUTPUT_PACKET_IP_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.IPv6.value) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_IP_NULL_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6, ttl=255) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_MPLS_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_MPLS_UNIFORM_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.IP_TTL - 1) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_UPDATED_MPLS_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.NEW_LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_SR_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_SR_4_LABELS_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL3.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_SR_5_LABELS_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL4.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL3.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_SR_6_LABELS_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL5.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL4.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL3.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_SR_7_LABELS_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL6.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL5.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL4.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL3.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_SR_8_LABELS_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL7.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL6.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL5.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL4.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL3.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_0_SR_WITH_EXP_NULL_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL4.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL3.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_1_SR_WITH_EXP_NULL_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL7.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL6.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL5.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_1_SR_WITHOUT_EXP_NULL_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL7.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL6.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL5.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_TE_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.PRIMARY_TE_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_LDPoTE_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.PRIMARY_TE_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_SWAP_LDPoTE_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.PRIMARY_TE_LABEL.label, ttl=mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL - 1) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL, plen=40)

    EXPECTED_OUTPUT_PACKET_SWAP_DOUBLE_LABEL_LDPoTE_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.PRIMARY_TE_LABEL.label, ttl=mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_headend_base.INPUT_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL, plen=40)

    EXPECTED_OUTPUT_PACKET_SWAP_WITH_VLAN_LDPoTE_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.PRIMARY_TE_LABEL.label, ttl=mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL - 1) / \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL, plen=40)

    EXPECTED_OUTPUT_PACKET_LDPoTE_TE_IMPL_NULL_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_LDPoTE_VPN_LABEL_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.IP6PE_VPN_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_LDPoTE_VPN_LABEL_4_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL3.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.IP6PE_VPN_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_2_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_3_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_3_NO_EXPLICIT_NULL_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_4_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL3.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_8_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL7.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL6.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL5.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL4.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL3.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_VPN_BGP_LU_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.BGP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.VPN_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_VPN_BGP_LU_NO_LDP_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.BGP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.VPN_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_VPN_BGP_LU_NULL_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.VPN_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_6PE_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.IP6PE_LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.IP6PE_VPN_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_6PE_TE_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.PRIMARY_TE_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.IP6PE_VPN_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_headend_base.IP_TTL - 1, plen=40)

    INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    INPUT_MPLS_PACKET = U.add_payload(INPUT_MPLS_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_MPLS_PACKET_POP_FWD = U.add_payload(INPUT_MPLS_PACKET_BASE_POP_FWD, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_MPLS_PACKET_DOUBLE_LABEL = U.add_payload(INPUT_MPLS_PACKET_DOUBLE_LABEL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_MPLS_PACKET_WITH_VLAN = U.add_payload(INPUT_MPLS_PACKET_WITH_VLAN_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_IP = U.add_payload(EXPECTED_OUTPUT_PACKET_IP_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_IP_NULL = U.add_payload(EXPECTED_OUTPUT_PACKET_IP_NULL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_MPLS = U.add_payload(EXPECTED_OUTPUT_PACKET_MPLS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_MPLS_UNIFORM = U.add_payload(EXPECTED_OUTPUT_PACKET_MPLS_UNIFORM_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_UPDATED_MPLS = U.add_payload(EXPECTED_OUTPUT_PACKET_UPDATED_MPLS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SR = U.add_payload(EXPECTED_OUTPUT_PACKET_SR_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SR_4_LABELS = U.add_payload(EXPECTED_OUTPUT_PACKET_SR_4_LABELS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SR_5_LABELS = U.add_payload(EXPECTED_OUTPUT_PACKET_SR_5_LABELS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SR_6_LABELS = U.add_payload(EXPECTED_OUTPUT_PACKET_SR_6_LABELS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SR_7_LABELS = U.add_payload(EXPECTED_OUTPUT_PACKET_SR_7_LABELS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SR_8_LABELS = U.add_payload(EXPECTED_OUTPUT_PACKET_SR_8_LABELS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_0_SR_WITH_EXP_NULL = U.add_payload(
        EXPECTED_OUTPUT_PACKET_0_SR_WITH_EXP_NULL_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_1_SR_WITH_EXP_NULL = U.add_payload(
        EXPECTED_OUTPUT_PACKET_1_SR_WITH_EXP_NULL_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_1_SR_WITHOUT_EXP_NULL = U.add_payload(
        EXPECTED_OUTPUT_PACKET_1_SR_WITHOUT_EXP_NULL_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_TE = U.add_payload(EXPECTED_OUTPUT_PACKET_TE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE = U.add_payload(EXPECTED_OUTPUT_PACKET_LDPoTE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SWAP_LDPoTE = U.add_payload(EXPECTED_OUTPUT_PACKET_SWAP_LDPoTE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SWAP_DOUBLE_LABEL_LDPoTE = U.add_payload(
        EXPECTED_OUTPUT_PACKET_SWAP_DOUBLE_LABEL_LDPoTE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SWAP_WITH_VLAN_LDPoTE = U.add_payload(
        EXPECTED_OUTPUT_PACKET_SWAP_WITH_VLAN_LDPoTE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE_TE_IMPL_NULL = U.add_payload(
        EXPECTED_OUTPUT_PACKET_LDPoTE_TE_IMPL_NULL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE_VPN_LABEL = U.add_payload(
        EXPECTED_OUTPUT_PACKET_LDPoTE_VPN_LABEL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE_VPN_LABEL_4 = U.add_payload(
        EXPECTED_OUTPUT_PACKET_LDPoTE_VPN_LABEL_4_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_2 = U.add_payload(
        EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_2_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_3 = U.add_payload(
        EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_3_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_3_NO_EXPLICIT_NULL = U.add_payload(
        EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_3_NO_EXPLICIT_NULL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_4 = U.add_payload(
        EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_4_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_8 = U.add_payload(
        EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_8_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_VPN_BGP_LU_PACKET = U.add_payload(EXPECTED_OUTPUT_VPN_BGP_LU_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_VPN_BGP_LU_NO_LDP_PACKET = U.add_payload(
        EXPECTED_OUTPUT_VPN_BGP_LU_NO_LDP_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_VPN_BGP_LU_NULL_PACKET = U.add_payload(
        EXPECTED_OUTPUT_VPN_BGP_LU_NULL_PACKET_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_6PE = U.add_payload(EXPECTED_OUTPUT_PACKET_6PE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_6PE_TE = U.add_payload(EXPECTED_OUTPUT_PACKET_6PE_TE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
