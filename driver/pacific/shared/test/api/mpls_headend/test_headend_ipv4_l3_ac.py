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

from mpls_headend_base import *
import sim_utils
import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
import ip_test_base
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv4_l3_ac(mpls_headend_base):
    protocol = sdk.la_l3_protocol_e_IPV4_UC
    php_protocol = sdk.la_l3_protocol_e_IPV4_UC
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl_class = ip_test_base.ipv4_test_base
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL)

    INPUT_PACKET_GLOBAL_VRF_BASE = \
        Ether(dst=T.TX_L3_AC_EXT_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL)

    INPUT_MPLS_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL)

    INPUT_MPLS_PACKET_BASE_POP_FWD = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=mpls_headend_base.INPUT_POP_FWD_LABEL.label, ttl=mpls_headend_base.MPLS_TTL, s=0) / \
        MPLS(label=mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL)

    INPUT_MPLS_PACKET_DOUBLE_LABEL_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.INPUT_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL)

    INPUT_MPLS_PACKET_WITH_VLAN_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_PACKET_IP_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_IP_NULL_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_IP_UPDATED_DESTINATION_BASE = \
        Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_MPLS_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_MPLS_UNIFORM_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.IP_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_UPDATED_MPLS_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.NEW_LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_SR_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_SR_4_LABELS_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL3.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_SR_5_LABELS_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL4.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL3.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_SR_6_LABELS_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL5.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL4.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL3.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_SR_7_LABELS_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL6.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL5.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL4.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL3.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

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
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_TE_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.PRIMARY_TE_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_TE_BACKUP_BASE = \
        Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.BACKUP_TE_LABEL.label, ttl=mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_headend_base.MP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_PACKET_IP_LDPoTE_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.PRIMARY_TE_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_LDPoTE_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.PRIMARY_TE_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_LDPoTE_WITH_VLAN_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=mpls_headend_base.OUTPUT_VID, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.PRIMARY_TE_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_LDPoTE_LDP_IMPLICIT_NULL_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.PRIMARY_TE_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_LDPoTE_TE_IMPLICIT_NULL_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_LDPoTE_LDP_AND_TE_IMPLICIT_NULL_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_SWAP_LDPoTE_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.PRIMARY_TE_LABEL.label, ttl=mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_PACKET_SWAP_DOUBLE_LABEL_LDPoTE_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.PRIMARY_TE_LABEL.label, ttl=mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_headend_base.INPUT_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_PACKET_SWAP_WITH_VLAN_LDPoTE_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.PRIMARY_TE_LABEL.label, ttl=mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL - 1) / \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_PACKET_LDPoTE_TE_IMPL_NULL_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_2_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_3_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_TE_VPN_LABEL_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.VPN_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_TE_VPN_LABEL_4_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL3.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.VPN_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_LDPoTE_VPN_LABEL_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.VPN_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_LDPoTE_VPN_LABEL_4_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL3.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.VPN_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_4_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL3.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

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
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_VPN_BGP_LU_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.BGP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.VPN_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_VPN_BGP_LU_NO_LDP_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.BGP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.VPN_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_VPN_BGP_LU_NULL_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.VPN_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_6PE_WITH_GLOBAL_VRF_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    INPUT_PACKET_GLOBAL_VRF = U.add_payload(INPUT_PACKET_GLOBAL_VRF_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_MPLS_PACKET = U.add_payload(INPUT_MPLS_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_MPLS_PACKET_POP_FWD = U.add_payload(INPUT_MPLS_PACKET_BASE_POP_FWD, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_MPLS_PACKET_DOUBLE_LABEL = U.add_payload(INPUT_MPLS_PACKET_DOUBLE_LABEL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_MPLS_PACKET_WITH_VLAN = U.add_payload(INPUT_MPLS_PACKET_WITH_VLAN_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_IP = U.add_payload(EXPECTED_OUTPUT_PACKET_IP_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_IP_NULL = U.add_payload(EXPECTED_OUTPUT_PACKET_IP_NULL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_IP_UPDATED_DESTINATION = U.add_payload(
        EXPECTED_OUTPUT_PACKET_IP_UPDATED_DESTINATION_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_MPLS = U.add_payload(EXPECTED_OUTPUT_PACKET_MPLS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_MPLS_UNIFORM = U.add_payload(EXPECTED_OUTPUT_PACKET_MPLS_UNIFORM_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_UPDATED_MPLS = U.add_payload(EXPECTED_OUTPUT_PACKET_UPDATED_MPLS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SR = U.add_payload(EXPECTED_OUTPUT_PACKET_SR_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SR_4_LABELS = U.add_payload(EXPECTED_OUTPUT_PACKET_SR_4_LABELS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SR_5_LABELS = U.add_payload(EXPECTED_OUTPUT_PACKET_SR_5_LABELS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SR_6_LABELS = U.add_payload(EXPECTED_OUTPUT_PACKET_SR_6_LABELS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SR_7_LABELS = U.add_payload(EXPECTED_OUTPUT_PACKET_SR_7_LABELS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SR_8_LABELS = U.add_payload(EXPECTED_OUTPUT_PACKET_SR_8_LABELS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_TE = U.add_payload(EXPECTED_OUTPUT_PACKET_TE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_TE_BACKUP = U.add_payload(EXPECTED_OUTPUT_PACKET_TE_BACKUP_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE = U.add_payload(EXPECTED_OUTPUT_PACKET_LDPoTE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE_WITH_VLAN = U.add_payload(
        EXPECTED_OUTPUT_PACKET_LDPoTE_WITH_VLAN_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE_LDP_IMPLICIT_NULL = U.add_payload(
        EXPECTED_OUTPUT_PACKET_LDPoTE_LDP_IMPLICIT_NULL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE_TE_IMPLICIT_NULL = U.add_payload(
        EXPECTED_OUTPUT_PACKET_LDPoTE_TE_IMPLICIT_NULL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE_LDP_AND_TE_IMPLICIT_NULL = U.add_payload(
        EXPECTED_OUTPUT_PACKET_LDPoTE_LDP_AND_TE_IMPLICIT_NULL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_IP_LDPoTE = U.add_payload(EXPECTED_OUTPUT_PACKET_IP_LDPoTE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SWAP_LDPoTE = U.add_payload(EXPECTED_OUTPUT_PACKET_SWAP_LDPoTE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SWAP_DOUBLE_LABEL_LDPoTE = U.add_payload(
        EXPECTED_OUTPUT_PACKET_SWAP_DOUBLE_LABEL_LDPoTE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SWAP_WITH_VLAN_LDPoTE = U.add_payload(
        EXPECTED_OUTPUT_PACKET_SWAP_WITH_VLAN_LDPoTE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE_TE_IMPL_NULL = U.add_payload(
        EXPECTED_OUTPUT_PACKET_LDPoTE_TE_IMPL_NULL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_2 = U.add_payload(
        EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_2_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_3 = U.add_payload(
        EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_3_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_3_NO_EXPLICIT_NULL = EXPECTED_OUTPUT_PACKET_LDPoTE_LABEL_3
    EXPECTED_OUTPUT_PACKET_TE_VPN_LABEL = U.add_payload(
        EXPECTED_OUTPUT_PACKET_TE_VPN_LABEL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_TE_VPN_LABEL_4 = U.add_payload(
        EXPECTED_OUTPUT_PACKET_TE_VPN_LABEL_4_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE_VPN_LABEL = U.add_payload(
        EXPECTED_OUTPUT_PACKET_LDPoTE_VPN_LABEL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE_VPN_LABEL_4 = U.add_payload(
        EXPECTED_OUTPUT_PACKET_LDPoTE_VPN_LABEL_4_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
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
    EXPECTED_OUTPUT_PACKET_6PE_WITH_GLOBAL_VRF = U.add_payload(
        EXPECTED_OUTPUT_PACKET_6PE_WITH_GLOBAL_VRF_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_prefix_nh_to_ip(self):
        self._test_ecmp_prefix_nh_to_ip_setup()
        self.topology.vrf.hld_obj.add_ipv4_route(self.prefix, self.m_ecmp_rec, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_ecmp_prefix_nh_to_ip_run()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_prefix_nh_to_mpls(self):
        self._test_ecmp_prefix_nh_to_mpls_setup()
        self.topology.vrf.hld_obj.add_ipv4_route(self.prefix, self.m_ecmp_rec, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_ecmp_prefix_nh_to_mpls_run()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_tenh_to_mpls(self):
        self._test_ecmp_tenh_to_mpls_setup()
        self.topology.vrf.hld_obj.add_ipv4_route(self.prefix, self.te_ecmp, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_ecmp_tenh_to_mpls_run()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_fec_prefix_nh_to_ip(self):
        self._test_fec_prefix_nh_to_ip_setup()
        self.topology.vrf.hld_obj.add_ipv4_route(self.prefix, self.fec.hld_obj, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_fec_prefix_nh_to_ip_run()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_fec_prefix_nh_to_mpls(self):
        self._test_fec_prefix_nh_to_mpls_setup()
        self.topology.vrf.hld_obj.add_ipv4_route(self.prefix, self.fec.hld_obj, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_fec_prefix_nh_to_mpls_run()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_pacific(), "Feature is not supported on Pacific")
    def test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_no_ldp_vrf_redir(self):
        vrf = self.device.create_vrf(100)

        self._test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_setup(is_v4=True, enable_ldp=False, add_lsp_counter=True, redir_vrf=vrf)

        vrf.add_ipv4_route(self.prefix, self.bgp_ecmp, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        redir_vrf_dest = self.device.create_vrf_redirect_destination(vrf)
        self.topology.vrf.hld_obj.add_ipv4_route(self.prefix, redir_vrf_dest, mpls_headend_base.PRIVATE_DATA, False)

        self._test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_run(enable_ldp=False)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - NP2 compound")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ip6pe_with_global_vrf(self):
        self._test_ip6pe_with_global_vrf_setup()
        self.topology.global_vrf.hld_obj.add_ipv4_route(self.prefix, self.m_ecmp_rec, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_ip6pe_with_global_vrf_run()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_with_vlan(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls(with_vlan=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_ldp_implicit_null(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls_ldp_implicit_null()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_te_implicit_null(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls_te_implicit_null()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_ldp_and_te_implicit_null(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls_ldp_and_te_implicit_null()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ip_ecmp_ldp_tenh_to_mpls(self):
        self._test_ip_ecmp_ldp_tenh_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_l3_dlp_update(self):
        self._test_prefix_ecmp_ldp_tenh_l3_dlp_update()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_label_2(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls_label_2()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_label_3(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls_label_3()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_label_3_no_explicit_null(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls_label_3(add_lsp_counter=False, v6_explicit_null=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_tenh_to_mpls_vpn_label(self):
        self._test_prefix_ecmp_tenh_to_mpls_vpn_label()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_tenh_to_mpls_vpn_label_4(self):
        self._test_prefix_ecmp_tenh_to_mpls_vpn_label_4()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_vpn_label(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls_vpn_label()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_vpn_label_4(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls_vpn_label_4()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_label_4(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls_label_4()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_label_4_lsp_counter(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls_label_4(False, True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_label_4_both_counter(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls_label_4(True, True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls_label_8(self):
        self._test_prefix_ecmp_ldp_tenh_to_mpls_label_8()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_tenh_to_ip(self):
        self._test_prefix_ecmp_tenh_to_ip()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_tenh_to_mpls(self):
        self._test_prefix_ecmp_tenh_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_tenh_to_mpls_3_labels(self):
        self._test_prefix_ecmp_tenh_to_mpls_3_labels()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_tenh_to_mpls_4_labels(self):
        self._test_prefix_ecmp_tenh_to_mpls_4_labels()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_tenh_to_mpls_5_labels(self):
        self._test_prefix_ecmp_tenh_to_mpls_5_labels()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_tenh_to_mpls_6_labels(self):
        self._test_prefix_ecmp_tenh_to_mpls_6_labels()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_tenh_to_mpls_7_labels(self):
        self._test_prefix_ecmp_tenh_to_mpls_7_labels()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_tenh_to_mpls_8_labels(self):
        self._test_prefix_ecmp_tenh_to_mpls_8_labels()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_to_ip(self):
        self._test_prefix_ecmp_to_ip()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_to_mpls(self):
        self._test_prefix_ecmp_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_to_mpls_dm_counter(self):
        self._test_prefix_ecmp_to_mpls(True, True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_global_ecmp_to_mpls(self):
        self._test_prefix_global_ecmp_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_global_ecmp_to_mpls_dm_counter(self):
        self._test_prefix_global_ecmp_to_mpls(True, True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_sr_global_per_protocol_counters(self):
        self._test_sr_global_per_protocol_counters(sdk.la_mpls_sr_protocol_counter_e_IP_UC)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_sr_global_with_4_labels(self):
        self._test_sr_global_with_4_labels()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_sr_global_with_5_labels(self):
        self._test_sr_global_with_5_labels()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_sr_global_with_6_labels(self):
        self._test_sr_global_with_6_labels()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_sr_global_with_7_labels(self):
        self._test_sr_global_with_7_labels()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_sr_global_with_7_labels_dm_counter(self):
        self._test_sr_global_with_7_labels(True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_sr_global_with_8_labels(self):
        self._test_sr_global_with_8_labels()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_sr_global_label_update(self):
        self._test_sr_global_label_update()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_global_ecmp_update_destination(self):
        self._test_prefix_global_ecmp_update_destination()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_global_error_handling(self):
        self._test_prefix_global_error_handling()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ldp_tenh_error_handling1(self):
        self._test_ldp_tenh_error_handling1()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ldp_tenh_error_handling2(self):
        self._test_ldp_tenh_error_handling2()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ldp_tenh_to_mpls(self):
        self._test_prefix_ldp_tenh_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ldp_tenh_to_mpls_te_impl_null(self):
        self._test_prefix_ldp_tenh_to_mpls_te_impl_null()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_nh_to_ip(self):
        self._test_prefix_nh_to_ip()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_nh_to_ip_uniform(self):
        self._test_prefix_nh_to_ip_uniform()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_nh_to_mpls(self):
        self._test_prefix_nh_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_nh_to_mpls_uniform(self):
        self._test_prefix_nh_to_mpls_uniform()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_nh_to_mpls_update_label(self):
        self._test_prefix_nh_to_mpls_update_label()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_tenh_to_ip(self):
        self._test_prefix_tenh_to_ip()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_tenh_to_mpls(self):
        self._test_prefix_tenh_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_ecmp_ldp_tenh_to_mpls(self):
        self._test_swap_ecmp_ldp_tenh_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_ecmp_ldp_tenh_to_mpls_double_label(self):
        self._test_swap_ecmp_ldp_tenh_to_mpls_double_label()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_with_vlan_ecmp_ldp_tenh_to_mpls(self):
        self._test_swap_with_vlan_ecmp_ldp_tenh_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_clear_prefix_ldp_tenh_lsp_properties(self):
        self._test_clear_prefix_ldp_tenh_lsp_properties()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_clear_prefix_nh_lsp_properties(self):
        self._test_clear_prefix_nh_lsp_properties()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_clear_prefix_tenh_lsp_properties(self):
        self._test_clear_prefix_tenh_lsp_properties()

    @unittest.skipUnless(decor.is_pacific(), "Test is only enabled on PAC")
    def test_invalid_prefix(self):
        self._test_invalid_prefix()

    @unittest.skipUnless(decor.is_pacific(), "Test is only enabled on PAC")
    def test_prefix_object_destination_entry_format(self):
        self._test_prefix_object_destination_entry_format()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mpls_headend_getter(self):
        self._test_prefix_tenh_to_mpls_getter()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_prefix_object_destination(self):
        self._test_set_prefix_object_destination()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_te_destination(self):
        self._test_set_te_destination()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_te_type(self):
        self._test_set_te_type()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_no_ldp(self):
        self._test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_setup(is_v4=True, enable_ldp=False, add_lsp_counter=True)
        self.topology.vrf.hld_obj.add_ipv4_route(self.prefix, self.bgp_ecmp, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_run(enable_ldp=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_with_ldp(self):
        self._test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_setup(is_v4=True, enable_ldp=True, add_lsp_counter=True)
        self.topology.vrf.hld_obj.add_ipv4_route(self.prefix, self.bgp_ecmp, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_run(enable_ldp=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_ip_ecmp_dpe_ecmp_implicit_null_asbr_lsp_to_mpls_with_ldp(self):
        self._test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_setup(
            is_v4=True, enable_ldp=True, add_lsp_counter=True, asbr_labels_null=True)
        self.topology.vrf.hld_obj.add_ipv4_route(self.prefix, self.bgp_ecmp, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_run(enable_ldp=True, asbr_labels_null=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_dpe_vpn_properties(self):
        self._test_bgp_lu_dpe_vpn_properties()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_object_vpn_properties(self):
        self._test_prefix_object_vpn_properties()


if __name__ == '__main__':
    unittest.main()
