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

import decor
from mpls_to_mpls_headend_base import *
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
class ipv4_l3_ac_test(mpls_to_mpls_headend_base):
    protocol = sdk.la_l3_protocol_e_IPV4_UC
    l3_port_impl_class = T.ip_l3_ac_base

    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_to_mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    INPUT_PACKET_GLOBAL_VRF_BASE = \
        Ether(dst=T.TX_L3_AC_EXT_MAC.addr_str, src=mpls_to_mpls_headend_base.SA.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    INPUT_PACKET_WITH_EXP_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_to_mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL0.label, cos=1, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    INPUT_PACKET_DOUBLE_LABEL_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_to_mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 2, s=0) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL1.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    INPUT_PACKET_DOUBLE_LABEL_1_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_to_mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL + 2, s=0) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL1.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    INPUT_PACKET_WITH_VLAN_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_to_mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_to_mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    INPUT_PACKET_MULTI_LABEL_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_to_mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL1.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL2.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL3.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL4.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL5.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL6.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL7.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL8.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL9.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL)

    INPUT_PACKET_MULTI_LABEL_BASE_gtp = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_to_mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL1.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL)

    EXPECTED_OUTPUT_SWAP_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.OUTPUT_LABEL0.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.OUTPUT_LABEL2.label, cos=1, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_to_mpls_headend_base.OUTPUT_LABEL1.label, cos=1, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_to_mpls_headend_base.OUTPUT_LABEL0.label, cos=1, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_SWAP_PACKET_WITH_VLAN_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=mpls_to_mpls_headend_base.OUTPUT_VID, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.OUTPUT_LABEL0.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_to_mpls_headend_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_SWAP_PACKET_DOUBLE_LABEL_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.OUTPUT_LABEL0.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 3, s=0) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL1.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_POP_PIPE_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL1.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_POP_UNIFORM_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL1.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 3) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_PHP_UNIFORM_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1)

    EXPECTED_OUTPUT_BGP_LU_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.LDP_LABEL.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_to_mpls_headend_base.BGP_LABEL.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_BGP_LU_NO_LDP_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.BGP_LABEL.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_BGP_LU_PACKET_NEW_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.LDP_LABEL.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_to_mpls_headend_base.BGP_LABEL_NEW.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_BGP_LU_NO_LDP_BGP_LBL_UPDATED_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.BGP_LABEL_NEW.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_BGP_LU_NO_LDP_DEST_UPDATED_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.BGP_LABEL.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_BGP_LU_DEST_UPDATED_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.LDP_LABEL.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_to_mpls_headend_base.BGP_LABEL.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_BGP_LU_IMPL_NULL_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.LDP_LABEL.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_PACKET_MULTI_LABEL_BASE = \
        MPLS(label=mpls_to_mpls_headend_base.OUTPUT_LABEL0.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL1.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL2.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL3.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL4.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL5.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL6.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL7.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL8.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL9.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL)

    EXPECTED_OUTPUT_PACKET_MULTI_LABEL_BASE_gtp = \
        MPLS(label=mpls_to_mpls_headend_base.OUTPUT_LABEL0.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL1.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL)

    EXPECTED_OUTPUT_VPN_CSC_PE_PACKET1_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.LDP_LABEL.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_to_mpls_headend_base.VPN_LABEL.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_VPN_CSC_PE_PACKET2_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.LDP_LABEL.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 3) / \
        MPLS(label=mpls_to_mpls_headend_base.VPN_LABEL.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 3) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL1.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    INPUT_PACKET_GLOBAL_VRF = U.add_payload(INPUT_PACKET_GLOBAL_VRF_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_WITH_EXP, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_EXP_BASE)
    INPUT_PACKET_DOUBLE_LABEL = U.add_payload(INPUT_PACKET_DOUBLE_LABEL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_DOUBLE_LABEL_1 = U.add_payload(INPUT_PACKET_DOUBLE_LABEL_1_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_WITH_VLAN = U.add_payload(INPUT_PACKET_WITH_VLAN_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_SWAP_PACKET = U.add_payload(EXPECTED_OUTPUT_SWAP_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET = U.add_payload(
        EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_SWAP_PACKET_WITH_VLAN = U.add_payload(
        EXPECTED_OUTPUT_SWAP_PACKET_WITH_VLAN_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_SWAP_PACKET_DOUBLE_LABEL = U.add_payload(
        EXPECTED_OUTPUT_SWAP_PACKET_DOUBLE_LABEL_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_POP_PIPE_PACKET = U.add_payload(EXPECTED_OUTPUT_POP_PIPE_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_POP_UNIFORM_PACKET = U.add_payload(EXPECTED_OUTPUT_POP_UNIFORM_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PHP_UNIFORM_PACKET = U.add_payload(EXPECTED_OUTPUT_PHP_UNIFORM_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_BGP_LU_PACKET = U.add_payload(EXPECTED_OUTPUT_BGP_LU_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_BGP_LU_NO_LDP_PACKET = U.add_payload(
        EXPECTED_OUTPUT_BGP_LU_NO_LDP_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_BGP_LU_PACKET_NEW = U.add_payload(EXPECTED_OUTPUT_BGP_LU_PACKET_NEW_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_BGP_LU_NO_LDP_BGP_LBL_UPDATED_PACKET = U.add_payload(
        EXPECTED_OUTPUT_BGP_LU_NO_LDP_BGP_LBL_UPDATED_PACKET_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_BGP_LU_NO_LDP_DEST_UPDATED_PACKET = U.add_payload(
        EXPECTED_OUTPUT_BGP_LU_NO_LDP_DEST_UPDATED_PACKET_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_BGP_LU_DEST_UPDATED_PACKET = U.add_payload(
        EXPECTED_OUTPUT_BGP_LU_DEST_UPDATED_PACKET_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_BGP_LU_IMPL_NULL_PACKET = U.add_payload(
        EXPECTED_OUTPUT_BGP_LU_IMPL_NULL_PACKET_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_VPN_CSC_PE_PACKET1 = U.add_payload(
        EXPECTED_OUTPUT_VPN_CSC_PE_PACKET1_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_VPN_CSC_PE_PACKET2 = U.add_payload(
        EXPECTED_OUTPUT_VPN_CSC_PE_PACKET2_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_swap(self):
        self._test_ecmp_swap()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_swap_dm_counter(self):
        self._test_ecmp_swap(True, True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_global_ecmp_swap(self):
        self._test_prefix_global_ecmp_swap()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_global_ecmp_multiple_labels(self):
        self._test_prefix_global_ecmp_multiple_labels()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_sr_global_per_protocol_counters(self):
        self._test_sr_global_per_protocol_counters(sdk.la_mpls_sr_protocol_counter_e_MPLS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_ecmp_uniform(self):
        self._test_php_ecmp_uniform()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_global_php_ecmp_uniform(self):
        self._test_prefix_global_php_ecmp_uniform()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_uniform(self):
        self._test_php_uniform()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_uniform_dm_counter(self):
        self._test_php_uniform(True, False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap(self):
        self._test_swap()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_dm_counter(self):
        self._test_swap(True, True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_double_label(self):
        self._test_swap_double_label()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_add_existing_lsr_entry(self):
        self._test_add_existing_lsr_entry()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_clear_mappings(self):
        self._test_clear_mappings()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_label_mapping(self):
        self._test_get_label_mapping()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_remove_busy_prefix_object(self):
        self._test_remove_busy_prefix_object()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop_double_label_pipe(self):
        self._test_pop_double_label_pipe()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop_double_label_uniform_1(self):
        self._test_pop_double_label_uniform_1()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop_double_label_uniform_2(self):
        self._test_pop_double_label_uniform_2()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_dpe_ecmp_asbr_lsp_to_mpls_no_ldp(self):
        self._test_bgp_lu_dpe_ecmp_asbr_lsp_to_mpls(enable_ldp=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop_double_label_pipe(self):
        self._test_pop_double_label_pipe()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop_double_label_uniform_1(self):
        self._test_bgp_lu_dpe_ecmp_asbr_lsp_drop_nh()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_transit_asbr_with_vpn(self):
        self._test_bgp_lu_transit_asbr_with_vpn()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_error_handling(self):
        self._test_bgp_lu_error_handling()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_update_asbr_lsp_asbr(self):
        self._test_bgp_lu_update_asbr_lsp_asbr()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_update_asbr_lsp_destination_no_ldp(self):
        self._test_bgp_lu_update_asbr_lsp_destination(False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_update_asbr_lsp_asbr(self):
        self._test_bgp_lu_update_asbr_lsp_asbr()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_update_asbr_lsp_prot_group_destination(self):
        self._test_bgp_lu_update_asbr_lsp_prot_group_destination()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_update_dpe_destination(self):
        self._test_bgp_lu_update_dpe_destination()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_csc_label_check(self):
        self._test_csc_label_check()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_csc_label_check_intf_non_csc(self):
        self._test_csc_label_check_intf_non_csc()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_csc_label_check_label_drop(self):
        self._test_csc_label_check_label_drop()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_csc_label_check_vrf_drop(self):
        self._test_csc_label_check_vrf_drop()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_uniform_csc_label_check(self):
        self._test_php_uniform_csc_label_check()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_uniform_csc_label_check_intf_non_csc(self):
        self._test_php_uniform_csc_label_check_intf_non_csc()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_uniform_csc_label_check_label_drop(self):
        self._test_php_uniform_csc_label_check_label_drop()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_uniform_csc_label_check_vrf_drop(self):
        self._test_php_uniform_csc_label_check_vrf_drop()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_hash_multipath_mpls_ip(self):
        self._test_ecmp_hash_multipath_mpls_ip()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_ecmp_hash_multipath_mpls_eth(self):
        self._test_ecmp_hash_multipath_mpls_eth()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_hash_multipath_mpls_gtp(self):
        self._test_ecmp_hash_multipath_mpls_gtp()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_vpn_on_csc_pe_with_1_label(self):
        self._test_vpn_on_csc_pe_with_1_label()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_vpn_on_csc_pe_with_2_labels(self):
        self._test_vpn_on_csc_pe_with_2_labels()


if __name__ == '__main__':
    unittest.main()
