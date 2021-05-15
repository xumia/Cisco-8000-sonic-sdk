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

from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
import ip_test_base
from sdk_test_case_base import *
from gue.gue_base import *

load_contrib('mpls')


class l3_ac_gue_base(gue_base):
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl = ip_test_base.ipv4_test_base
    ip6_impl = ip_test_base.ipv6_test_base
    TUNNEL_PORT_GID1 = 0x521
    TUNNEL_PORT_GID2 = 0x522
    TUNNEL_PORT_GID3 = 0x523
    TUNNEL_PORT_GID4 = 0x524
    REMOTE_IP = T.ipv4_addr('12.10.12.10')
    ANY_IP = T.ipv4_addr('255.255.255.255')
    REMOTE_ANY_IP = T.ipv4_addr('250.12.255.10')
    LOCAL_IP1 = T.ipv4_addr('192.168.95.250')
    LOCAL_IP2 = T.ipv4_addr('202.168.95.250')
    NEW_REMOTE_IP = T.ipv4_addr('12.11.12.11')
    NEW_LOCAL_IP = T.ipv4_addr('192.168.100.250')
    SIP = T.ipv4_addr('102.10.12.10')
    DIP = T.ipv4_addr('202.81.95.250')
    SIP1 = T.ipv4_addr('103.10.12.10')
    DIP1 = T.ipv4_addr('203.81.95.250')
    SIP_UNL = T.ipv4_addr('192.168.200.250')
    DIP_UNL = T.ipv4_addr('192.168.250.251')
    SIPv6 = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    DIPv6 = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')
    DSCP_VAL = 8
    DSCP = sdk.la_ip_dscp()
    DSCP.value = DSCP_VAL
    INPUT_LABEL = sdk.la_mpls_label()
    INPUT_LABEL.label = 0x64
    OUTPUT_LABEL = sdk.la_mpls_label()
    OUTPUT_LABEL.label = 0x65
    NUM_OF_NH = 10

    INPUT_PACKET_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=gue_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=REMOTE_IP.addr_str, dst=LOCAL_IP1.addr_str, ttl=gue_base.TUNNEL_TTL) / \
        S.UDP(sport=0x17ff, dport=0x17c0) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=gue_base.TTL)

    INPUT_PACKET_BASE_v6 = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=gue_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=REMOTE_IP.addr_str, dst=LOCAL_IP1.addr_str, ttl=gue_base.TUNNEL_TTL) / \
        S.UDP(sport=0x17ff, dport=0x17c0) / \
        S.IPv6(src=SIPv6.addr_str, dst=DIPv6.addr_str, hlim=gue_base.TTL, plen=40)

    INPUT_PACKET_ANY_IP_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=gue_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=REMOTE_ANY_IP.addr_str, dst=LOCAL_IP2.addr_str, ttl=gue_base.TUNNEL_TTL) / \
        S.UDP(sport=0x17ff, dport=0x17c0) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=gue_base.TTL)

    INPUT_PACKET_NEW_REMOTE_IP_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=gue_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=NEW_REMOTE_IP.addr_str, dst=LOCAL_IP1.addr_str, ttl=gue_base.TUNNEL_TTL) / \
        S.UDP(sport=0x17ff, dport=0x17c0) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=gue_base.TTL)

    INPUT_PACKET_TTL_QOS_UNIFORM_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=gue_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=REMOTE_IP.addr_str, dst=LOCAL_IP1.addr_str, ttl=gue_base.TUNNEL_TTL, tos=DSCP_VAL << 2) / \
        S.UDP(sport=0x17ff, dport=0x17c0) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=gue_base.TTL)

    INPUT_PACKET_NEW_LOCAL_IP_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=gue_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=REMOTE_IP.addr_str, dst=NEW_LOCAL_IP.addr_str, ttl=gue_base.TUNNEL_TTL) / \
        S.UDP(sport=0x17ff, dport=0x17c0) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=gue_base.TTL)

    INPUT_PACKET_BASE_MPLS = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=gue_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=REMOTE_IP.addr_str, dst=LOCAL_IP1.addr_str, ttl=gue_base.TUNNEL_TTL) / \
        S.UDP(sport=0x17ff, dport=0x19eb) / \
        MPLS(label=INPUT_LABEL.label, ttl=gue_base.MPLS_TTL) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=gue_base.TTL)

    INPUT_PACKET_BASE_MPLS_NOVLAN = \
        S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str, src=gue_base.SA.addr_str) / \
        S.IP(src=REMOTE_IP.addr_str, dst=LOCAL_IP1.addr_str, ttl=gue_base.TUNNEL_TTL) / \
        S.UDP(sport=0x17ff, dport=0x19eb) / \
        MPLS(label=INPUT_LABEL.label, ttl=gue_base.MPLS_TTL) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=gue_base.TTL)

    INPUT_PACKET_BASE_MPLS_ENCAP = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=gue_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=REMOTE_IP.addr_str, dst=LOCAL_IP1.addr_str, ttl=gue_base.TUNNEL_TTL) / \
        S.UDP(sport=0x17ff, dport=0x17c0) / \
        S.IP(src=SIP1.addr_str, dst=DIP1.addr_str, ttl=gue_base.TTL)

    INPUT_PACKET_BASE_MPLS_v6 = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=gue_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=REMOTE_IP.addr_str, dst=LOCAL_IP1.addr_str, ttl=gue_base.TUNNEL_TTL) / \
        S.UDP(sport=0x17ff, dport=0x19eb) / \
        MPLS(label=INPUT_LABEL.label, ttl=gue_base.MPLS_TTL) / \
        S.IPv6(src=SIPv6.addr_str, dst=DIPv6.addr_str, hlim=gue_base.TTL, plen=40)

    INPUT_PACKET_BASE_MPLS_NOVLAN_v6 = \
        S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str, src=gue_base.SA.addr_str) / \
        S.IP(src=REMOTE_IP.addr_str, dst=LOCAL_IP1.addr_str, ttl=gue_base.TUNNEL_TTL) / \
        S.UDP(sport=0x17ff, dport=0x19eb) / \
        MPLS(label=INPUT_LABEL.label, ttl=gue_base.MPLS_TTL) / \
        S.IPv6(src=SIPv6.addr_str, dst=DIPv6.addr_str, hlim=gue_base.TTL, plen=40)

    INPUT_PACKET_BASE_MPLS_ENCAP_v6 = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=gue_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=REMOTE_IP.addr_str, dst=LOCAL_IP1.addr_str, ttl=gue_base.TUNNEL_TTL) / \
        S.UDP(sport=0x17ff, dport=0x17c0) / \
        S.IPv6(src=SIPv6.addr_str, dst=DIPv6.addr_str, hlim=gue_base.TTL, plen=40)

    INPUT_PACKET_MULTI_BASE = \
        S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str, src=gue_base.SA.addr_str) / \
        S.IP(src=REMOTE_IP.addr_str, dst=LOCAL_IP1.addr_str, ttl=gue_base.TUNNEL_TTL) / \
        S.UDP(sport=0x17ff, dport=0x17c0) / \
        S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str, ttl=gue_base.TTL) / \
        S.TCP()

    INPUT_PACKET_MPLS_MULTI_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=gue_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=REMOTE_IP.addr_str, dst=LOCAL_IP1.addr_str, ttl=gue_base.TUNNEL_TTL) / \
        S.UDP(sport=0x17ff, dport=0x19eb) / \
        MPLS(label=INPUT_LABEL.label, ttl=gue_base.MPLS_TTL) / \
        S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str, ttl=gue_base.TTL) / \
        S.TCP()

    EXPECTED_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=gue_base.TTL - 1)

    EXPECTED_OUTPUT_PACKET_NO_TTL_DECR_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=gue_base.TTL)

    EXPECTED_OUTPUT_PACKET_BASE_v6 = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IPv6(src=SIPv6.addr_str, dst=DIPv6.addr_str, hlim=gue_base.TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_NO_TTL_DECR_BASE_v6 = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IPv6(src=SIPv6.addr_str, dst=DIPv6.addr_str, hlim=gue_base.TTL, plen=40)

    EXPECTED_OUTPUT_PACKET_TTL_QOS_UNIFORM_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=gue_base.TUNNEL_TTL - 1, tos=DSCP_VAL << 2)

    EXPECTED_OUTPUT_PACKET_BASE_MPLS_SWAP = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=OUTPUT_LABEL.label, ttl=gue_base.MPLS_TTL - 1) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=gue_base.TTL)

    EXPECTED_OUTPUT_PACKET_BASE_MPLS_ENCAP = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=OUTPUT_LABEL.label, ttl=gue_base.TUNNEL_TTL) / \
        S.IP(src=SIP1.addr_str, dst=DIP1.addr_str, ttl=gue_base.TTL - 1)

    EXPECTED_OUTPUT_PACKET_BASE_MPLS_DECAP = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=gue_base.TTL - 1)

    EXPECTED_OUTPUT_PACKET_BASE_MPLS_SWAP_v6 = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=OUTPUT_LABEL.label, ttl=gue_base.MPLS_TTL - 1) / \
        S.IPv6(src=SIPv6.addr_str, dst=DIPv6.addr_str, hlim=gue_base.TTL, plen=40)

    EXPECTED_OUTPUT_PACKET_BASE_MPLS_ENCAP_v6 = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=OUTPUT_LABEL.label, ttl=gue_base.TUNNEL_TTL) / \
        S.IPv6(src=SIPv6.addr_str, dst=DIPv6.addr_str, hlim=gue_base.TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_BASE_MPLS_DECAP_v6 = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IPv6(src=SIPv6.addr_str, dst=DIPv6.addr_str, hlim=gue_base.TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_MULTI_BASE = \
        S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str, ttl=gue_base.TTL - 1) / \
        S.TCP()

    EXPECTED_OUTPUT_PACKET_MPLS_MULTI_BASE = \
        MPLS(label=OUTPUT_LABEL.label, ttl=gue_base.MPLS_TTL - 1) / \
        S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str, ttl=gue_base.TTL) / \
        S.TCP()

    INPUT_PACKET, PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    INPUT_PACKET_v6, PAYLOAD_SIZE_v6 = enlarge_packet_to_min_length(INPUT_PACKET_BASE_v6)
    INPUT_ANY_IP_PACKET, PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_ANY_IP_BASE)
    INPUT_PACKET_NEW_REMOTE_IP = add_payload(INPUT_PACKET_NEW_REMOTE_IP_BASE, PAYLOAD_SIZE)
    INPUT_PACKET_TTL_QOS_UNIFORM = add_payload(INPUT_PACKET_TTL_QOS_UNIFORM_BASE, PAYLOAD_SIZE)
    INPUT_PACKET_NEW_LOCAL_IP = add_payload(INPUT_PACKET_NEW_LOCAL_IP_BASE, PAYLOAD_SIZE)
    INPUT_PACKET_MPLS, BASE_INPUT_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_BASE_MPLS)
    INPUT_PACKET_MPLS_NOVLAN, BASE_INPUT_PACKET_PAYLOAD_SIZE_NOVLAN = enlarge_packet_to_min_length(INPUT_PACKET_BASE_MPLS_NOVLAN)
    INPUT_PACKET_MPLS_ENCAP, BASE_INPUT_PACKET_PAYLOAD_SIZE_ENCAP = enlarge_packet_to_min_length(INPUT_PACKET_BASE_MPLS_ENCAP)
    INPUT_PACKET_MPLS_NOVLAN_v6, BASE_INPUT_PACKET_PAYLOAD_SIZE_NOVLAN_v6 = enlarge_packet_to_min_length(
        INPUT_PACKET_BASE_MPLS_NOVLAN_v6)
    INPUT_PACKET_MPLS_v6, BASE_INPUT_PACKET_PAYLOAD_SIZE_v6 = enlarge_packet_to_min_length(INPUT_PACKET_BASE_MPLS_v6)
    INPUT_PACKET_MPLS_ENCAP_v6, BASE_INPUT_PACKET_PAYLOAD_SIZE_ENCAP_v6 = enlarge_packet_to_min_length(
        INPUT_PACKET_BASE_MPLS_ENCAP_v6)

    EXPECTED_OUTPUT_PACKET = add_payload(EXPECTED_OUTPUT_PACKET_BASE, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_NO_TTL_DECR = add_payload(EXPECTED_OUTPUT_PACKET_NO_TTL_DECR_BASE, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_v6 = add_payload(EXPECTED_OUTPUT_PACKET_BASE_v6, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_NO_TTL_DECR_v6 = add_payload(EXPECTED_OUTPUT_PACKET_NO_TTL_DECR_BASE_v6, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_TTL_QOS_UNIFORM = add_payload(EXPECTED_OUTPUT_PACKET_TTL_QOS_UNIFORM_BASE, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_MPLS_SWAP = add_payload(EXPECTED_OUTPUT_PACKET_BASE_MPLS_SWAP, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_MPLS_ENCAP = add_payload(EXPECTED_OUTPUT_PACKET_BASE_MPLS_ENCAP, BASE_INPUT_PACKET_PAYLOAD_SIZE_ENCAP)
    EXPECTED_OUTPUT_PACKET_MPLS_DECAP = add_payload(EXPECTED_OUTPUT_PACKET_BASE_MPLS_DECAP, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_MPLS_SWAP_v6 = add_payload(EXPECTED_OUTPUT_PACKET_BASE_MPLS_SWAP_v6, BASE_INPUT_PACKET_PAYLOAD_SIZE_v6)
    EXPECTED_OUTPUT_PACKET_MPLS_ENCAP_v6 = add_payload(
        EXPECTED_OUTPUT_PACKET_BASE_MPLS_ENCAP_v6,
        BASE_INPUT_PACKET_PAYLOAD_SIZE_ENCAP_v6)
    EXPECTED_OUTPUT_PACKET_MPLS_DECAP_v6 = add_payload(EXPECTED_OUTPUT_PACKET_BASE_MPLS_DECAP_v6, BASE_INPUT_PACKET_PAYLOAD_SIZE_v6)
