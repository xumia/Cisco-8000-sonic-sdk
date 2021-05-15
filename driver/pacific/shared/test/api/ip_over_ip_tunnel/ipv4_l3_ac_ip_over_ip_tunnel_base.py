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

import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
import ip_test_base
import sim_utils
from sdk_test_case_base import *
from ip_over_ip_tunnel.ip_over_ip_tunnel_base import *


class ipv4_l3_ac_ip_over_ip_tunnel_base(ip_over_ip_tunnel_base):
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl = ip_test_base.ipv4_test_base
    TUNNEL_PORT_GID1 = 0x521
    TUNNEL_PORT_GID2 = 0x522
    TUNNEL_PORT_GID3 = 0x523
    TUNNEL_PORT_GID4 = 0x524
    TUNNEL_PORT_GID5 = 0x525
    REMOTE_IP = T.ipv4_addr('12.10.12.10')
    ANY_IP = T.ipv4_addr('255.255.255.255')
    REMOTE_ANY_IP = T.ipv4_addr('250.12.255.10')
    LOCAL_IP1 = T.ipv4_addr('192.168.95.250')
    LOCAL_IP2 = T.ipv4_addr('202.168.95.250')
    LOCAL_IP3 = T.ipv4_addr('194.168.100.155')
    NEW_REMOTE_IP = T.ipv4_addr('12.11.12.11')
    NEW_LOCAL_IP = T.ipv4_addr('192.168.100.250')
    SIP = T.ipv4_addr('102.10.12.10')
    DIP = T.ipv4_addr('202.81.95.250')
    DIP1 = T.ipv4_addr('150.111.111.111')
    DSCP_VAL = 8
    DSCP = sdk.la_ip_dscp()
    DSCP.value = DSCP_VAL

    INPUT_PACKET_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ip_over_ip_tunnel_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=REMOTE_IP.addr_str, dst=LOCAL_IP1.addr_str, ttl=ip_over_ip_tunnel_base.TUNNEL_TTL) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_over_ip_tunnel_base.TTL)

    INPUT_PACKET_ANY_IP_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ip_over_ip_tunnel_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=REMOTE_ANY_IP.addr_str, dst=LOCAL_IP2.addr_str, ttl=ip_over_ip_tunnel_base.TUNNEL_TTL) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_over_ip_tunnel_base.TTL)

    INPUT_PACKET_NEW_REMOTE_IP_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ip_over_ip_tunnel_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=NEW_REMOTE_IP.addr_str, dst=LOCAL_IP1.addr_str, ttl=ip_over_ip_tunnel_base.TUNNEL_TTL) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_over_ip_tunnel_base.TTL)

    INPUT_PACKET_TTL_QOS_UNIFORM_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ip_over_ip_tunnel_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=REMOTE_IP.addr_str, dst=LOCAL_IP1.addr_str, ttl=ip_over_ip_tunnel_base.TUNNEL_TTL, tos=DSCP_VAL << 2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_over_ip_tunnel_base.TTL)

    INPUT_PACKET_NEW_LOCAL_IP_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ip_over_ip_tunnel_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=REMOTE_IP.addr_str, dst=NEW_LOCAL_IP.addr_str, ttl=ip_over_ip_tunnel_base.TUNNEL_TTL) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_over_ip_tunnel_base.TTL)

    INPUT_PACKET_MULTI_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ip_over_ip_tunnel_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=REMOTE_IP.addr_str, dst=LOCAL_IP3.addr_str, ttl=ip_over_ip_tunnel_base.TUNNEL_TTL) / \
        S.IP(src=SIP.addr_str, dst=DIP1.addr_str, ttl=ip_over_ip_tunnel_base.TTL)

    EXPECTED_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_over_ip_tunnel_base.TTL - 1)

    EXPECTED_OUTPUT_PACKET_NO_TTL_DECR_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_over_ip_tunnel_base.TTL)

    EXPECTED_OUTPUT_PACKET_TTL_QOS_UNIFORM_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_over_ip_tunnel_base.TUNNEL_TTL - 1, tos=DSCP_VAL << 2)

    EXPECTED_OUTPUT_PACKET_MULTI_BASE = \
        S.IP(src=SIP.addr_str, dst=DIP1.addr_str, ttl=ip_over_ip_tunnel_base.TTL - 1)

    INPUT_PACKET, PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    INPUT_ANY_IP_PACKET, PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_ANY_IP_BASE)
    INPUT_PACKET_NEW_REMOTE_IP = add_payload(INPUT_PACKET_NEW_REMOTE_IP_BASE, PAYLOAD_SIZE)
    INPUT_PACKET_TTL_QOS_UNIFORM = add_payload(INPUT_PACKET_TTL_QOS_UNIFORM_BASE, PAYLOAD_SIZE)
    INPUT_PACKET_NEW_LOCAL_IP = add_payload(INPUT_PACKET_NEW_LOCAL_IP_BASE, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET = add_payload(EXPECTED_OUTPUT_PACKET_BASE, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_NO_TTL_DECR = add_payload(EXPECTED_OUTPUT_PACKET_NO_TTL_DECR_BASE, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_TTL_QOS_UNIFORM = add_payload(EXPECTED_OUTPUT_PACKET_TTL_QOS_UNIFORM_BASE, PAYLOAD_SIZE)

    EXPECTED_OUTPUT_PACKET_MULTI, PAYLOAD_SIZE = enlarge_packet_to_min_length(EXPECTED_OUTPUT_PACKET_MULTI_BASE)
    INPUT_PACKET_MULTI = add_payload(INPUT_PACKET_MULTI_BASE, PAYLOAD_SIZE)
