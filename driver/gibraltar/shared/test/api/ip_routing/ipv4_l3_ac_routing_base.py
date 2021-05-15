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
from ip_routing.ip_routing_base import *


class ipv4_l3_ac_routing_base(ip_routing_base):
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl = ip_test_base.ipv4_test_base
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    DIP0 = T.ipv4_addr('82.81.95.0')
    DIP255 = T.ipv4_addr('82.81.95.255')
    DIP_DEF_RTE = T.ipv4_addr('10.01.01.01')
    PORT_Px_GID = 0x111
    PORT_Px_MAC = T.mac_addr('01:01:01:01:01:01')
    PORT_PxVx_GID = 0x222
    PORT_PxVx_MAC = T.mac_addr('02:02:02:02:02:02')
    PORT_PxVx_VID1 = 0x4
    PORT_PxVx_VID1_2 = 0x44
    SUBNETS_HOSTS = {}
    SPORT = 4567
    DPORT = 4789  # VXLAN
    for i in range(0, 6, 2):
       # Offset by a non-zero value (2) to ensure we do not populate 0.0.0.0 in the table
        t = i + 2
        dip_str = '%d.%d.%d.%d' % (t, t, t, t)
        dip = T.ipv4_addr(dip_str)
        host = T.mac_addr('0%d:0%d:0%d:0%d:0%d:0%d' % (t, t, t, t, t, t))
        SUBNETS_HOSTS[dip] = host

    INPUT_PACKET_Px_BASE = \
        S.Ether(dst=PORT_Px_MAC.addr_str, src=ip_routing_base.SA.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL)

    INPUT_PACKET_PxVx_BASE = \
        S.Ether(dst=PORT_PxVx_MAC.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=PORT_PxVx_VID1) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL)

    INPUT_PACKET_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL)

    INPUT_PACKET_VXLAN_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL) / \
        S.UDP(sport=SPORT, dport=DPORT)

    INPUT_PACKET_DEF_RTE_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP_DEF_RTE.addr_str, ttl=ip_routing_base.TTL)

    INPUT_INJECT_UP_PACKET_BASE = \
        S.Ether(dst=PUNT_INJECT_PORT_MAC_ADDR, src=HOST_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(prio=0, id=0, vlan=INJECT_VLAN, type=U.Ethertype.Inject.value) / \
        U.InjectUp(ssp_gid=T.RX_SYS_PORT_GID) / \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL)

    EXPECTED_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL - 1)

    EXPECTED_OUTPUT_PACKET_VXLAN_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL - 1) / \
        S.UDP(sport=SPORT, dport=DPORT)

    EXPECTED_OUTPUT_PACKET_DEF_RTE_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP_DEF_RTE.addr_str, ttl=ip_routing_base.TTL - 1)

    EXPECTED_OUTPUT_PACKET_WITH_VLAN_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=ip_routing_base.OUTPUT_VID) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL - 1)

    EXPECTED_OUTPUT_PACKET_WITH_VLAN_VLAN_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.SVLAN.value) / \
        S.Dot1Q(vlan=ip_routing_base.OUTPUT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=ip_routing_base.OUTPUT_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL - 1)

    EXPECTED_OUTPUT_PACKET_WITH_UPDATED_MAC_BASE = \
        S.Ether(dst=NH_MAC_MODIFIED.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL - 1)

    EXPECTED_DEFAULT_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL - 1)

    EXPECTED_EXTRA_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL - 1)

    PUNT_PACKET_BASE = \
        S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
        U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
               next_header_offset=len(S.Ether()) + 2 * len(S.Dot1Q()),
               source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP, code=sdk.LA_EVENT_L3_GLEAN_ADJ,
               source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
               #source_lp=T.RX_L3_AC_GID, destination_lp=sdk.la_packet_types.LA_L3_LOGICAL_PORT_GID_INVALID,
               source_lp=T.RX_L3_AC_GID, destination_lp=sdk.LA_EVENT_L3_GLEAN_ADJ,
               relay_id=T.VRF_GID, lpts_flow_type=0
               ) / \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL)

    PUNT_PACKET_L3_DROP_ADJ_BASE = \
        S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
        U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
               next_header_offset=len(S.Ether()) + len(S.Dot1Q()) + len(U.InjectUp()) + len(S.Ether()) + 2 * len(S.Dot1Q()),
               source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP, code=sdk.LA_EVENT_L3_DROP_ADJ,
               source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
               #source_lp=T.RX_L3_AC_GID, destination_lp=sdk.la_packet_types.LA_L3_LOGICAL_PORT_GID_INVALID,
               source_lp=T.RX_L3_AC_GID, destination_lp=sdk.LA_EVENT_L3_DROP_ADJ,
               relay_id=T.VRF_GID, lpts_flow_type=0
               ) / \
        INPUT_INJECT_UP_PACKET_BASE

    PUNT_PACKET_L3_DROP_ADJ_NON_INJECT_BASE = \
        S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
        U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
               next_header_offset=len(S.Ether()) + 2 * len(S.Dot1Q()),
               source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP, code=sdk.LA_EVENT_L3_DROP_ADJ_NON_INJECT,
               source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
               #source_lp=T.RX_L3_AC_GID, destination_lp=sdk.la_packet_types.LA_L3_LOGICAL_PORT_GID_INVALID,
               source_lp=T.RX_L3_AC_GID, destination_lp=sdk.LA_EVENT_L3_DROP_ADJ_NON_INJECT,
               relay_id=T.VRF_GID, lpts_flow_type=0
               ) / \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL)

    PUNT_PACKET_L3_USER_TRAP1_ADJ_BASE = \
        S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
        U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
               next_header_offset=len(S.Ether()) + len(S.Dot1Q()) + len(U.InjectUp()) + len(S.Ether()) + 2 * len(S.Dot1Q()),
               source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP, code=sdk.LA_EVENT_L3_USER_TRAP1,
               source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
               source_lp=T.RX_L3_AC_GID, destination_lp=sdk.LA_EVENT_L3_USER_TRAP1,
               relay_id=T.VRF_GID, lpts_flow_type=0
               ) / \
        INPUT_INJECT_UP_PACKET_BASE

    PUNT_PACKET_L3_USER_TRAP2_ADJ_BASE = \
        S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
        U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
               next_header_offset=len(S.Ether()) + len(S.Dot1Q()) + len(U.InjectUp()) + len(S.Ether()) + 2 * len(S.Dot1Q()),
               source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP, code=sdk.LA_EVENT_L3_USER_TRAP2,
               source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
               source_lp=T.RX_L3_AC_GID, destination_lp=sdk.LA_EVENT_L3_USER_TRAP2,
               relay_id=T.VRF_GID, lpts_flow_type=0
               ) / \
        INPUT_INJECT_UP_PACKET_BASE

    INPUT_PACKET_PxVx_2_BASE = \
        S.Ether(dst=PORT_PxVx_MAC.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=PORT_PxVx_VID1_2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL)

    CHANGE_VLAN_INPUT_PACKET_0_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=VID1_2, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=VID2_2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL)

    CHANGE_VLAN_INPUT_PACKET_1_BASE = \
        S.Ether(dst=PORT_MAC_ADDR.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=RX_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=DUMMY_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL)

    CHANGE_VLAN_INPUT_PACKET_2_BASE = \
        S.Ether(dst=PORT_MAC_ADDR.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=RX_AC_PORT_VID1_2, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=DUMMY_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL)

    SNOOP_PACKET_BASE = \
        Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=MIRROR_VLAN, type=U.Ethertype.Punt.value) / \
        U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
               next_header_offset=0,
               source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR, code=MIRROR_CMD_INGRESS_GID,
               source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
               source_lp=T.RX_L3_AC_GID, destination_lp=T.TX_L3_AC_REG_GID,
               relay_id=T.VRF_GID, lpts_flow_type=0
               ) / \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL)

    INPUT_PACKET_Px, PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_Px_BASE)
    INPUT_PACKET_PxVx = U.add_payload(INPUT_PACKET_PxVx_BASE, PAYLOAD_SIZE)
    INPUT_PACKET = U.add_payload(INPUT_PACKET_BASE, PAYLOAD_SIZE)
    INPUT_PACKET_VXLAN = U.add_payload(INPUT_PACKET_VXLAN_BASE, PAYLOAD_SIZE)
    INPUT_PACKET_DEF_RTE = U.add_payload(INPUT_PACKET_DEF_RTE_BASE, PAYLOAD_SIZE)
    INPUT_INJECT_UP_PACKET = U.add_payload(INPUT_INJECT_UP_PACKET_BASE, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_VXLAN = U.add_payload(EXPECTED_OUTPUT_PACKET_VXLAN_BASE, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_DEF_RTE = U.add_payload(EXPECTED_OUTPUT_PACKET_DEF_RTE_BASE, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_WITH_VLAN = U.add_payload(EXPECTED_OUTPUT_PACKET_WITH_VLAN_BASE, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_WITH_VLAN_VLAN = U.add_payload(EXPECTED_OUTPUT_PACKET_WITH_VLAN_VLAN_BASE, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_WITH_UPDATED_MAC = U.add_payload(EXPECTED_OUTPUT_PACKET_WITH_UPDATED_MAC_BASE, PAYLOAD_SIZE)
    EXPECTED_DEFAULT_OUTPUT_PACKET = U.add_payload(EXPECTED_DEFAULT_OUTPUT_PACKET_BASE, PAYLOAD_SIZE)
    EXPECTED_EXTRA_OUTPUT_PACKET = U.add_payload(EXPECTED_EXTRA_OUTPUT_PACKET_BASE, PAYLOAD_SIZE)
    PUNT_PACKET = U.add_payload(PUNT_PACKET_BASE, PAYLOAD_SIZE)
    PUNT_PACKET_L3_DROP_ADJ = U.add_payload(PUNT_PACKET_L3_DROP_ADJ_BASE, PAYLOAD_SIZE)
    PUNT_PACKET_L3_DROP_ADJ_NON_INJECT = U.add_payload(PUNT_PACKET_L3_DROP_ADJ_NON_INJECT_BASE, PAYLOAD_SIZE)
    PUNT_PACKET_L3_USER_TRAP1_ADJ = U.add_payload(PUNT_PACKET_L3_USER_TRAP1_ADJ_BASE, PAYLOAD_SIZE)
    PUNT_PACKET_L3_USER_TRAP2_ADJ = U.add_payload(PUNT_PACKET_L3_USER_TRAP2_ADJ_BASE, PAYLOAD_SIZE)
    INPUT_PACKET_PxVx_2 = U.add_payload(INPUT_PACKET_PxVx_2_BASE, PAYLOAD_SIZE)
    CHANGE_VLAN_INPUT_PACKET_0 = U.add_payload(CHANGE_VLAN_INPUT_PACKET_0_BASE, PAYLOAD_SIZE)
    CHANGE_VLAN_INPUT_PACKET_1 = U.add_payload(CHANGE_VLAN_INPUT_PACKET_1_BASE, PAYLOAD_SIZE)
    CHANGE_VLAN_INPUT_PACKET_2 = U.add_payload(CHANGE_VLAN_INPUT_PACKET_2_BASE, PAYLOAD_SIZE)
    SNOOP_PACKET = U.add_payload(SNOOP_PACKET_BASE, PAYLOAD_SIZE)
