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


class ipv6_l3_ac_routing_base(ip_routing_base):
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl = ip_test_base.ipv6_test_base
    SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')
    DIP0 = T.ipv6_addr('1111:0d00:0a0b:12f0:0000:0000:0000:1111')
    DIP255 = T.ipv6_addr('1111:0dff:0a0b:12f0:0000:0000:0000:1111')
    DIP_DEF_RTE = T.ipv6_addr('3333:0db8:0a0b:12f0:0000:0000:0000:3333')
    PORT_Px_MAC = T.mac_addr('01:01:01:01:01:01')
    PORT_Px_GID = 0x111
    PORT_PxVx_GID = 0x222
    PORT_PxVx_VID1_2 = 0x44
    PORT_PxVx_VID1 = 0x4
    PORT_PxVx_MAC = T.mac_addr('00:02:02:02:02:02')
    SUBNETS_HOSTS = {}
    i = 2
    for str in [
        '1111:0db8:0a0b:12f0:0000:0000:0000:1111',
        '2222:0db8:0a0b:12f0:0000:0000:0000:2222',
        '3333:0db8:0a0b:12f0:0000:0000:0000:3333',
            '4444:0db8:0a0b:12f0:0000:0000:0000:4444']:
        dip = T.ipv6_addr(str)
        host = T.mac_addr('0%d:0%d:0%d:0%d:0%d:0%d' % (i, i, i, i, i, i))
        SUBNETS_HOSTS[dip] = host

    INPUT_PACKET_Px_BASE = \
        S.Ether(dst=PORT_Px_MAC.addr_str, src=ip_routing_base.SA.addr_str) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=ip_routing_base.TTL, plen=40)

    INPUT_PACKET_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=ip_routing_base.TTL, plen=40)

    INPUT_PACKET_DEF_RTE_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IPv6(src=SIP.addr_str, dst=DIP_DEF_RTE.addr_str, hlim=ip_routing_base.TTL, plen=40)

    EXPECTED_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=ip_routing_base.TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_DEF_RTE_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IPv6(src=SIP.addr_str, dst=DIP_DEF_RTE.addr_str, hlim=ip_routing_base.TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_WITH_VLAN_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=ip_routing_base.OUTPUT_VID) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=ip_routing_base.TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_WITH_UPDATED_MAC_BASE = \
        S.Ether(dst=NH_MAC_MODIFIED.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=ip_routing_base.TTL - 1, plen=40)

    EXPECTED_DEFAULT_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=ip_routing_base.TTL - 1, plen=40)

    EXPECTED_EXTRA_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=ip_routing_base.TTL - 1, plen=40)

    PUNT_PACKET_BASE = \
        S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
        U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6,
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
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=ip_routing_base.TTL, plen=40)

    SNOOP_PACKET_BASE = \
        Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=MIRROR_VLAN, type=U.Ethertype.Punt.value) / \
        U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV6, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6,
               next_header_offset=0,
               source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR, code=MIRROR_CMD_INGRESS_GID,
               source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
               source_lp=T.RX_L3_AC_GID, destination_lp=T.TX_L3_AC_REG_GID,
               relay_id=T.VRF_GID, lpts_flow_type=0
               ) / \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=ip_routing_base.TTL, plen=40)

    INPUT_PACKET_PxVx_BASE = \
        S.Ether(dst=PORT_PxVx_MAC.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=PORT_PxVx_VID1) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=ip_routing_base.TTL, plen=40)

    INPUT_PACKET_PxVx_2_BASE = \
        S.Ether(dst=PORT_PxVx_MAC.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=PORT_PxVx_VID1_2) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=ip_routing_base.TTL, plen=40)

    CHANGE_VLAN_INPUT_PACKET_0_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=VID1_2, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=VID2_2) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=ip_routing_base.TTL, plen=40)

    CHANGE_VLAN_INPUT_PACKET_1_BASE = \
        S.Ether(dst=PORT_MAC_ADDR.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=RX_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=DUMMY_VID2) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=ip_routing_base.TTL, plen=40)

    CHANGE_VLAN_INPUT_PACKET_2_BASE = \
        S.Ether(dst=PORT_MAC_ADDR.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=RX_AC_PORT_VID1_2, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=DUMMY_VID2) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=ip_routing_base.TTL, plen=40)

    INPUT_PACKET_Px, PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_Px_BASE)
    INPUT_PACKET = U.add_payload(INPUT_PACKET_BASE, PAYLOAD_SIZE)
    INPUT_PACKET_DEF_RTE = U.add_payload(INPUT_PACKET_DEF_RTE_BASE, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_DEF_RTE = U.add_payload(EXPECTED_OUTPUT_PACKET_DEF_RTE_BASE, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_WITH_VLAN = U.add_payload(EXPECTED_OUTPUT_PACKET_WITH_VLAN_BASE, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_WITH_UPDATED_MAC = U.add_payload(EXPECTED_OUTPUT_PACKET_WITH_UPDATED_MAC_BASE, PAYLOAD_SIZE)
    EXPECTED_DEFAULT_OUTPUT_PACKET = U.add_payload(EXPECTED_DEFAULT_OUTPUT_PACKET_BASE, PAYLOAD_SIZE)
    EXPECTED_EXTRA_OUTPUT_PACKET = U.add_payload(EXPECTED_EXTRA_OUTPUT_PACKET_BASE, PAYLOAD_SIZE)
    PUNT_PACKET = U.add_payload(PUNT_PACKET_BASE, PAYLOAD_SIZE)
    SNOOP_PACKET = U.add_payload(SNOOP_PACKET_BASE, PAYLOAD_SIZE)
    INPUT_PACKET_PxVx = U.add_payload(INPUT_PACKET_PxVx_BASE, PAYLOAD_SIZE)
    INPUT_PACKET_PxVx_2 = U.add_payload(INPUT_PACKET_PxVx_2_BASE, PAYLOAD_SIZE)
    CHANGE_VLAN_INPUT_PACKET_0 = U.add_payload(CHANGE_VLAN_INPUT_PACKET_0_BASE, PAYLOAD_SIZE)
    CHANGE_VLAN_INPUT_PACKET_1 = U.add_payload(CHANGE_VLAN_INPUT_PACKET_1_BASE, PAYLOAD_SIZE)
    CHANGE_VLAN_INPUT_PACKET_2 = U.add_payload(CHANGE_VLAN_INPUT_PACKET_2_BASE, PAYLOAD_SIZE)
