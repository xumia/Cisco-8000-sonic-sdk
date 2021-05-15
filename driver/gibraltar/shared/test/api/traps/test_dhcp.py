#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import sim_utils
import topology as T

from traps_base import *
import decor

dhcp_da = 'fe:dc:ba:98:76:54'
dhcp_bcast_da = 'ff:ff:ff:ff:ff:ff'
dhcp_mcast_da = '01:00:5E:00:01:11'


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class TrapsDhcp(TrapsTest):

    # Setup
    def dhcp_setup(self):
        # configure DHCP v4/v6 server and client traps and configure ethernet port for the same
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER, 0, None, self.punt_dest, False, False, True, 0)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_CLIENT, 0, None, self.punt_dest, False, False, True, 0)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER, 0, None, self.punt_dest, False, False, True, 0)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV6_CLIENT, 0, None, self.punt_dest, False, False, True, 0)

        # set ethernet profile id on ethernet port
        udp_protocol = 0x11
        ethernet_profile_id = 1
        ipv4_l4_dhcp_server_dst_port = 0x43
        ipv4_l4_dhcp_client_dst_port = 0x44
        ipv6_l4_dhcp_server_dst_port = 0x223
        ipv6_l4_dhcp_client_dst_port = 0x222

        self.topology.rx_eth_port.hld_obj.set_copc_profile(ethernet_profile_id)

        # Set entries in copc_ipv4_table
        self.install_an_entry_in_copc_ipv4_table(
            udp_protocol,
            0xff,
            ipv4_l4_dhcp_server_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L3,
            0xff,
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER)
        self.install_an_entry_in_copc_ipv4_table(
            udp_protocol,
            0xff,
            ipv4_l4_dhcp_server_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            True,
            True,
            sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER)
        self.install_an_entry_in_copc_ipv4_table(
            udp_protocol,
            0xff,
            ipv4_l4_dhcp_server_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER)
        self.install_an_entry_in_copc_ipv4_table(
            udp_protocol,
            0xff,
            ipv4_l4_dhcp_client_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L3,
            0xff,
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV4_CLIENT)
        self.install_an_entry_in_copc_ipv4_table(
            udp_protocol,
            0xff,
            ipv4_l4_dhcp_client_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            True,
            True,
            sdk.LA_EVENT_ETHERNET_DHCPV4_CLIENT)
        self.install_an_entry_in_copc_ipv4_table(
            udp_protocol,
            0xff,
            ipv4_l4_dhcp_client_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER)
        # Set entries in copc_ipv6_table
        self.install_an_entry_in_copc_ipv6_table(
            udp_protocol,
            0xff,
            ipv6_l4_dhcp_server_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L3,
            0xff,
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER)
        self.install_an_entry_in_copc_ipv6_table(
            udp_protocol,
            0xff,
            ipv6_l4_dhcp_server_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            True,
            True,
            sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER)
        self.install_an_entry_in_copc_ipv6_table(
            udp_protocol,
            0xff,
            ipv6_l4_dhcp_server_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER)
        self.install_an_entry_in_copc_ipv6_table(
            udp_protocol,
            0xff,
            ipv6_l4_dhcp_client_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L3,
            0xff,
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV6_CLIENT)
        self.install_an_entry_in_copc_ipv6_table(
            udp_protocol,
            0xff,
            ipv6_l4_dhcp_client_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            True,
            True,
            sdk.LA_EVENT_ETHERNET_DHCPV6_CLIENT)
        self.install_an_entry_in_copc_ipv6_table(
            udp_protocol,
            0xff,
            ipv6_l4_dhcp_client_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER)

    # Teardown
    def dhcp_teardown(self):
        self.topology.rx_eth_port.hld_obj.set_copc_profile(0)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_CLIENT)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV6_CLIENT)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_dhcp_ipv4_server(self):
        # Pass an ipv4 DHCP unicast server packet over L3 AC port.
        # Pass an ipv4 DHCP broadcast server packet over L3 AC port.
        # Pass an ipv4 DHCP multicast server packet over L3 AC port.

        self.dhcp_setup()

        # DHCP IPv4 server unicast packet
        DHCP_PACKET_BASE = \
            S.Ether(dst=dhcp_da, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_ONE_TAG_PORT_VID) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            S.UDP(sport=0x44, dport=0x43) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        DHCP_PACKET, __ = U.enlarge_packet_to_min_length(DHCP_PACKET_BASE)

        PUNT_PACKET = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_L3_AC_ONE_TAG_GID,
                   destination_lp=sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER,
                   relay_id=self.PUNT_RELAY_ID,
                   lpts_flow_type=0) / DHCP_PACKET

        U.run_and_compare(self, self.device,
                          DHCP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # DHCP IPv4 server broadcast packet
        DHCP_PACKET_BASE = \
            S.Ether(dst=dhcp_bcast_da, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_ONE_TAG_PORT_VID) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            S.UDP(sport=0x44, dport=0x43) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        DHCP_PACKET, __ = U.enlarge_packet_to_min_length(DHCP_PACKET_BASE)

        PUNT_PACKET = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_L3_AC_ONE_TAG_GID,
                   destination_lp=sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER,
                   relay_id=self.PUNT_RELAY_ID,
                   lpts_flow_type=0) / DHCP_PACKET

        U.run_and_compare(self, self.device,
                          DHCP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # DHCP IPv4 server multicast packet
        DHCP_PACKET_BASE = \
            S.Ether(dst=dhcp_mcast_da, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_ONE_TAG_PORT_VID) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            S.UDP(sport=0x44, dport=0x43) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        DHCP_PACKET, __ = U.enlarge_packet_to_min_length(DHCP_PACKET_BASE)

        PUNT_PACKET = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_L3_AC_ONE_TAG_GID,
                   destination_lp=sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER,
                   relay_id=self.PUNT_RELAY_ID,
                   lpts_flow_type=0) / DHCP_PACKET

        U.run_and_compare(self, self.device,
                          DHCP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        self.dhcp_teardown()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_dhcp_ipv4_client(self):
        # Pass an ipv4 DHCP unicast client packet over L3 AC port.
        # Pass an ipv4 DHCP broadcast client packet over L3 AC port.
        # Pass an ipv4 DHCP multicast client packet over L3 AC port.
        self.dhcp_setup()

        # DHCP IPv4 client unicast packet
        DHCP_PACKET_BASE = \
            S.Ether(dst=dhcp_da, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_ONE_TAG_PORT_VID) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            S.UDP(sport=0x43, dport=0x44) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        DHCP_PACKET, __ = U.enlarge_packet_to_min_length(DHCP_PACKET_BASE)

        PUNT_PACKET = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_DHCPV4_CLIENT,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_L3_AC_ONE_TAG_GID,
                   destination_lp=sdk.LA_EVENT_ETHERNET_DHCPV4_CLIENT,
                   relay_id=self.PUNT_RELAY_ID,
                   lpts_flow_type=0) / DHCP_PACKET

        U.run_and_compare(self, self.device,
                          DHCP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # DHCP IPv4 client broadcast packet
        DHCP_PACKET_BASE = \
            S.Ether(dst=dhcp_bcast_da, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_ONE_TAG_PORT_VID) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            S.UDP(sport=0x43, dport=0x44) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        DHCP_PACKET, __ = U.enlarge_packet_to_min_length(DHCP_PACKET_BASE)

        PUNT_PACKET = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_DHCPV4_CLIENT,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_L3_AC_ONE_TAG_GID,
                   destination_lp=sdk.LA_EVENT_ETHERNET_DHCPV4_CLIENT,
                   relay_id=self.PUNT_RELAY_ID,
                   lpts_flow_type=0) / DHCP_PACKET

        U.run_and_compare(self, self.device,
                          DHCP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # DHCP IPv4 client multicast packet
        DHCP_PACKET_BASE = \
            S.Ether(dst=dhcp_mcast_da, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_ONE_TAG_PORT_VID) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            S.UDP(sport=0x43, dport=0x44) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        DHCP_PACKET, __ = U.enlarge_packet_to_min_length(DHCP_PACKET_BASE)

        PUNT_PACKET = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_DHCPV4_CLIENT,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_L3_AC_ONE_TAG_GID,
                   destination_lp=sdk.LA_EVENT_ETHERNET_DHCPV4_CLIENT,
                   relay_id=self.PUNT_RELAY_ID,
                   lpts_flow_type=0) / DHCP_PACKET

        U.run_and_compare(self, self.device,
                          DHCP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        self.dhcp_teardown()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_dhcp_ipv6_server(self):
        # Pass an ipv6 DHCP unicast server packet over L3 AC port.
        # Pass an ipv6 DHCP broadcast server packet over L3 AC port.
        # Pass an ipv6 DHCP multicast server packet over L3 AC port.
        self.dhcp_setup()

        # DHCP IPv6 server unicast packet
        DHCP_PACKET_BASE = \
            S.Ether(dst=dhcp_da, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_ONE_TAG_PORT_VID) / \
            S.IPv6(src=SIP6.addr_str, dst=DIP6.addr_str, hlim=TTL) / \
            S.UDP(sport=0x222, dport=0x223) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        DHCP_PACKET, __ = U.enlarge_packet_to_min_length(DHCP_PACKET_BASE)

        PUNT_PACKET = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_L3_AC_ONE_TAG_GID,
                   destination_lp=sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER,
                   relay_id=self.PUNT_RELAY_ID,
                   lpts_flow_type=0) / DHCP_PACKET

        U.run_and_compare(self, self.device,
                          DHCP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # DHCP IPv6 server broadcast packet
        DHCP_PACKET_BASE = \
            S.Ether(dst=dhcp_bcast_da, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_ONE_TAG_PORT_VID) / \
            S.IPv6(src=SIP6.addr_str, dst=DIP6.addr_str, hlim=TTL) / \
            S.UDP(sport=0x222, dport=0x223) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        DHCP_PACKET, __ = U.enlarge_packet_to_min_length(DHCP_PACKET_BASE)

        PUNT_PACKET = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_L3_AC_ONE_TAG_GID,
                   destination_lp=sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER,
                   relay_id=self.PUNT_RELAY_ID,
                   lpts_flow_type=0) / DHCP_PACKET

        U.run_and_compare(self, self.device,
                          DHCP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # DHCP IPv6 server multicast packet
        DHCP_PACKET_BASE = \
            S.Ether(dst=dhcp_mcast_da, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_ONE_TAG_PORT_VID) / \
            S.IPv6(src=SIP6.addr_str, dst=DIP6.addr_str, hlim=TTL) / \
            S.UDP(sport=0x222, dport=0x223) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        DHCP_PACKET, __ = U.enlarge_packet_to_min_length(DHCP_PACKET_BASE)

        PUNT_PACKET = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_L3_AC_ONE_TAG_GID,
                   destination_lp=sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER,
                   relay_id=self.PUNT_RELAY_ID,
                   lpts_flow_type=0) / DHCP_PACKET

        U.run_and_compare(self, self.device,
                          DHCP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        self.dhcp_teardown()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_dhcp_ipv6_client(self):
        # Pass an ipv6 DHCP unicast client packet over L3 AC port.
        # Pass an ipv6 DHCP broadcast client packet over L3 AC port.
        # Pass an ipv6 DHCP multicast client packet over L3 AC port.
        self.dhcp_setup()

        # DHCP IPv6 client unicast packet
        DHCP_PACKET_BASE = \
            S.Ether(dst=dhcp_da, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_ONE_TAG_PORT_VID) / \
            S.IPv6(src=SIP6.addr_str, dst=DIP6.addr_str, hlim=TTL) / \
            S.UDP(sport=0x223, dport=0x222) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        DHCP_PACKET, __ = U.enlarge_packet_to_min_length(DHCP_PACKET_BASE)

        PUNT_PACKET = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_DHCPV6_CLIENT,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_L3_AC_ONE_TAG_GID,
                   destination_lp=sdk.LA_EVENT_ETHERNET_DHCPV6_CLIENT,
                   relay_id=self.PUNT_RELAY_ID,
                   lpts_flow_type=0) / DHCP_PACKET

        U.run_and_compare(self, self.device,
                          DHCP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # DHCP IPv6 client broadcast packet
        DHCP_PACKET_BASE = \
            S.Ether(dst=dhcp_bcast_da, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_ONE_TAG_PORT_VID) / \
            S.IPv6(src=SIP6.addr_str, dst=DIP6.addr_str, hlim=TTL) / \
            S.UDP(sport=0x223, dport=0x222) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        DHCP_PACKET, __ = U.enlarge_packet_to_min_length(DHCP_PACKET_BASE)

        PUNT_PACKET = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_DHCPV6_CLIENT,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_L3_AC_ONE_TAG_GID,
                   destination_lp=sdk.LA_EVENT_ETHERNET_DHCPV6_CLIENT,
                   relay_id=self.PUNT_RELAY_ID,
                   lpts_flow_type=0) / DHCP_PACKET

        U.run_and_compare(self, self.device,
                          DHCP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # DHCP IPv6 client multicast packet
        DHCP_PACKET_BASE = \
            S.Ether(dst=dhcp_mcast_da, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_ONE_TAG_PORT_VID) / \
            S.IPv6(src=SIP6.addr_str, dst=DIP6.addr_str, hlim=TTL) / \
            S.UDP(sport=0x223, dport=0x222) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        DHCP_PACKET, __ = U.enlarge_packet_to_min_length(DHCP_PACKET_BASE)

        PUNT_PACKET = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_DHCPV6_CLIENT,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_L3_AC_ONE_TAG_GID,
                   destination_lp=sdk.LA_EVENT_ETHERNET_DHCPV6_CLIENT,
                   relay_id=self.PUNT_RELAY_ID,
                   lpts_flow_type=0) / DHCP_PACKET

        U.run_and_compare(self, self.device,
                          DHCP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        self.dhcp_teardown()


if __name__ == '__main__':
    unittest.main()
