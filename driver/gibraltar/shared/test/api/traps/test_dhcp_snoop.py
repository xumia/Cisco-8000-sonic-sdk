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

import decor
import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import sim_utils
import topology as T
import nplapicli as nplapi

from traps_base import *

DA_BCAST = T.mac_addr('ff:ff:ff:ff:ff:ff')
BCAST_DIP = T.ipv4_addr('255.255.255.255')
MCAST_DIP6_1 = T.ipv6_addr('ff02:0000:0000:0000:0000:0000:0001:0002')
MCAST_DIP6_2 = T.ipv6_addr('ff05:0000:0000:0000:0000:0000:0001:0003')
MCAST_DIP6 = T.ipv6_addr('ff00:0000:0000:0000:0000:0000:0000:0000')
MCAST_DIP6_MASK = T.ipv6_addr('fff0:0000:0000:0000:0000:0000:fff0:0000')

MIRROR_CMD_GID = 9

MIRROR_GID_INGRESS_OFFSET = 32
MIRROR_GID_EGRESS_OFFSET = 0
MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class TrapsDhcp_Snoop(TrapsTest):

    def dhcp_setup(self):
        sampling_rate = 1.0
        HOST_MAC_ADDR1 = T.mac_addr('cd:cd:cd:cd:cd:cd')
        mirror_cmd = T.create_l2_mirror_command(
            self.device,
            MIRROR_CMD_INGRESS_GID,
            self.pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN,
            sampling_rate)

        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_CLIENT)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV6_CLIENT)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT)
        self.device.set_snoop_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER, 0, False, False, mirror_cmd)
        self.device.set_snoop_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_CLIENT, 0, False, False, mirror_cmd)
        self.device.set_snoop_configuration(sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER, 0, False, False, mirror_cmd)
        self.device.set_snoop_configuration(sdk.LA_EVENT_ETHERNET_DHCPV6_CLIENT, 0, False, False, mirror_cmd)

        udp_protocol = 0x11
        ethernet_profile_id = 0
        ipv4_l4_dhcp_server_dst_port = 0x43
        ipv4_l4_dhcp_client_dst_port = 0x44
        ipv6_l4_dhcp_server_dst_port = 0x223
        ipv6_l4_dhcp_client_dst_port = 0x222

        # Set entries in copc_ipv4_table
        self.install_an_entry_in_copc_ipv4_table(
            udp_protocol,
            0xff,
            ipv4_l4_dhcp_server_dst_port,
            0xffff,
            ethernet_profile_id,
            0x0,
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
            0x0,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
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
            0x0,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            True,
            True,
            sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER,
            BCAST_DIP,
            BCAST_DIP)
        self.install_an_entry_in_copc_ipv4_table(
            udp_protocol,
            0xff,
            ipv4_l4_dhcp_client_dst_port,
            0xffff,
            ethernet_profile_id,
            0x0,
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
            0x0,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
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
            0x0,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            True,
            True,
            sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER,
            BCAST_DIP,
            BCAST_DIP)

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
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER)
        self.install_an_entry_in_copc_ipv6_table(
            udp_protocol,
            0xff,
            ipv6_l4_dhcp_server_dst_port,
            0xffff,
            ethernet_profile_id,
            0x00,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            True,
            True,
            sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER,
            MCAST_DIP6,
            MCAST_DIP6_MASK)
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
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV6_CLIENT)
        self.install_an_entry_in_copc_ipv6_table(
            udp_protocol,
            0xff,
            ipv6_l4_dhcp_client_dst_port,
            0xffff,
            ethernet_profile_id,
            0x00,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            True,
            True,
            sdk.LA_EVENT_ETHERNET_DHCPV6_CLIENT,
            MCAST_DIP6,
            MCAST_DIP6_MASK)

    def dhcp_teardown(self):
        self.device.clear_snoop_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER)
        self.device.clear_snoop_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_CLIENT)
        self.device.clear_snoop_configuration(sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER)
        self.device.clear_snoop_configuration(sdk.LA_EVENT_ETHERNET_DHCPV6_CLIENT)
        self.clear_entries_from_copc_ipv4_table()
        self.clear_entries_from_copc_ipv6_table()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_dhcp_ipv4_server(self):
        '''
           Pass an DHCP packet over L3 AC port.
        '''
        self.dhcp_setup()

        # DHCP IPv4 server - L3 unicast
        INPUT_PACKET_BASE = \
            S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            S.UDP(sport=0x44, dport=0x43) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        PUNT_PACKET = S.Ether(dst=HOST_MAC_ADDR,
                              src=PUNT_INJECT_PORT_MAC_ADDR,
                              type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                      id=0,
                                                                      vlan=PUNT_VLAN,
                                                                      type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                            fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_REDIRECT,
                                                                                                            next_header_offset=0,
                                                                                                            source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                            code=MIRROR_CMD_INGRESS_GID,
                                                                                                            source_sp=T.RX_SYS_PORT_GID,
                                                                                                            destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                            source_lp=T.RX_L3_AC_GID,
                                                                                                            # destination_lp=sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT,
                                                                                                            destination_lp = sdk.LA_EVENT_L3_LPM_DROP,
                                                                                                            relay_id=T.VRF_GID,
                                                                                                            lpts_flow_type=0) / INPUT_PACKET

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # DHCP IPv4 server - SVI unicast
        INPUT_PACKET_BASE = \
            S.Ether(dst=T.RX_SVI_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            S.UDP(sport=0x44, dport=0x43) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        PUNT_PACKET = S.Ether(dst=HOST_MAC_ADDR,
                              src=PUNT_INJECT_PORT_MAC_ADDR,
                              type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                      id=0,
                                                                      vlan=PUNT_VLAN,
                                                                      type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                            fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_REDIRECT,
                                                                                                            next_header_offset=0,
                                                                                                            source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                            code=MIRROR_CMD_INGRESS_GID,
                                                                                                            source_sp=T.RX_SYS_PORT_GID,
                                                                                                            destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                            source_lp=T.RX_SVI_GID,
                                                                                                            destination_lp = sdk.LA_EVENT_L3_LPM_DROP,
                                                                                                            relay_id=T.VRF_GID,
                                                                                                            lpts_flow_type=0) / INPUT_PACKET

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # DHCP IPv4 server - SVI broadcast
        INPUT_PACKET_BASE = \
            S.Ether(dst=DA_BCAST.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IP(src=SIP.addr_str, dst=BCAST_DIP.addr_str, ttl=TTL) / \
            S.UDP(sport=0x44, dport=0x43) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        PUNT_PACKET = S.Ether(dst=HOST_MAC_ADDR,
                              src=PUNT_INJECT_PORT_MAC_ADDR,
                              type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                      id=0,
                                                                      vlan=PUNT_VLAN,
                                                                      type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                            fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                            next_header_offset=0,
                                                                                                            source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                            code=MIRROR_CMD_INGRESS_GID,
                                                                                                            source_sp=T.RX_SYS_PORT_GID,
                                                                                                            destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                            source_lp=T.RX_L2_AC_PORT_GID | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                                                                                                            destination_lp = 0,
                                                                                                            relay_id=T.RX_SWITCH_GID,
                                                                                                            lpts_flow_type=0) / INPUT_PACKET

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        self.dhcp_teardown()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_dhcp_ipv4_client(self):
        self.dhcp_setup()
        # DHCP IPv4 client - L3 unicast
        INPUT_PACKET_BASE = \
            S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            S.UDP(sport=0x43, dport=0x44) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        PUNT_PACKET = S.Ether(dst=HOST_MAC_ADDR,
                              src=PUNT_INJECT_PORT_MAC_ADDR,
                              type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                      id=0,
                                                                      vlan=PUNT_VLAN,
                                                                      type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                            fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_REDIRECT,
                                                                                                            next_header_offset=0,
                                                                                                            source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                            code=MIRROR_CMD_INGRESS_GID,
                                                                                                            source_sp=T.RX_SYS_PORT_GID,
                                                                                                            destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                            source_lp=T.RX_L3_AC_GID,
                                                                                                            # destination_lp=sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT,
                                                                                                            destination_lp = sdk.LA_EVENT_L3_LPM_DROP,
                                                                                                            relay_id=T.VRF_GID,
                                                                                                            lpts_flow_type=0) / INPUT_PACKET

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # DHCP IPv4 client - SVI unicast
        INPUT_PACKET_BASE = \
            S.Ether(dst=T.RX_SVI_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            S.UDP(sport=0x43, dport=0x44) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        PUNT_PACKET = S.Ether(dst=HOST_MAC_ADDR,
                              src=PUNT_INJECT_PORT_MAC_ADDR,
                              type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                      id=0,
                                                                      vlan=PUNT_VLAN,
                                                                      type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                            fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_REDIRECT,
                                                                                                            next_header_offset=0,
                                                                                                            source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                            code=MIRROR_CMD_INGRESS_GID,
                                                                                                            source_sp=T.RX_SYS_PORT_GID,
                                                                                                            destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                            source_lp=T.RX_SVI_GID,
                                                                                                            destination_lp = sdk.LA_EVENT_L3_LPM_DROP,
                                                                                                            relay_id=T.VRF_GID,
                                                                                                            lpts_flow_type=0) / INPUT_PACKET

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # DHCP IPv4 client - SVI broadcast
        INPUT_PACKET_BASE = \
            S.Ether(dst=DA_BCAST.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IP(src=SIP.addr_str, dst=BCAST_DIP.addr_str, ttl=TTL) / \
            S.UDP(sport=0x43, dport=0x43) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        PUNT_PACKET = S.Ether(dst=HOST_MAC_ADDR,
                              src=PUNT_INJECT_PORT_MAC_ADDR,
                              type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                      id=0,
                                                                      vlan=PUNT_VLAN,
                                                                      type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                            fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                            next_header_offset=0,
                                                                                                            source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                            code=MIRROR_CMD_INGRESS_GID,
                                                                                                            source_sp=T.RX_SYS_PORT_GID,
                                                                                                            destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                            source_lp=T.RX_L2_AC_PORT_GID | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                                                                                                            destination_lp = 0,
                                                                                                            relay_id=T.RX_SWITCH_GID,
                                                                                                            lpts_flow_type=0) / INPUT_PACKET

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)
        self.dhcp_teardown()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_dhcp_ipv6_server(self):
        self.dhcp_setup()
        # DHCP IPv6 server - L3 unicast
        INPUT_PACKET_BASE = \
            S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.IPv6(src=SIP6.addr_str, dst=DIP6.addr_str, hlim=TTL) / \
            S.UDP(sport=0x222, dport=0x223) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        PUNT_PACKET = S.Ether(dst=HOST_MAC_ADDR,
                              src=PUNT_INJECT_PORT_MAC_ADDR,
                              type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                      id=0,
                                                                      vlan=PUNT_VLAN,
                                                                      type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                            fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_REDIRECT,
                                                                                                            next_header_offset=0,
                                                                                                            source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                            code=MIRROR_CMD_INGRESS_GID,
                                                                                                            source_sp=T.RX_SYS_PORT_GID,
                                                                                                            destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                            source_lp=T.RX_L3_AC_GID,
                                                                                                            # destination_lp=sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT,
                                                                                                            destination_lp = sdk.LA_EVENT_L3_LPM_DROP,
                                                                                                            relay_id=T.VRF_GID,
                                                                                                            lpts_flow_type=0) / INPUT_PACKET

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # DHCP IPv6 server - SVI unicast
        INPUT_PACKET_BASE = \
            S.Ether(dst=T.RX_SVI_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IPv6(src=SIP6.addr_str, dst=DIP6.addr_str, hlim=TTL) / \
            S.UDP(sport=0x222, dport=0x223) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        PUNT_PACKET = S.Ether(dst=HOST_MAC_ADDR,
                              src=PUNT_INJECT_PORT_MAC_ADDR,
                              type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                      id=0,
                                                                      vlan=PUNT_VLAN,
                                                                      type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                            fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_REDIRECT,
                                                                                                            next_header_offset=0,
                                                                                                            source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                            code=MIRROR_CMD_INGRESS_GID,
                                                                                                            source_sp=T.RX_SYS_PORT_GID,
                                                                                                            destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                            source_lp=T.RX_SVI_GID,
                                                                                                            destination_lp = sdk.LA_EVENT_L3_LPM_DROP,
                                                                                                            relay_id=T.VRF_GID,
                                                                                                            lpts_flow_type=0) / INPUT_PACKET

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # DHCP IPv6 server - SVI multicast
        INPUT_PACKET_BASE = \
            S.Ether(dst=DA_BCAST.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IPv6(src=SIP6.addr_str, dst=MCAST_DIP6_1.addr_str, hlim=TTL) / \
            S.UDP(sport=0x222, dport=0x223) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        PUNT_PACKET = S.Ether(dst=HOST_MAC_ADDR,
                              src=PUNT_INJECT_PORT_MAC_ADDR,
                              type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                      id=0,
                                                                      vlan=PUNT_VLAN,
                                                                      type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                            fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                            next_header_offset=0,
                                                                                                            source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                            code=MIRROR_CMD_INGRESS_GID,
                                                                                                            source_sp=T.RX_SYS_PORT_GID,
                                                                                                            destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                            source_lp=T.RX_L2_AC_PORT_GID | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                                                                                                            destination_lp = 0,
                                                                                                            relay_id=T.RX_SWITCH_GID,
                                                                                                            lpts_flow_type=0) / INPUT_PACKET

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # DHCP IPv6 server - SVI multicast
        INPUT_PACKET_BASE = \
            S.Ether(dst=DA_BCAST.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IPv6(src=SIP6.addr_str, dst=MCAST_DIP6_2.addr_str, hlim=TTL) / \
            S.UDP(sport=0x222, dport=0x223) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        PUNT_PACKET = S.Ether(dst=HOST_MAC_ADDR,
                              src=PUNT_INJECT_PORT_MAC_ADDR,
                              type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                      id=0,
                                                                      vlan=PUNT_VLAN,
                                                                      type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                            fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                            next_header_offset=0,
                                                                                                            source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                            code=MIRROR_CMD_INGRESS_GID,
                                                                                                            source_sp=T.RX_SYS_PORT_GID,
                                                                                                            destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                            source_lp=T.RX_L2_AC_PORT_GID | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                                                                                                            destination_lp = 0,
                                                                                                            relay_id=T.RX_SWITCH_GID,
                                                                                                            lpts_flow_type=0) / INPUT_PACKET

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)
        self.dhcp_teardown()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_dhcp_ipv6_client(self):
        self.dhcp_setup()
        # DHCP IPv6 client - L3 unicast
        INPUT_PACKET_BASE = \
            S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.IPv6(src=SIP6.addr_str, dst=DIP6.addr_str, hlim=TTL) / \
            S.UDP(sport=0x223, dport=0x222) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        PUNT_PACKET = S.Ether(dst=HOST_MAC_ADDR,
                              src=PUNT_INJECT_PORT_MAC_ADDR,
                              type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                      id=0,
                                                                      vlan=PUNT_VLAN,
                                                                      type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                            fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_REDIRECT,
                                                                                                            next_header_offset=0,
                                                                                                            source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                            code=MIRROR_CMD_INGRESS_GID,
                                                                                                            source_sp=T.RX_SYS_PORT_GID,
                                                                                                            destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                            source_lp=T.RX_L3_AC_GID,
                                                                                                            # destination_lp=sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT,
                                                                                                            destination_lp = sdk.LA_EVENT_L3_LPM_DROP,
                                                                                                            relay_id=T.VRF_GID,
                                                                                                            lpts_flow_type=0) / INPUT_PACKET

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # DHCP IPv6 client - SVI unicast
        INPUT_PACKET_BASE = \
            S.Ether(dst=T.RX_SVI_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IPv6(src=SIP6.addr_str, dst=DIP6.addr_str, hlim=TTL) / \
            S.UDP(sport=0x223, dport=0x222) / \
            S.BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304) / \
            S.DHCP(options=[("message-type", "discover"), "end"])
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        PUNT_PACKET = S.Ether(dst=HOST_MAC_ADDR,
                              src=PUNT_INJECT_PORT_MAC_ADDR,
                              type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                      id=0,
                                                                      vlan=PUNT_VLAN,
                                                                      type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                            fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_REDIRECT,
                                                                                                            next_header_offset=0,
                                                                                                            source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                            code=MIRROR_CMD_INGRESS_GID,
                                                                                                            source_sp=T.RX_SYS_PORT_GID,
                                                                                                            destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                            source_lp=T.RX_SVI_GID,
                                                                                                            destination_lp = sdk.LA_EVENT_L3_LPM_DROP,
                                                                                                            relay_id=T.VRF_GID,
                                                                                                            lpts_flow_type=0) / INPUT_PACKET

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)
        self.dhcp_teardown()


if __name__ == '__main__':
    unittest.main()
