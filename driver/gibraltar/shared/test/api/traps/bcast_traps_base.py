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
from sdk_test_case_base import *
import smart_slices_choise as ssch
import decor

PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
DONT_CARE_MAC = "00:00:00:00:00:00"

SYS_PORT_GID_BASE = 23
IN_SP_GID = SYS_PORT_GID_BASE
OUT_SP_GID = SYS_PORT_GID_BASE + 1

PUNT_VLAN = 0xA13
PUNT_RELAY_ID = 0 if decor.is_pacific() else T.VRF_GID

MIRROR_CMD_GID = 9
MIRROR_VLAN = 0xA12

MIRROR_GID_INGRESS_OFFSET = 32
MIRROR_GID_EGRESS_OFFSET = 0
MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET
ARP_ETHER_TYPE = 0x0806


class bcast_traps_base(sdk_test_case_base):

    PI_SLICE = 3
    PI_IFG = 1
    PI_PIF_FIRST = 8
    PI_SP_GID = SYS_PORT_GID_BASE + 2

    SA = T.mac_addr('be:ef:5d:35:7a:30')
    DA = T.mac_addr('ff:ff:ff:ff:ff:ff')
    SIP = T.ipv4_addr('12.10.12.10')
    DIP_BC = T.ipv4_addr('255.255.255.255')
    DIP_UC = T.ipv4_addr('12.10.12.11')

    L2_BC_PACKET = \
        S.Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2)

    V4_BC_PACKET = \
        L2_BC_PACKET / \
        S.IP(src=SIP.addr_str, dst=DIP_BC.addr_str, ttl=1) / \
        S.UDP(sport=520, dport=520) / RIP(version=1)

    V4_UC_PACKET = \
        L2_BC_PACKET / \
        S.IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=1) / \
        S.UDP(sport=520, dport=520) / RIP(version=1)

    ARP_BC_PACKET = L2_BC_PACKET / S.ARP(op='who-has')

    punt_hdr = S.Ether(dst=HOST_MAC_ADDR,
                       src=PUNT_INJECT_PORT_MAC_ADDR,
                       type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                               id=0,
                                                               vlan=PUNT_VLAN,
                                                               type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                     fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                     next_header_offset=0,
                                                                                                     source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                                                                                                     code=sdk.LA_EVENT_ETHERNET_BCAST_PKT,
                                                                                                     source_sp=T.RX_SYS_PORT_GID,
                                                                                                     destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                     source_lp=T.RX_L3_AC_GID,
                                                                                                     # destination_lp=sdk.la_packet_types.LA_L3_LOGICAL_PORT_GID_INVALID,
                                                                                                     destination_lp=sdk.LA_EVENT_ETHERNET_BCAST_PKT,
                                                                                                     relay_id=PUNT_RELAY_ID,
                                                                                                     lpts_flow_type=0)

    snoop_hdr = S.Ether(dst=HOST_MAC_ADDR,
                        src=PUNT_INJECT_PORT_MAC_ADDR,
                        type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                id=0,
                                                                vlan=MIRROR_VLAN,
                                                                type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                      fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_REDIRECT,
                                                                                                      next_header_offset=0,
                                                                                                      source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                      code=MIRROR_CMD_INGRESS_GID,
                                                                                                      source_sp=T.RX_SYS_PORT_GID,
                                                                                                      destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                      source_lp=T.RX_L3_AC_GID,
                                                                                                      # destination_lp=sdk.la_packet_types.LA_L3_LOGICAL_PORT_GID_INVALID,
                                                                                                      destination_lp=sdk.LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT,
                                                                                                      relay_id=PUNT_RELAY_ID,
                                                                                                      lpts_flow_type=0)

    PUNT_V4_BC_PACKET = punt_hdr / V4_BC_PACKET
    PUNT_V4_UC_PACKET = punt_hdr / V4_UC_PACKET
    PUNT_ARP_BC_PACKET = punt_hdr / ARP_BC_PACKET
    PUNT_L2_BC_PACKET = punt_hdr / L2_BC_PACKET

    V4_BC_PACKET, PUNT_V4_BC_PACKET = U.pad_input_and_output_packets(V4_BC_PACKET, PUNT_V4_BC_PACKET)
    V4_UC_PACKET, PUNT_V4_UC_PACKET = U.pad_input_and_output_packets(V4_UC_PACKET, PUNT_V4_UC_PACKET)
    ARP_BC_PACKET, PUNT_ARP_BC_PACKET = U.pad_input_and_output_packets(ARP_BC_PACKET, PUNT_ARP_BC_PACKET)
    L2_BC_PACKET, PUNT_L2_BC_PACKET = U.pad_input_and_output_packets(L2_BC_PACKET, PUNT_L2_BC_PACKET)

    SNOOP_V4_BC_PACKET = snoop_hdr / V4_BC_PACKET
    SNOOP_V4_UC_PACKET = snoop_hdr / V4_UC_PACKET
    SNOOP_ARP_BC_PACKET = snoop_hdr / ARP_BC_PACKET
    SNOOP_L2_BC_PACKET = snoop_hdr / L2_BC_PACKET

    V4_BC_PACKET, SNOOP_V4_BC_PACKET = U.pad_input_and_output_packets(V4_BC_PACKET, SNOOP_V4_BC_PACKET)
    V4_UC_PACKET, SNOOP_V4_UC_PACKET = U.pad_input_and_output_packets(V4_UC_PACKET, SNOOP_V4_UC_PACKET)
    ARP_BC_PACKET, SNOOP_ARP_BC_PACKET = U.pad_input_and_output_packets(ARP_BC_PACKET, SNOOP_ARP_BC_PACKET)
    L2_BC_PACKET, SNOOP_L2_BC_PACKET = U.pad_input_and_output_packets(L2_BC_PACKET, SNOOP_L2_BC_PACKET)

    def setUp(self):
        super().setUp()
        ssch.rechoose_PI_slices(self, self.device)
        # setup inject port
        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            self.PI_SLICE,
            self.PI_IFG,
            self.PI_SP_GID,
            self.PI_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        self.punt_dest = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            self.pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN)

        self.copc_mac = self.device.create_copc(sdk.la_control_plane_classifier.type_e_MAC)
        self.copc_ipv4 = self.device.create_copc(sdk.la_control_plane_classifier.type_e_IPV4)

    def tearDown(self):
        super().tearDown()

    def install_an_entry_in_copc_mac_table(
            self,
            ether_value,
            ether_mask,
            mac_da_value,
            event,
            mac_da_mask=T.mac_addr('ff:ff:ff:ff:ff:ff'),
            npp_attribute=0x0,
            mac_lp_type_value=0x0,
            mac_lp_type_mask=0x0):

        key1 = []
        f1 = sdk.field()
        f1.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_ETHERNET_PROFILE_ID
        f1.val.mac.ethernet_profile_id = npp_attribute
        f1.mask.mac.ethernet_profile_id = npp_attribute
        key1.append(f1)

        f2 = sdk.field()
        f2.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_DA
        f2.val.mac.da = mac_da_value.hld_obj
        f2.mask.mac.da = mac_da_mask.hld_obj
        key1.append(f2)

        f3 = sdk.field()
        f3.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_ETHERTYPE
        f3.val.mac.ethertype = ether_value
        f3.mask.mac.ethertype = ether_mask
        key1.append(f3)

        f4 = sdk.field()
        f4.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_LP_TYPE
        f4.val.mac.lp_type = mac_lp_type_value
        f4.mask.mac.lp_type = mac_lp_type_mask
        key1.append(f4)

        result1 = sdk.result()
        result1.event = event

        self.copc_mac.append(key1, result1)

    def clear_entries_from_copc_mac_table(self):
        self.copc_mac.clear()
