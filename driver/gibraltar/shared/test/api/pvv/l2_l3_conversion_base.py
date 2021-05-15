#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import ip_test_base
import packet_test_utils as U
import scapy.all as S
import sim_utils
import topology as T
from sdk_test_case_base import *
import decor

SYS_PORT_GID = 23
L2_AC_PORT_GID = 0x42
L3_AC_PORT_GID = 0x32

VRF_GID = 0x1 if not decor.is_gibraltar() else 0xF00
SWITCH_GID = 100
MC_GROUP_GID = 0x13

L3_AC_PORT_MAC_ADDR = T.mac_addr('44:33:44:33:44:33')
L3_AC_PORT_MAC_ADDR2 = T.mac_addr('45:33:45:33:45:33')
DST_MAC = "ca:fe:ca:fe:ca:fe"
SRC_MAC = "de:ad:de:ad:de:ad"

VID1 = 0xAB9
VID2 = 0xABA

IN_SLICE = T.get_device_slice(2)
IN_IFG = 0
IN_SERDES_FIRST = 4
IN_SERDES_LAST = IN_SERDES_FIRST + 1
OUT_SLICE = T.get_device_slice(1)
OUT_IFG = 1
OUT_SERDES_FIRST = 8
OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

OUT_SLICE1 = T.get_device_slice(0)
OUT_IFG1 = 1
OUT_SERDES_FIRST1 = 8
OUT_SERDES_LAST1 = OUT_SERDES_FIRST1 + 1

DST_MAC = "ca:fe:ca:fe:ca:fe"
SRC_MAC = "de:ad:de:ad:de:ad"

TTL = 128
SA = T.mac_addr('be:ef:5d:35:7a:35')
SIP = T.ipv4_addr('12.10.12.10')
DIP = T.ipv4_addr('82.81.95.250')
NH_L3_AC_GID = 0x111
NH_L3_AC_MAC = T.mac_addr('80:82:83:84:85:86')


PRIVATE_DATA = 0x1234567890abcdef


class l2_l3_conversion_base(sdk_test_case_base):

    def setUp(self):

        super().setUp()
        self.maxDiff = None  # Show whole strings on failures (unittest variable)

        self.ac_profile = T.ac_profile(self, self.device)
        self.eth_port = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, SYS_PORT_GID, IN_SERDES_FIRST, IN_SERDES_LAST)
        self.eth_port.set_ac_profile(self.ac_profile)

        self.eth_port1 = T.ethernet_port(self, self.device, OUT_SLICE, OUT_IFG,
                                         SYS_PORT_GID + 1, OUT_SERDES_FIRST, OUT_SERDES_LAST)
        self.eth_port1.set_ac_profile(self.ac_profile)

        self.eth_port2 = T.ethernet_port(self, self.device, OUT_SLICE1, OUT_IFG1,
                                         SYS_PORT_GID + 2, OUT_SERDES_FIRST1, OUT_SERDES_LAST1)
        self.eth_port2.set_ac_profile(self.ac_profile)

        self.vrf = T.vrf(self, self.device, VRF_GID)
        self.sw1 = T.switch(self, self.device, SWITCH_GID)

    def create_l2_topology(self, mc=False):
        # Create L2 port over eth_port and eth_port1 with (VID1,0)
        self.rx_l2_ac = T.l2_ac_port(self, self.device, L2_AC_PORT_GID,
                                     self.topology.filter_group_def,
                                     None,
                                     self.eth_port,
                                     None,
                                     VID1,
                                     0)
        self.tx_l2_ac = T.l2_ac_port(self, self.device, L2_AC_PORT_GID + 1,
                                     self.topology.filter_group_def,
                                     None,
                                     self.eth_port1,
                                     None,
                                     VID1,
                                     0)
        self.tx_l2_ac_1 = T.l2_ac_port(self, self.device, L2_AC_PORT_GID + 2,
                                       self.topology.filter_group_def,
                                       None,
                                       self.eth_port2,
                                       None,
                                       VID1,
                                       0)

        self.rx_l2_ac.hld_obj.attach_to_switch(self.sw1.hld_obj)
        self.tx_l2_ac.hld_obj.attach_to_switch(self.sw1.hld_obj)
        self.tx_l2_ac_1.hld_obj.attach_to_switch(self.sw1.hld_obj)

        if not mc:
            dest_mac = T.mac_addr(DST_MAC)
            self.sw1.hld_obj.set_mac_entry(dest_mac.hld_obj, self.tx_l2_ac.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        self.create_l2_packets()

    def create_l2_packets(self):
        # Create Packets
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=U.Ethertype.Dot1Q.value) / \
            U.Dot1Q(prio=2, id=1, vlan=VID1) / \
            U.IP() / U.TCP()

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=U.Ethertype.Dot1Q.value) / \
            U.Dot1Q(prio=2, id=1, vlan=VID1) / \
            U.IP() / U.TCP()

        self.l2_in_packet, self.l2_out_packet = U.pad_input_and_output_packets(in_packet_base, out_packet_base)
        self.l2_ingress_packet = {'data': self.l2_in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        self.l2_expected_packets = [{'data': self.l2_out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST}]

        self.expected_packets1 = []
        self.expected_packets1.append({'data': self.l2_out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST})
        self.expected_packets1.append({'data': self.l2_out_packet, 'slice': OUT_SLICE1, 'ifg': OUT_IFG1, 'pif': OUT_SERDES_FIRST1})

    def create_l3_topology(self):
        self.ip_impl_class = ip_test_base.ipv4_test_base
        self.ip_impl = self.ip_impl_class()

        self.rx_l3_ac_port = T.l3_ac_port(self,
                                          self.device,
                                          L3_AC_PORT_GID,
                                          self.eth_port,
                                          self.vrf,
                                          L3_AC_PORT_MAC_ADDR,
                                          VID1,
                                          0)

        self.tx_l3_ac_port = T.l3_ac_port(self,
                                          self.device,
                                          L3_AC_PORT_GID + 1,
                                          self.eth_port1,
                                          self.vrf,
                                          L3_AC_PORT_MAC_ADDR2,
                                          VID1,
                                          0)

        self.tx_l3_ac_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.rx_l3_ac_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

        self.nh_l3_ac = T.next_hop(self, self.device, NH_L3_AC_GID, NH_L3_AC_MAC, self.tx_l3_ac_port)
        self.prefix = self.ip_impl.build_prefix(DIP, length=16)
        self.vrf.hld_obj.add_ipv4_route(self.prefix, self.nh_l3_ac.hld_obj, PRIVATE_DATA, False)

        # Create Packets
        l3_in_packet_base = \
            S.Ether(dst=L3_AC_PORT_MAC_ADDR.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=VID1) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

        l3_out_packet_base = \
            S.Ether(dst=NH_L3_AC_MAC.addr_str, src=L3_AC_PORT_MAC_ADDR2.addr_str) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1)

        self.l3_in_packet, self.l3_out_packet = U.pad_input_and_output_packets(l3_in_packet_base, l3_out_packet_base)

        self.l3_ingress_packet = {'data': self.l3_in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        self.l3_expected_packets = [{'data': self.l3_out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST}]
