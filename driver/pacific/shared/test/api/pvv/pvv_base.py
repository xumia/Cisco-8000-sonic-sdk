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
import decor

SYS_PORT_GID = 23
L2_AC_PORT_GID = 0x42
L3_AC_PORT_GID = 0x32
VRF_GID = 0x1 if not decor.is_gibraltar() else 0xF00
MC_GROUP_GID = 0x13
L3_AC_PORT_MAC_ADDR = T.mac_addr('44:33:44:33:44:33')
L3_AC_PORT_MAC_ADDR2 = T.mac_addr('45:33:45:33:45:33')
VID1 = 0xAB9
VID2 = 0xABA

IN_SLICE = T.get_device_slice(2)
IN_IFG = 0
IN_SERDES_FIRST = T.get_device_first_serdes(4)
IN_SERDES_LAST = IN_SERDES_FIRST + 1

OUT_SLICE = T.get_device_slice(1)
OUT_IFG = T.get_device_ifg(1)
OUT_SERDES_FIRST = T.get_device_out_first_serdes(8)
OUT_SERDES_LAST = T.get_device_out_last_serdes(OUT_SERDES_FIRST + 1)

OUT_SLICE1 = T.get_device_slice(0)
OUT_IFG1 = T.get_device_ifg(1)
OUT_SERDES_FIRST1 = T.get_device_out_next_first_serdes(8)
OUT_SERDES_LAST1 = T.get_device_out_next_last_serdes(OUT_SERDES_FIRST1 + 1)

DST_MAC = "ca:fe:ca:fe:ca:fe"
SRC_MAC = "de:ad:de:ad:de:ad"


class pvv_base(unittest.TestCase):

    def setUp(self):

        self.maxDiff = None  # Show whole strings on failures (unittest variable)

        self.device = U.sim_utils.create_device(1)

        self.topology = T.topology(self, self.device, create_default_topology=False)

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

    def tearDown(self):
        self.device.tearDown()

    def create_packets(self):
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=U.Ethertype.Dot1Q.value) / \
            U.Dot1Q(prio=2, id=1, vlan=VID1) / \
            U.IP() / U.TCP()

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=U.Ethertype.Dot1Q.value) / \
            U.Dot1Q(prio=2, id=1, vlan=VID1) / \
            U.IP() / U.TCP()
        self.in_packet, self.out_packet = U.pad_input_and_output_packets(in_packet_base, out_packet_base)

        self.ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        self.expected_packets = [{'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST}]
        self.expected_packets1 = []
        self.expected_packets1.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST})
        self.expected_packets1.append({'data': self.out_packet, 'slice': OUT_SLICE1, 'ifg': OUT_IFG1, 'pif': OUT_SERDES_FIRST1})
