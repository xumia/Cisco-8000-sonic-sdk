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

import unittest
from leaba import sdk
import ip_test_base
from packet_test_utils import *
import sim_utils
import topology as T
from scapy.all import *
from sdk_test_case_base import sdk_test_case_base

PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
SA = T.mac_addr('be:ef:5d:35:7a:35')


class ipv6_traps_base(sdk_test_case_base):
    ip_impl_class = ip_test_base.ipv6_test_base
    DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')
    SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    TTL = 127

    def setUp(self):
        super().setUp()

        self.ip_impl = self.ip_impl_class()
        self.add_default_route()

    def add_default_route(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=0)
        self.topology.vrf.hld_obj.add_ipv6_route(prefix, self.topology.nh_l3_ac_def.hld_obj, PRIVATE_DATA_DEFAULT, False)

    def do_test_legall_sip_drop(self, sip):
        input_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IPv6(src=sip.addr_str, dst=self.DIP.addr_str, hlim=self.TTL) / \
            TCP()
        input_packet, __ = enlarge_packet_to_min_length(input_packet_base)

        run_and_drop(self, self.device, input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def do_test_ttl_drop(self):
        input_packet_base = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IPv6(src=self.SIP.addr_str, dst=self.DIP.addr_str, hlim=0) / \
            TCP()
        input_packet, __ = enlarge_packet_to_min_length(input_packet_base)

        run_and_drop(self, self.device, input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def do_test_legall_packet(self, input_packet):
        run_and_drop(self, self.device, input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
