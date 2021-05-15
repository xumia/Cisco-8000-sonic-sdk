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

from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
from ip_test_base import *
from traps_base import *
import sim_utils
import topology as T


class ipv4_traps_base(TrapsTest):
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    TTL = 128
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    OUTPUT_VID = 0xac

    def setUp(self):
        TrapsTest.setUp(self)

        priority = 0
        self.device.clear_trap_configuration(sdk.LA_EVENT_IPV4_HEADER_ERROR)
        self.device.set_trap_configuration(sdk.LA_EVENT_IPV4_HEADER_ERROR, priority, None, self.punt_dest, False, False, True, 0)

        priority = 1
        self.device.clear_trap_configuration(sdk.LA_EVENT_IPV4_OPTIONS_EXIST)
        self.device.set_trap_configuration(sdk.LA_EVENT_IPV4_OPTIONS_EXIST, priority, None, self.punt_dest, False, False, True, 0)

    def add_default_route(self):
        prefix = ipv4_test_base.get_default_prefix()
        ipv4_test_base.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh,
                                 ipv4_traps_base.PRIVATE_DATA_DEFAULT)
        self.has_default_route = True

    def do_run_test(self, in_packet, punt_packet):
        run_and_compare(self, self.device,
                        in_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        punt_packet, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)
