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
from scapy.all import *
from rate_limiters_getters_base import *
import sim_utils
import topology as T
import packet_test_utils as U

RATE = 114000000000
AC_PORT_GID_BASE = 10

DEFAULT_SLICE_IFG = sdk.la_slice_ifg()
DEFAULT_SLICE_IFG.ifg = 0
DEFAULT_SLICE_IFG.slice = 0


class rate_limiter_set_base(rate_limiters_getters_base, unittest.TestCase):

    def init(self):
        self.slice_ifg = sdk.la_slice_ifg()
        self.slice_ifg.ifg = 0
        self.slice_ifg.slice = T.get_device_slice(1)

    def create_attach_rate_limiter_set(self, is_aggregate=False):

        # Create a MAC port
        self.mac_port = T.mac_port(self, self.device, IN_SLICE, IN_IFG, IN_SERDES_FIRST, IN_SERDES_LAST)

        # Create an ethernet port on top of a system port, on top of a MAC port
        self.sys_port = T.system_port(self, self.device, SYS_PORT_GID_BASE, self.mac_port)
        self.spa_port = T.spa_port(self, self.device, SYS_PORT_GID_BASE + 1)
        if(is_aggregate):
            self.spa_port.add(self.sys_port)
        underlying_port = self.sys_port if (not is_aggregate) else self.spa_port
        self.eth_port = T.sa_ethernet_port(self, self.device, underlying_port)

        # Create ingress port over the ethernet port
        self.ac_port = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            None,
            self.eth_port,
            None,
            VLAN,
            0x0)

        self.rate_limiter_set = self.device.create_rate_limiter(self.sys_port.hld_obj)
