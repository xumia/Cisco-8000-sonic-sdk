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

import decor
import sys
import unittest
from leaba import sdk
from leaba.debug import debug_device
import packet_test_utils as U
import scapy.all as S
import topology as T
import ip_test_base
from sdk_test_case_base import *
from ip_routing_base import *
from ipv4_l3_ac_routing_base import *
import decor

PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
PUNT_VLAN = 0xA13
MIRROR_CMD_GID = 9
MIRROR_GID_INGRESS_OFFSET = 32
MIRROR_GID_EGRESS_OFFSET = 0
MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET

PUNT_SLICE = T.get_device_slice(2)  # must be even numbered slice
PUNT_IFG = 0
PUNT_PIF_FIRST = T.get_device_first_serdes(8)
PUNT_PIF_LAST = PUNT_PIF_FIRST
PUNT_SP_GID = SYS_PORT_GID_BASE + 3


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_ipv4_l3_ac_routing2(ipv4_l3_ac_routing_base):
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_modify_route(self):
        self._test_modify_route()


if __name__ == '__main__':
    unittest.main()
