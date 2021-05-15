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
import decor
from leaba import sdk
import ip_test_base
import packet_test_utils as U
import scapy.all as S
import sim_utils
import topology as T
from l3_ac_base import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class recreate_port(l3_ac_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_recreate_port(self):

        port = T.l3_ac_port(
            self,
            self.device,
            L3_AC_PORT_GID,
            self.topology.rx_eth_port,
            self.topology.vrf,
            L3_AC_PORT_MAC_ADDR,
            111,
            112)
        port.destroy()
        port = T.l3_ac_port(
            self,
            self.device,
            L3_AC_PORT_GID,
            self.topology.rx_eth_port,
            self.topology.vrf,
            L3_AC_PORT_MAC_ADDR,
            111,
            112)
        port.destroy()


if __name__ == '__main__':
    unittest.main()
