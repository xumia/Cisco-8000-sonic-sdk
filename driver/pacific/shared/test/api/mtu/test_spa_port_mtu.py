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

from packet_test_utils import *
from spa_port_mtu_base import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
import decor

# Helper class


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class spa_port_mtu_check (spa_port_mtu_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_spa_port_mtu(self):
        mac_port_member_1 = T.mac_port(
            self,
            self.device,
            self.s_tx[0].slice,
            self.s_tx[0].ifg,
            self.s_tx[0].first_serdes,
            self.s_tx[0].last_serdes)
        sys_port_member_1 = T.system_port(self, self.device, 100, mac_port_member_1)

        mac_port_member_2 = T.mac_port(
            self,
            self.device,
            self.s_tx[1].slice,
            self.s_tx[1].ifg,
            self.s_tx[1].first_serdes,
            self.s_tx[1].last_serdes)
        sys_port_member_2 = T.system_port(self, self.device, 101, mac_port_member_2)

        spa_port = T.spa_port(self, self.device, 123)

        spa_port.add(sys_port_member_1)
        spa_port.add(sys_port_member_2)

        # Verify setting mtu on the  spa port
        spa_eth_port = T.sa_ethernet_port(self, self.device, spa_port)
        mtu_test = 64
        mtu_max = (1 << 14) - 1
        spa_eth_port.hld_obj.set_mtu(mtu_test)
        mtu = spa_eth_port.hld_obj.get_mtu()
        self.assertEqual(mtu, mtu_test)

        # Verify default mtu on the port removed from spa is max_mtu
        spa_port.remove(sys_port_member_2)
        eth_port = T.sa_ethernet_port(self, self.device, sys_port_member_2)
        mtu = eth_port.hld_obj.get_mtu()
        self.assertEqual(mtu, mtu_max)


if __name__ == '__main__':
    unittest.main()
