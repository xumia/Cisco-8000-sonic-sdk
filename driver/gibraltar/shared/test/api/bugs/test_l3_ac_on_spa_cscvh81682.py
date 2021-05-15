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

# Test covering CSCvh81682.
#
#
# Description
#
#-----------
#
#
# 2 system ports on the same slice, different IFG-s; both ports are part of an SPA.
#
# There's an ethernet port and L3 AC port built on top of this SPA.
#
# The test does the following:
#
#
# 1. Destroy L3AC and EP.
#
# 2. Recreate EP and L3AC on same SPA.


from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
import decor

# Helper class


SLICE = T.get_device_slice(2)
IFG = 0
IFG2 = T.get_device_ifg(IFG + 1)

FIRST_SERDES1 = T.get_device_first_serdes(4)
LAST_SERDES1 = T.get_device_last_serdes(5)
FIRST_SERDES2 = T.get_device_next_first_serdes(8)
LAST_SERDES2 = T.get_device_next_last_serdes(9)

VRF_GID = 0x6cc if not decor.is_gibraltar() else 0xFFE


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l3_ac_on_spa(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(1)

        self.topology = T.topology(self, self.device, create_default_topology=False)
        # MATILDA_SAVE -- need review
        if SLICE not in self.device.get_used_slices():
            self.skipTest("In this model the tested slice is deactiveated, thus the test is irrelevant.")
            return

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l3_ac_port_on_spa(self):

        mac_port_member_1 = T.mac_port(
            self,
            self.device,
            SLICE,
            IFG,
            FIRST_SERDES1,
            LAST_SERDES1)
        sys_port_member_1 = T.system_port(self, self.device, 100, mac_port_member_1)

        mac_port_member_2 = T.mac_port(
            self,
            self.device,
            SLICE,
            IFG2,
            FIRST_SERDES2,
            LAST_SERDES2)
        sys_port_member_2 = T.system_port(self, self.device, 101, mac_port_member_2)

        spa_port = T.spa_port(self, self.device, 123)

        spa_port.add(sys_port_member_1)
        spa_port.add(sys_port_member_2)

        vrf = T.vrf(self, self.device, VRF_GID)

        eth_port = T.sa_ethernet_port(self, self.device, spa_port)
        l3_ac = T.l3_ac_port(
            self,
            self.device,
            T.TX_L3_AC_REG_GID,
            eth_port,
            vrf,
            T.TX_L3_AC_REG_MAC)

        l3_ac.destroy()
        eth_port.destroy()

        eth_port = T.sa_ethernet_port(self, self.device, spa_port)
        l3_ac = T.l3_ac_port(
            self,
            self.device,
            T.TX_L3_AC_REG_GID,
            eth_port,
            vrf,
            T.TX_L3_AC_REG_MAC)


if __name__ == '__main__':
    unittest.main()
