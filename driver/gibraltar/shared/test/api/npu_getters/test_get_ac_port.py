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

# Test covering CSCvj12381.
#
#
# Description
#
#-----------
#
# Add get_ac_port API on EP.
# Moved VIDs handling to EP.
#
# The test does the following:
#
# 1. Create EP.
#
# 2. Create L2 AC port and get it using get_ac_port.
#
# 3. Get an invalid AC port.
#
# 4. Ensure creating L3 AC port with same VIDs fails.
#
# 5. Create a valid L3 AC port and use get_ac_port.

from packet_test_utils import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class get_ac_port(unittest.TestCase):
    vid1 = 1
    vid2 = 2

    def setUp(self):
        self.maxDiff = None  # Show whole strings on failures (unittest variable)

        self.device = sim_utils.create_device(1)

        self.topology = T.topology(self, self.device, create_default_topology=False)

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_ac_port(self):
        eth_port = T.ethernet_port(self, self.device, T.RX_SLICE, T.RX_IFG, T.RX_SYS_PORT_GID, T.FIRST_SERDES, T.LAST_SERDES)
        rx_switch = T.switch(self, self.device, T.RX_SWITCH_GID)
        vrf = T.vrf(self, self.device, T.VRF_GID)

        # Attemp to create a valid L2 port
        l2_ac_port = T.l2_ac_port(self, self.device, T.RX_L2_AC_PORT_GID, None, rx_switch, eth_port, T.RX_MAC, self.vid1, self.vid2)
        ac_port = eth_port.hld_obj.get_ac_port(self.vid1, self.vid2)
        self.assertEqual(l2_ac_port.hld_obj.oid(), ac_port.oid())

        # Attemp to get invalid AC port.
        # Ensure ac port is None.
        ac_port = eth_port.hld_obj.get_ac_port(self.vid1 + 1, self.vid2)
        self.assertEqual(ac_port, None)

        # Attemp to create L3 port with same VIDs.
        # Ensure fails with status busy.
        try:
            l3_ac_port = T.l3_ac_port(self, self.device, T.RX_L3_AC_GID, eth_port, vrf, T.RX_L3_AC_MAC, self.vid1, self.vid2)
            self.fail()
        except sdk.BaseException as STATUS:
            self.assertEqual(STATUS.args[0], sdk.la_status_e_E_BUSY)

        # Attemp to create a valid L3 port
        l3_ac_port = T.l3_ac_port(self, self.device, T.RX_L3_AC_GID, eth_port, vrf, T.RX_L3_AC_MAC, self.vid1 + 1, self.vid2)
        ac_port = eth_port.hld_obj.get_ac_port(self.vid1 + 1, self.vid2)
        self.assertEqual(l3_ac_port.hld_obj.oid(), ac_port.oid())


if __name__ == '__main__':
    unittest.main()
