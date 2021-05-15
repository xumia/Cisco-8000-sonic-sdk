#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import sim_utils
import topology as T
import decor

VXLAN_L2_PORT_GID = 0x250
VXLAN_SIP = T.ipv4_addr('12.10.12.11')
VXLAN_DIP = T.ipv4_addr('12.1.95.250')
SA = T.mac_addr('be:ef:5d:35:7a:35')


class test_nexthop_vxlan_dependency_CSCvw72345(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(1)
        self.topology = T.topology(self, self.device)

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_nexthop_vxlan_dependency_CSCvw72345(self):
        self.vxlan_l2_port = self.device.create_vxlan_l2_service_port(
            VXLAN_L2_PORT_GID,
            VXLAN_SIP.hld_obj,
            VXLAN_DIP.hld_obj,
            self.topology.vrf.hld_obj)

        self.nh_l3_ac = T.next_hop(self, self.device, 0x900, SA, self.topology.tx_l3_ac_ext)

        self.vxlan_l2_port.set_l3_destination(self.nh_l3_ac.hld_obj)

        # next_hop  cannot be destroyed until the Vxlan port is using it
        with self.assertRaises(sdk.BusyException):
            self.device.destroy(self.nh_l3_ac.hld_obj)

        # Remove the dependency by setting the next hop to null
        self.vxlan_l2_port.set_l3_destination(None)

        # Should be able to destroy now
        self.device.destroy(self.nh_l3_ac.hld_obj)

        self.device.destroy(self.vxlan_l2_port)


if __name__ == '__main__':
    unittest.main()
