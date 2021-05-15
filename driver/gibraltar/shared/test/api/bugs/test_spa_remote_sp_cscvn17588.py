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

from leaba import sdk
from packet_test_utils import *
import scapy.all as S
import sim_utils
import topology as T
import unittest
#from ip_routing_base import *
import decor


SLICE = T.get_device_slice(3)
IFG = 0
FIRST_SERDES = T.get_device_first_serdes(4)
LAST_SERDES = T.get_device_last_serdes(5)
EGRESS_DEVICE_ID = 10

SPA_L3AC_GID = 198
REMOTE_SYS_PORT_GID = 199
RX_AC_PORT_VID1 = 0x987


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class spa_remote_port_add_delete(unittest.TestCase):

    SLICE = T.get_device_slice(3)
    IFG = T.get_device_ifg(0)
    FIRST_SERDES = T.get_device_first_serdes(4)
    LAST_SERDES = T.get_device_last_serdes(5)

    def rechoose_even_inject_slice(self):
        # MATILDA_SAVE -- need review
        if self.SLICE not in self.device.get_used_slices():
            self.SLICE = T.choose_active_slices(self.device, self.SLICE, [1, 3, 4])

    def setUp(self):
        self.device = sim_utils.create_device(1)
        self.topology = T.topology(self, self.device)
        self.rechoose_even_inject_slice()
        # Create remote port
        remote_port = T.remote_port(
            self,
            self.device,
            EGRESS_DEVICE_ID,
            self.SLICE,
            self.IFG,
            self.FIRST_SERDES,
            self.LAST_SERDES)

        # Create remote system port above the remote port
        self.remote_sys_port = T.system_port(self, self.device, REMOTE_SYS_PORT_GID, remote_port)

        self.spa_port = T.spa_port(self, self.device, 123)
        mac_port_member_1 = T.mac_port(
            self,
            self.device,
            self.SLICE,
            self.IFG + 1,
            self.FIRST_SERDES,
            self.LAST_SERDES)
        self.sys_port_member_1 = T.system_port(self, self.device, 100, mac_port_member_1)

        self.eth_port = T.sa_ethernet_port(self, self.device, self.spa_port)
        self.rx_spa_l3_ac = T.l3_ac_port(
            self,
            self.device,
            SPA_L3AC_GID,
            self.eth_port,
            self.topology.vrf,
            T.RX_L3_AC_MAC,
            vid1=RX_AC_PORT_VID1,
            vid2=0)
        self.rx_spa_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR - no remote port")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_add_remove_members(self):
        # add remote member
        self.spa_port.add(self.remote_sys_port)

        # remove remote member
        self.spa_port.remove(self.remote_sys_port)

        # add local member
        self.spa_port.add(self.sys_port_member_1)

        # remove local member
        self.spa_port.remove(self.sys_port_member_1)


if __name__ == '__main__':
    unittest.main()
