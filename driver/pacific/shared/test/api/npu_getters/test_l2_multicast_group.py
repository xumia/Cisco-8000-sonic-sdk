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
from leaba import sdk
from scapy.all import *
from npu_getters_base import *
import sim_utils
import topology as T
import packet_test_utils as U
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l2_multicast_group(npu_getters_base, unittest.TestCase):

    def init(self):
        self.topology = T.topology(self, self.device, create_default_topology=False)
        self.mc_group = self.device.create_l2_multicast_group(MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.assertIsNotNone(self.mc_group)

        group_size = self.mc_group.get_size()
        self.assertEqual(group_size, 0)

        # Create ports
        sw1 = T.switch(self, self.device, 100)

        self.out_mac_port1 = T.mac_port(self, self.device, self.OUT_SLICE, OUT_IFG, OUT_SERDES_FIRST, OUT_SERDES_LAST)
        self.out_sys_port1 = T.system_port(self, self.device, SYS_PORT_GID_BASE + 1, self.out_mac_port1)
        self.out_mac_port2 = T.mac_port(self, self.device, self.OUT_SLICE1, OUT_IFG1, OUT_SERDES_FIRST1, OUT_SERDES_LAST1)
        self.out_sys_port2 = T.system_port(self, self.device, SYS_PORT_GID_BASE + 2, self.out_mac_port2)
        self.eth_port1 = T.sa_ethernet_port(self, self.device, self.out_sys_port1)
        self.ac_port1 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE +
                                     1, self.topology.filter_group_def, sw1, self.eth_port1, None, VLAN, 0x0)
        self.eth_port2 = T.sa_ethernet_port(self, self.device, self.out_sys_port2)
        self.ac_port2 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE +
                                     2, self.topology.filter_group_def, sw1, self.eth_port2, None, VLAN, 0x0)

    def test_l2_mc_group_set_get(self):
        self.mc_group.add(self.ac_port1.hld_obj, self.out_sys_port1.hld_obj)
        group_size = self.mc_group.get_size()
        self.assertEqual(group_size, 1)

        self.mc_group.add(self.ac_port2.hld_obj, self.out_sys_port2.hld_obj)
        group_size = self.mc_group.get_size()
        self.assertEqual(group_size, 2)

        # Check get_member
        res_ac_port1 = self.mc_group.get_member(0)
        self.assertEqual(res_ac_port1.this, self.ac_port1.hld_obj.this)

        try:
            self.mc_group.get_member(5)
            self.assertFail()
        except sdk.BaseException:
            pass

        # Check get_members
        res_ac_ports = self.mc_group.get_members()
        res_ac_port2 = res_ac_ports[1]
        self.assertEqual(res_ac_port2.this, self.ac_port2.hld_obj.this)

        # Check get_replication_paradigm
        res_replication_paradigm = self.mc_group.get_replication_paradigm()
        self.assertEqual(res_replication_paradigm, sdk.la_replication_paradigm_e_EGRESS)

        # DSP
        dsp = self.mc_group.get_destination_system_port(self.ac_port1.hld_obj)
        self.assertEqual(dsp.this, self.out_sys_port1.hld_obj.this)

        # Check get multicast group
        mc_group2 = self.device.get_l2_multicast_group(MC_GROUP_GID)
        self.assertEqual(mc_group2.this, self.mc_group.this)


if __name__ == '__main__':
    unittest.main()
