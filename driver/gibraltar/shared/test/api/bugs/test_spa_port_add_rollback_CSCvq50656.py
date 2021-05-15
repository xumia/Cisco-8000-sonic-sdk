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

from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
import decor
from sdk_test_case_base import sdk_test_case_base

SLICE = 0
SPA_SLICE = T.get_device_slice(1)
SPA_SERDES_START = T.get_device_first_serdes(0)
SPA_IFG = 0
PORT_MAC_START = "ca:fe:ca:fe:ca:00"
SPA_L3_AC_MAC = "ab:cd:ef:12:34:56"
L3_AC_PORT_GID_BASE = 0
SPA_L3_AC_GID = L3_AC_PORT_GID_BASE + 15
SYS_PORT_GID_BASE = T.MIN_SYSTEM_PORT_GID
SPA_SYS_PORT_GID = SYS_PORT_GID_BASE + 15
SPA_PORT_GID = 1


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class spa_port_add_rollback(sdk_test_case_base):

    def get_next_mac(self, index):
        return T.mac_addr(PORT_MAC_START[:-1] + hex((int(PORT_MAC_START[-1], 16) + index))[-1])

    def create_ports(self):
        self.m_ac_ports = []
        for x in range(0, 15):
            # Create mac ports on Slice 0, IFG 0/1, Serdes 0-15
            if (x < 8):
                mac_port = T.mac_port(self, self.device, SLICE, 0, 0 + (x * 2), 1 + (x * 2))
            else:
                mac_port = T.mac_port(self, self.device, SLICE, 1, 0 + ((x - 8) * 2), 1 + ((x - 8) * 2))
            sys_port = T.system_port(self, self.device, SYS_PORT_GID_BASE + x, mac_port)
            eth_port = T.sa_ethernet_port(self, self.device, sys_port)
            ac_port = T.l3_ac_port(self, self.device, L3_AC_PORT_GID_BASE + x,
                                   eth_port, self.topology.vrf, self.get_next_mac(x))
            ingress_qos_profile = T.ingress_qos_profile(self, self.device)
            ac_port.hld_obj.set_ingress_qos_profile(ingress_qos_profile.hld_obj)
            self.m_ac_ports.append(ac_port)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_spa_port_add_rollback(self):
        # MATILDA_SAVE -- need review
        if (SLICE not in self.device.get_used_slices()) or (5 not in self.device.get_used_slices()):
            self.skipTest("In this model the tested slice has been deactivated, thus the test is irrelevant.")
            return

        self.create_ports()

        self.mac_port = T.mac_port(self, self.device, SPA_SLICE, SPA_IFG, SPA_SERDES_START, SPA_SERDES_START + 1)
        self.system_port = T.system_port(self, self.device, SPA_SYS_PORT_GID, self.mac_port)

        self.spa_port = T.spa_port(self, self.device, SPA_PORT_GID)
        self.ethernet_port = T.sa_ethernet_port(self, self.device, self.spa_port)
        self.l3_ac_port = T.l3_ac_port(
            self,
            self.device,
            SPA_L3_AC_GID,
            self.ethernet_port,
            self.topology.vrf,
            T.mac_addr(SPA_L3_AC_MAC))

        self.ingress_qos_profile = T.ingress_qos_profile(self, self.device)
        self.l3_ac_port.hld_obj.set_ingress_qos_profile(self.ingress_qos_profile.hld_obj)

        with self.assertRaises(sdk.ResourceException):
            self.spa_port.add(self.system_port)

        self.spa_port.hld_obj.get_members()
        self.assertEqual(len(self.spa_port.hld_obj.get_members()), 0)


if __name__ == '__main__':
    unittest.main()
