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
from scapy.all import *
import unittest
from leaba import sdk
import decor
import topology as T

SLICE_1 = 1
SLICE_2 = 2
IFG_0 = 0
SERDES_3 = 3
IFG_1 = 1
SERDES_14 = 14

DST_MAC = "ca:fe:ca:fe:ca:fe"
SRC_MAC = "de:ad:de:ad:de:ad"
VLAN = 0xAB9

SYS_PORT0_GID = 0x111
SYS_PORT1_GID = 0x112
AC_PORT0_GID = 0x221
AC_PORT1_GID = 0x222


@unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
class loopback_unit_test(unittest.TestCase):

    def setUp(self):
        import sim_utils
        self.device = sim_utils.create_device(1)

        self.topology = T.topology(self, self.device, create_default_topology=False)
        self.create_packets()

    def tearDown(self):
        self.device.tearDown()

    def create_packets(self):
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        self.in_packet, self.out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_loopback(self):

        ac_profile = T.ac_profile(self, self.device)

        # Create topology
        #
        #      mac_port0 -> sys_port0 -> eth_port0 -> ac_port0 _
        #                                                       |
        #    _ mac_port1 <- sys_port1 <- eth_port1 <- ac_port1 <-
        #   |
        #   ---------------> sys_port1 -> eth_port1 -> ac_port1 _
        #                                                        |
        #       mac_port0 <- sys_port0 <- eth_port0 <- ac_port0 <-
        #

        # Create objects
        mac_port0 = T.mac_port(self, self.device, SLICE_1, IFG_0, SERDES_3, SERDES_3)
        sys_port0 = T.system_port(self, self.device, SYS_PORT0_GID, mac_port0)
        eth_port0 = T.sa_ethernet_port(self, self.device, sys_port0, ac_profile)
        ac_port0 = T.l2_ac_port(self, self.device, AC_PORT0_GID, None, None, eth_port0, None, VLAN)

        mac_port1 = T.mac_port(self, self.device, SLICE_2, IFG_1, SERDES_14, SERDES_14)
        sys_port1 = T.system_port(self, self.device, SYS_PORT1_GID, mac_port1)
        eth_port1 = T.sa_ethernet_port(self, self.device, sys_port1, ac_profile)
        ac_port1 = T.l2_ac_port(self, self.device, AC_PORT1_GID, None, None, eth_port1, None, VLAN)

        # Attach the AC ports to each other
        ac_port0.hld_obj.set_destination(ac_port1.hld_obj)
        ac_port1.hld_obj.set_destination(ac_port0.hld_obj)

        # Set the loop back mode
        mac_port1.hld_obj.set_loopback_mode(sdk.la_mac_port.loopback_mode_e_MII_SRDS_CLK)

        # Run a packet - should end up where it started
        run_and_compare(self, self.device,
                        self.in_packet, SLICE_1, IFG_0, SERDES_3,
                        self.out_packet, SLICE_1, IFG_0, SERDES_3)


if __name__ == '__main__':
    unittest.main()
