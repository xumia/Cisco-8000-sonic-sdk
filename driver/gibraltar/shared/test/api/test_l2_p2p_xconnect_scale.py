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

from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
import decor
from distutils.util import strtobool


IN_SLICE = 0
IN_IFG = 0
IN_SERDES_FIRST = T.get_device_first_serdes(4)
IN_SERDES_LAST = IN_SERDES_FIRST + 1
OUT_SLICE = 0
OUT_IFG = 0
OUT_SERDES_FIRST = T.get_device_next_first_serdes(8)
OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

SYS_PORT_GID_BASE = 23
AC_PORT_GID_BASE = 10

DST_MAC = "ca:fe:ca:fe:ca:fe"
SRC_MAC = "de:ad:de:ad:de:ad"
VLAN = 0xAB9


@unittest.skipIf(decor.is_asic3(), "Disabled as asic3 hasn't resolved failures for scale_mode")
@unittest.skipIf(decor.is_valgrind(), "Disabled due to scale_mode conflict with valgrind")
@unittest.skipIf(decor.is_hw_device(), "Only suitable for NSIM")
class l2_p2p_xconnect_scale_unit_test(unittest.TestCase):

    def setUp(self):
        enable_logging = bool(strtobool(os.environ.get('ENABLE_NSIM_LOG', '0')))
        self.device = sim_utils.create_test_device('/dev/testdev', 1, nsim_accurate_scale_model=True, enable_logging=enable_logging)

        self.topology = T.topology(self, self.device, create_default_topology=False)
        self.topology.create_default_profiles()
        self.topology.create_inject_ports()

        self.create_ports()
        self.create_packets()

    def tearDown(self):
        self.destroy_ports()
        self.device.tearDown()

    def create_packets(self):
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()
        self.in_packet, self.out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

    def create_ports(self):
        self.ac_profile = T.ac_profile(self, self.device)
        global IN_SLICE
        IN_SLICE = T.choose_active_slices(self.device, IN_SLICE, [3, 1])
        global OUT_SLICE
        OUT_SLICE = T.choose_active_slices(self.device, OUT_SLICE, [5, 0])

        self.eth_port1 = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, SYS_PORT_GID_BASE, IN_SERDES_FIRST, IN_SERDES_LAST)
        self.eth_port1.set_ac_profile(self.ac_profile)
        self.ac_port1 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            None,
            self.eth_port1,
            None,
            VLAN,
            0x0)

        self.eth_port2 = T.ethernet_port(
            self,
            self.device,
            OUT_SLICE,
            OUT_IFG,
            SYS_PORT_GID_BASE + 1,
            OUT_SERDES_FIRST,
            OUT_SERDES_LAST)
        self.eth_port2.set_ac_profile(self.ac_profile)
        self.ac_port2 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE +
                                     1, self.topology.filter_group_def, None, self.eth_port2, None, VLAN, 0x0)

        self.ac_port1.hld_obj.set_destination(self.ac_port2.hld_obj)

    def destroy_ports(self):
        self.ac_port1.hld_obj.set_destination(None)
        self.ac_port2.destroy()
        self.eth_port2.destroy()
        self.ac_port1.destroy()
        self.eth_port1.destroy()
        self.ac_profile.destroy()

    def test_l2_p2p_xconnect(self):
        self.ac_port1.hld_obj.set_destination(self.ac_port2.hld_obj)
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)


if __name__ == '__main__':
    unittest.main()
