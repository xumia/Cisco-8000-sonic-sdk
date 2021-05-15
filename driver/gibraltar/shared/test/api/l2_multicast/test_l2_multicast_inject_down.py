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
import sim_utils
import topology as T
from sdk_test_case_base import *
import smart_slices_choise as ssch
import decor

OUT_SLICE = T.get_device_slice(4)
OUT_IFG = T.get_device_ifg(1)
OUT_SERDES_FIRST = T.get_device_next_first_serdes(8)
OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

OUT_SLICE1 = T.get_device_slice(1)
OUT_IFG1 = 0
OUT_SERDES_FIRST1 = T.get_device_out_first_serdes(12)
OUT_SERDES_LAST1 = OUT_SERDES_FIRST1 + 1

SYS_PORT_GID_BASE = 23
AC_PORT_GID_BASE = 10

SWITCH_GID = 100

DST_MAC = T.mac_addr('ca:fe:ca:fe:ca:fe')
SRC_MAC = T.mac_addr('de:ad:de:ad:de:ad')
VLAN = 0xAB9

PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"

MCID = 0x15


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l2_multicast_inject_down(sdk_test_case_base):
    INJECT_SLICE = T.get_device_slice(2)  # must be an even number
    INJECT_IFG = T.get_device_ifg(0)
    INJECT_PIF_FIRST = T.get_device_punt_inject_first_serdes(8)
    INJECT_PIF_LAST = INJECT_PIF_FIRST + 1

    def setUp(self):
        super().setUp()
        ssch.rechoose_even_inject_slice(self, self.device)

        # MATILDA_SAVE -- need review
        global OUT_SLICE, OUT_SLICE1
        OUT_SLICE = T.choose_active_slices(self.device, OUT_SLICE, [4, 2])
        OUT_SLICE1 = T.choose_active_slices(self.device, OUT_SLICE1, [1, 3])

        self.create_system_setup()
        self.create_packets()

    def create_packets(self):
        in_packet_base = Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        out_packet_base = Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        self.in_packet, self.out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

    def create_system_setup(self):
        # create punt/inject port
        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            SYS_PORT_GID_BASE + 3,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        # Create 2 output ports
        self.out_mac_port1 = T.mac_port(self, self.device, OUT_SLICE, OUT_IFG, OUT_SERDES_FIRST, OUT_SERDES_LAST)
        self.out_sys_port1 = T.system_port(self, self.device, SYS_PORT_GID_BASE + 1, self.out_mac_port1)
        self.eth_port1 = T.sa_ethernet_port(self, self.device, self.out_sys_port1)
        self.ac_port1 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 1,
            self.topology.filter_group_def,
            None,
            self.eth_port1,
            None,
            VLAN,
            0x0)

        self.out_mac_port2 = T.mac_port(self, self.device, OUT_SLICE1, OUT_IFG1, OUT_SERDES_FIRST1, OUT_SERDES_LAST1)
        self.out_sys_port2 = T.system_port(self, self.device, SYS_PORT_GID_BASE + 2, self.out_mac_port2)
        self.eth_port2 = T.sa_ethernet_port(self, self.device, self.out_sys_port2)
        self.ac_port2 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 2,
            self.topology.filter_group_def,
            None,
            self.eth_port2,
            None,
            VLAN,
            0x0)

        self.out_mac_port1.activate()
        self.out_mac_port2.activate()

        # Create multicast group
        self.mc_group = self.device.create_l2_multicast_group(MCID, sdk.la_replication_paradigm_e_EGRESS)
        self.assertIsNotNone(self.mc_group)

    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    def test_l2_multicast_inject_down(self):
        # Add the output AC ports to the MC group
        self.mc_group.add(self.ac_port1.hld_obj, self.out_sys_port1.hld_obj)
        self.mc_group.add(self.ac_port2.hld_obj, self.out_sys_port2.hld_obj)

        dest_id = sdk.la_packet_types.LA_PACKET_DESTINATION_PREFIX_MCID | (MCID & 0xffff)

        self.inject_down_packet = \
            Ether(dst=PUNT_INJECT_PORT_MAC_ADDR, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=Ethertype.Inject.value) / \
            InjectDown(dest=dest_id, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            self.in_packet

        ingress_packet = {
            'data': self.inject_down_packet,
            'slice': self.INJECT_SLICE,
            'ifg': self.INJECT_IFG,
            'pif': self.INJECT_PIF_FIRST}

        expected_packets = []
        expected_packets.append({
            'data': self.out_packet,
            'slice': OUT_SLICE,
            'ifg': OUT_IFG,
            'pif': OUT_SERDES_FIRST})
        expected_packets.append({
            'data': self.out_packet,
            'slice': OUT_SLICE1,
            'ifg': OUT_IFG1,
            'pif': OUT_SERDES_FIRST1})

        run_and_compare_list(self, self.device, ingress_packet, expected_packets)


if __name__ == '__main__':
    unittest.main()
