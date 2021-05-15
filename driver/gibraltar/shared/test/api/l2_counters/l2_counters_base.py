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


IN_SLICE = T.get_device_slice(1)
IN_IFG = 0
IN_SERDES_FIRST = T.get_device_first_serdes(4)
IN_SERDES_LAST = IN_SERDES_FIRST + 1
OUT_SLICE = T.get_device_slice(4)
OUT_IFG = T.get_device_ifg(1)
OUT_SLICE_1 = T.get_device_slice(5)
OUT_IFG_1 = 0
OUT_SLICE_2 = OUT_SLICE
OUT_IFG_2 = OUT_IFG
OUT_SERDES_FIRST = T.get_device_out_first_serdes(8)
OUT_SERDES_LAST = OUT_SERDES_FIRST + 1
SWITCH_GID = 0xa0f

SYS_PORT_GID_BASE = 23
AC_PORT_GID_BASE = 10

DST_MAC = "ca:fe:ca:fe:ca:fe"
SRC_MAC = "de:ad:de:ad:de:ad"
SRC_MAC_1 = "de:ad:be:ef:de:ad"
SRC_MAC_2 = SRC_MAC
VLAN = 0xAB9


class l2_counters_base(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(1)

        # MATILDA_SAVE -- need review
        global IN_SLICE, OUT_SLICE, OUT_SLICE_2, OUT_SLICE_1
        if (IN_SLICE not in self.device.get_used_slices()):
            IN_SLICE = T.choose_active_slices(self.device, IN_SLICE, [1, 3])
        if (OUT_SLICE not in self.device.get_used_slices()):
            OUT_SLICE = T.choose_active_slices(self.device, OUT_SLICE, [4, 2])
        if (OUT_SLICE_1 not in self.device.get_used_slices()):
            OUT_SLICE_1 = T.choose_active_slices(self.device, OUT_SLICE_1, [5, 0])
        OUT_SLICE_2 = OUT_SLICE

        self.OUT_SLICE = OUT_SLICE
        self.IN_SLICE = IN_SLICE

        self.topology = T.topology(self, self.device, create_default_topology=False)
        self.topology.create_inject_ports()
        self.ac_profile = T.ac_profile(self, self.device)

    def tearDown(self):
        self.device.tearDown()

    def create_packets(self, _prio, packet_to_use=0):

        src_mac = SRC_MAC
        if packet_to_use == 1:
            src_mac = SRC_MAC_1
        elif packet_to_use == 2:
            src_mac = SRC_MAC_2

        in_packet_base = Ether(dst=DST_MAC, src=src_mac, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=_prio, id=1, vlan=VLAN) / \
            IP() / TCP()

        out_packet_base = Ether(dst=DST_MAC, src=src_mac, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=_prio, id=1, vlan=VLAN) / \
            IP() / TCP()

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        return in_packet, out_packet

    def do_test_counter_l2_p2p_xconnect(self, single_counter, prios):

        # Create ingress port
        eth_port1 = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, SYS_PORT_GID_BASE, IN_SERDES_FIRST, IN_SERDES_LAST)
        eth_port1.set_ac_profile(self.ac_profile)
        ac_port1 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            None,
            eth_port1,
            None,
            VLAN,
            0x0)

        # Create and set ingress counter
        counter_set_size = 1 if single_counter else 8
        ingress_counter = self.device.create_counter(counter_set_size)
        ac_port1.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, ingress_counter)

        # Create egress port
        eth_port2 = T.ethernet_port(
            self,
            self.device,
            OUT_SLICE,
            OUT_IFG,
            SYS_PORT_GID_BASE + 1,
            OUT_SERDES_FIRST,
            OUT_SERDES_LAST)
        eth_port2.set_ac_profile(self.ac_profile)
        ac_port2 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 1,
            self.topology.filter_group_def,
            None,
            eth_port2,
            None,
            VLAN,
            0x0)

        # Create and set egress counter
        egress_counter = self.device.create_counter(counter_set_size)
        ac_port2.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, egress_counter)

        # Set destination
        ac_port1.hld_obj.set_destination(ac_port2.hld_obj)

        # Run the packet
        for prio in prios:
            in_packet, out_packet = self.create_packets(prio)

            run_and_compare(
                self,
                self.device,
                in_packet,
                IN_SLICE,
                IN_IFG,
                IN_SERDES_FIRST,
                out_packet,
                OUT_SLICE,
                OUT_IFG,
                OUT_SERDES_FIRST)

        # Check ingress counter
        if single_counter:
            packet_count, byte_count = ingress_counter.read(0,  # sub-counter index
                                                            True,  # force_update
                                                            True)  # clear_on_read
            self.assertEqual(packet_count, len(prios))
            assertPacketLengthIngress(self, in_packet, IN_SLICE, byte_count, num_packets=len(prios))
        else:
            for prio in prios:
                packet_count, byte_count = ingress_counter.read(prio,  # sub-counter index
                                                                True,  # force_update
                                                                True)  # clear_on_read
                self.assertEqual(packet_count, 1)
                assertPacketLengthIngress(self, in_packet, IN_SLICE, byte_count)

        # Check egress counter
        if single_counter:
            packet_count, byte_count = egress_counter.read(0,  # sub-counter index
                                                           True,  # force_update
                                                           True)  # clear_on_read
            self.assertEqual(packet_count, len(prios))
            assertPacketLengthEgress(self, out_packet, byte_count, num_packets=len(prios))
        else:
            for prio in prios:
                packet_count, byte_count = egress_counter.read(prio,  # sub-counter index
                                                               True,  # force_update
                                                               True)  # clear_on_read
                self.assertEqual(packet_count, 1)
                assertPacketLengthEgress(self, out_packet, byte_count)
