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
from l2_counters_base import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class delayed_attach(l2_counters_base):

    def _test_ac_port_delayed_attach(self, disable_rx=False, disable_tx=False):

        if T.is_matilda_model(self.device):
            self.skipTest("on matilda the interupt tree is partially not accessible, and the test is adapted to that. ")
            return

        # Create a MAC port
        mac_port = T.mac_port(self, self.device, IN_SLICE, IN_IFG, IN_SERDES_FIRST, IN_SERDES_LAST)

        # Create an ethernet port on top of a system port, on top of a MAC port
        sys_port = T.system_port(self, self.device, SYS_PORT_GID_BASE, mac_port)
        eth_port1 = T.sa_ethernet_port(self, self.device, sys_port)
        eth_port1.set_ac_profile(self.ac_profile)

        # Create ingress port over the ethernet port
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
        counter_set_size = 1
        ingress_counter = self.device.create_counter(counter_set_size)
        ac_port1.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, ingress_counter)

        # Create egress port
        eth_port2 = T.ethernet_port(
            self,
            self.device,
            self.OUT_SLICE,
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

        # Run a packet
        prio = 0  # arbitray value
        in_packet, out_packet = self.create_packets(prio)

        run_and_compare(
            self,
            self.device,
            in_packet,
            self.IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            self.OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        # Check ingress counter
        packet_count, byte_count = ingress_counter.read(0,  # sub-counter index
                                                        True,  # force_update
                                                        True)  # clear_on_read
        self.assertEqual(packet_count, 1)
        assertPacketLengthIngress(self, in_packet, IN_SLICE, byte_count)

        # Check egress counter
        packet_count, byte_count = egress_counter.read(0,  # sub-counter index
                                                       True,  # force_update
                                                       True)  # clear_on_read
        self.assertEqual(packet_count, 1)
        assertPacketLengthEgress(self, out_packet, byte_count)

        if disable_rx:
            ac_port1.hld_obj.disable()
            run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)
            # Check ingress counter
            packet_count, byte_count = ingress_counter.read(0,  # sub-counter index
                                                            True,  # force_update
                                                            True)  # clear_on_read
            self.assertEqual(packet_count, 0)
            ac_port1.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, None)
            self.device.destroy(ac_port1.hld_obj)

        if disable_tx:
            ac_port2.hld_obj.disable()
            run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)
            # Check egress counter
            packet_count, byte_count = egress_counter.read(0,  # sub-counter index
                                                           True,  # force_update
                                                           True)  # clear_on_read
            self.assertEqual(packet_count, 0)
            ac_port2.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, None)
            ac_port1.hld_obj.set_destination(None)
            self.device.destroy(ac_port2.hld_obj)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ac_port_delayed_atttach(self):
        self._test_ac_port_delayed_attach()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ac_port_delayed_atttach_disable_rx(self):
        self._test_ac_port_delayed_attach(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ac_port_delayed_atttach_disable_tx(self):
        self._test_ac_port_delayed_attach(disable_tx=True)


if __name__ == '__main__':
    unittest.main()
