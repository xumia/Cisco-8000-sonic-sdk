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
import ip_test_base
import packet_test_utils as U
import scapy.all as S
import sim_utils
import topology as T
from sdk_test_case_base import sdk_test_case_base


class ip_routing_counters_base(sdk_test_case_base):
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    TTL = 128
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    OUTPUT_VID = 0xac

    def setUp(self):
        super().setUp()
        self.ip_impl = self.ip_impl_class()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)
        self.add_default_route()

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh,
                               ip_routing_counters_base.PRIVATE_DATA_DEFAULT)

    def _test_counter_route_single_nh(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        counter_set_size = 1
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_nh, ip_routing_counters_base.PRIVATE_DATA)

        # Create and set L2 ingress counter
        l2_ingress_counter = self.device.create_counter(counter_set_size)
        self.topology.rx_l2_ac_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, l2_ingress_counter)

        # Create and set L2 egress counter
        l2_egress_counter = self.device.create_counter(counter_set_size)
        self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, l2_egress_counter)

        # Create and set L3 ingress counter
        l3_ingress_counter = self.device.create_counter(counter_set_size)
        self.l3_port_impl.rx_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, l3_ingress_counter)

        # Create and set L3 egress counter
        l3_egress_counter = self.device.create_counter(counter_set_size)
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, l3_egress_counter)

        # Run a packet
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        # Check L2 ingress counter
        packet_count, byte_count = l2_ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthIngress(self, self.INPUT_PACKET, T.RX_SLICE, byte_count)

        # Check L2 egress counter
        packet_count, byte_count = l2_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)

        # Check L3 ingress counter
        packet_count, byte_count = l3_ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthIngress(self, self.INPUT_PACKET, T.RX_SLICE, byte_count)

        # Check L3 egress counter
        packet_count, byte_count = l3_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)

    def _test_counter_route_single_nh_pkt_count(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        ingress_l2_counter_set_size = sdk.la_rate_limiters_packet_type_e_LAST
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_nh, ip_routing_counters_base.PRIVATE_DATA)

        # Create and set L2 ingress counter
        ingress_l2_counter = self.device.create_counter(ingress_l2_counter_set_size)
        self.topology.rx_l2_ac_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, ingress_l2_counter)

        # Run a packet
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        # Check L2 ingress counter
        packet_count, byte_count = ingress_l2_counter.read(sdk.la_rate_limiters_packet_type_e_UC, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthIngress(self, self.INPUT_PACKET, T.RX_SLICE, byte_count)
