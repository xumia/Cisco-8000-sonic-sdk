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

from leaba import sdk
import packet_test_utils as U
import topology as T
from sdk_test_case_base import sdk_test_case_base


class ip_tunnel_transit_counter_base(sdk_test_case_base):
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    TTL = 128
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    def setUp(self):
        super().setUp()
        self.ip_impl = self.ip_impl_class()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)
        self.add_default_route()
        self.add_ip_prefix()
        self.set_transit_counter()

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh,
                               ip_tunnel_transit_counter_base.PRIVATE_DATA_DEFAULT)

    def set_transit_counter(self):
        transit_counter_size = sdk.la_ip_tunnel_type_e_LAST
        self.transit_counter = self.device.create_counter(transit_counter_size)
        self.device.set_ip_tunnel_transit_counter(self.transit_counter)

    def add_ip_prefix(self):
        self.prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(
            self.topology.vrf,
            self.prefix,
            self.l3_port_impl.reg_nh,
            ip_tunnel_transit_counter_base.PRIVATE_DATA)

    def remove_ip_prefix(self):
        self.ip_impl.delete_route(self.topology.vrf, self.prefix)

    def _test_transit_counter_gue_pkt(self):
        # Run a packet
        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET_GUE,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_GUE,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

        # Check transit counter
        packet_count, byte_count = self.transit_counter.read(sdk.la_ip_tunnel_type_e_GUE, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthIngress(self, self.INPUT_PACKET_GUE, T.RX_SLICE, byte_count)
        self.remove_ip_prefix()

    def _test_transit_counter_gre_pkt(self):
        # Run a packet
        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET_GRE,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_GRE,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

        # Check transit counter
        packet_count, byte_count = self.transit_counter.read(sdk.la_ip_tunnel_type_e_GRE, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthIngress(self, self.INPUT_PACKET_GRE, T.RX_SLICE, byte_count)
        self.remove_ip_prefix()

    def _test_transit_counter_ip_over_ip_pkt(self):
        # Run a packet
        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET_IP_IN_IP,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_IP_IN_IP,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

        # Check transit counter
        packet_count, byte_count = self.transit_counter.read(sdk.la_ip_tunnel_type_e_IP_IN_IP, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthIngress(self, self.INPUT_PACKET_IP_IN_IP, T.RX_SLICE, byte_count)
        self.remove_ip_prefix()
