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

import decor
import sys
import unittest
from leaba import sdk
import ip_test_base
import packet_test_utils as U
import scapy.all as S
import sim_utils
import topology as T
from sdk_test_case_base import *
from enum import IntEnum


class ecn_codes(IntEnum):
    NON_ECT = 0,    # Non ECN-Capable transport
    ECT_1 = 1,    # ECN Capable Transport
    ECT_2 = 2,    # ECN Capable Transport
    CE = 3     # Congestion Encountered


class ecn_remark_test(sdk_test_case_base):
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    TTL = 128
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    def setUp(self):
        super().setUp()

        self.ip_impl = self.ip_impl_class()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)
        self.add_default_route()
        self.create_packets()

    def create_packets(self):
        INPUT_PACKET_BASE = S.Ether(dst=self.input_ether_0_dst,
                                    src=self.SA.addr_str,
                                    type=U.Ethertype.Dot1Q.value) / U.Dot1QPrio(vlan=self.input_dot1q_0_vlan) / U.IPvX(ipvx=self.ipvx,
                                                                                                                       src=self.SIP.addr_str,
                                                                                                                       dst=self.DIP.addr_str,
                                                                                                                       ttl=self.TTL) / U.TCP()

        EXPECTED_OUTPUT_PACKET_BASE = S.Ether(dst=self.output_ether_0_dst, src=self.output_ether_0_src) / U.IPvX(
            ipvx=self.ipvx,
            src=self.SIP.addr_str,
            dst=self.DIP.addr_str,
            ttl=self.TTL - 1) / U.TCP()

        self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET = U.pad_input_and_output_packets(
            INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()

        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh, self.PRIVATE_DATA_DEFAULT)

    def do_route_single_fec(self, congestion=False):
        cong_on = 0x0
        if congestion:
            cong_on = 0x1

        if self.device.ll_device.is_asic4():
            congestion_input = "txpp_npu_input.sms_rd_pd.congested"
        else:
            congestion_input = "txpp_npu_input.sms_rd_pd.cong_on"

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg,
                          initial_metadata_values_dict={congestion_input: cong_on})

    def do_test_ecn_remark(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        self.l3_port_impl.tx_port.hld_obj.set_ecn_remark_enabled(True)
        self.assertEqual(self.l3_port_impl.tx_port.hld_obj.get_ecn_remark_enabled(), True)

        is_ipv6 = False
        if self.INPUT_PACKET.version == 6:
            is_ipv6 = True

        # enabled remarking; congestion
        for ecn in ecn_codes:
            if is_ipv6:
                self.INPUT_PACKET.tc = ecn.value
                if ecn.value > ecn_codes.NON_ECT:
                    self.EXPECTED_OUTPUT_PACKET.tc = ecn_codes.CE
            else:
                self.INPUT_PACKET.tos = ecn.value
                if ecn.value > ecn_codes.NON_ECT:
                    self.EXPECTED_OUTPUT_PACKET.tos = ecn_codes.CE

            self.do_route_single_fec(congestion=True)

        # enabled remarking; no congestion
        for ecn in ecn_codes:
            if is_ipv6:
                self.INPUT_PACKET.tc = ecn
                self.EXPECTED_OUTPUT_PACKET.tc = ecn
            else:
                self.INPUT_PACKET.tos = ecn
                self.EXPECTED_OUTPUT_PACKET.tos = ecn

            self.do_route_single_fec(congestion=False)

        # disabled remarking; congestion
        self.l3_port_impl.tx_port.hld_obj.set_ecn_remark_enabled(False)
        for ecn in ecn_codes:
            if is_ipv6:
                self.INPUT_PACKET.tc = ecn
                self.EXPECTED_OUTPUT_PACKET.tc = ecn
            else:
                self.INPUT_PACKET.tos = ecn
                self.EXPECTED_OUTPUT_PACKET.tos = ecn

            self.do_route_single_fec(congestion=True)
            self.do_route_single_fec(congestion=False)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecn_remark(self):
        self.do_test_ecn_remark()


class ipv4_test:
    ip_impl_class = ip_test_base.ipv4_test_base
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    ipvx = 'v4'


class ipv6_test:
    ip_impl_class = ip_test_base.ipv6_test_base
    SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')
    ipvx = 'v6'


class svi_test:
    l3_port_impl_class = T.ip_svi_base

    input_ether_0_dst = T.RX_SVI_MAC.addr_str
    input_dot1q_0_vlan = T.RX_L2_AC_PORT_VID1
    output_ether_0_dst = T.NH_SVI_REG_MAC.addr_str
    output_ether_0_src = T.TX_SVI_MAC.addr_str


class l3_ac_test:
    l3_port_impl_class = T.ip_l3_ac_base

    input_ether_0_dst = T.RX_L3_AC_ONE_TAG_MAC.addr_str
    input_dot1q_0_vlan = T.RX_L3_AC_ONE_TAG_PORT_VID
    output_ether_0_dst = T.NH_L3_AC_REG_MAC.addr_str
    output_ether_0_src = T.TX_L3_AC_REG_MAC.addr_str


if __name__ == '__main__':
    unittest.main()
