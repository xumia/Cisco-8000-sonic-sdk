#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

# Test to check solution for CSCvh50533.

# Problem description:
#
# SDK does not properly update PxVxV mapping tables when set_service_mapping_vid is called.
# Changing the VID to VID2 and back to original VID reports an EBUSY.

import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import sim_utils
import topology as T
import ip_test_base
from packet_test_defs import *
from sdk_test_case_base import *
import decor

CHAR_BIT = 8
BYTES_NUM_IN_ADDR = 4


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l3_qos_profile(sdk_test_case_base):

    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    TTL = 128
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    IPV6_SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    IPV6_DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

    def setUp(self):
        super().setUp()
        self.add_default_route()
        self.add_default_ipv6_route()
        self.create_and_assign_qos_profiles()
        self.ipv6_impl = ip_test_base.ipv6_test_base

    def add_default_route(self):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = 0
        prefix.length = 0
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.topology.nh_l3_ac_def.hld_obj,
                                                 self.PRIVATE_DATA_DEFAULT, False)

    def add_default_ipv6_route(self):
        prefix_ipv6 = sdk.la_ipv6_prefix_t()
        sdk.set_ipv6_addr(prefix_ipv6.addr, 0, 0)
        prefix_ipv6.length = 0
        self.topology.vrf.hld_obj.add_ipv6_route(prefix_ipv6, self.topology.nh_l3_ac_def.hld_obj,
                                                 self.PRIVATE_DATA_DEFAULT, False)

    def create_and_assign_qos_profiles(self):
        # Create new ingress/egress qos profiles
        self.rx_port = self.topology.rx_l3_ac.hld_obj
        self.ingress_qos_profile_new = T.ingress_qos_profile(self, self.device)
        self.ingress_qos_profile_new.set_default_values()
        self.rx_port.set_ingress_qos_profile(self.ingress_qos_profile_new.hld_obj)
        self.ingress_qos_counter = self.device.create_counter(sdk.LA_NUM_L3_INGRESS_TRAFFIC_CLASSES)
        self.rx_port.set_ingress_counter(sdk.la_counter_set.type_e_QOS, self.ingress_qos_counter)

        # Create a counter mapping for dscp such that every 2 dscp values map
        # to the same counter offset.
        dscp = sdk.la_ip_dscp()
        for i in range(sdk.LA_MAX_DSCP):
            dscp.value = i
            self.ingress_qos_profile_new.hld_obj.set_meter_or_counter_offset_mapping(sdk.la_ip_version_e_IPV4, dscp, i // 2)
            self.ingress_qos_profile_new.hld_obj.set_meter_or_counter_offset_mapping(sdk.la_ip_version_e_IPV6, dscp, i // 4)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l3_qos_profile(self):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = ip_test_base.ipv4_test_base.apply_prefix_mask(self.DIP.to_num(), 16)
        prefix.length = 16
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.topology.fec_l3_ac_reg.hld_obj,
                                                 self.PRIVATE_DATA, False)

        for i in range(sdk.LA_MAX_DSCP):
            INPUT_PACKET_BASE = \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.SA.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                IPvX(ipvx='v4', src=self.SIP.addr_str, dst=self.DIP.addr_str, dscp=i, ttl=self.TTL)

            EXPECTED_OUTPUT_PACKET_BASE = \
                S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
                IPvX(ipvx='v4', src=self.SIP.addr_str, dst=self.DIP.addr_str, dscp=i, ttl=self.TTL - 1)

            INPUT_PACKET, pad_len = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
            EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, pad_len)

            U.run_and_compare(self, self.device,
                              INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                              EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

            packets, byte_count = self.ingress_qos_counter.read(i // 2, True, True)
            self.assertEqual(packets, 1)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l3_ipv6_qos_profile(self):
        prefix_ipv6 = self.ipv6_impl.build_prefix(self.IPV6_DIP, length=64)
        self.topology.vrf.hld_obj.add_ipv6_route(prefix_ipv6, self.topology.fec_l3_ac_reg.hld_obj,
                                                 self.PRIVATE_DATA, False)

        for i in range(sdk.LA_MAX_DSCP):
            INPUT_PACKET_BASE = \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.SA.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                IPvX(ipvx='v6', src=self.IPV6_SIP.addr_str, dst=self.IPV6_DIP.addr_str, dscp=i, ttl=self.TTL, plen=40)
            EXPECTED_OUTPUT_PACKET_BASE = \
                S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
                IPvX(ipvx='v6', src=self.IPV6_SIP.addr_str, dst=self.IPV6_DIP.addr_str, dscp=i, ttl=self.TTL - 1, plen=40)

            INPUT_PACKET, pad_len = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
            EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, pad_len)

            U.run_and_compare(self, self.device,
                              INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                              EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

            packets, byte_count = self.ingress_qos_counter.read(i // 4, True, True)
            self.assertEqual(packets, 1)


if __name__ == '__main__':
    unittest.main()
