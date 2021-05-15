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

import decor
from cbf_base import *
import sim_utils
import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
import ip_test_base
import decor


class ipv6_l3_ac_test(cbf_base):
    protocol = sdk.la_l3_protocol_e_IPV6_UC
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl = ip_test_base.ipv6_test_base

    SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')
    LEN = 24

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=cbf_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=cbf_base.INPUT_LABEL0.label, ttl=cbf_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=cbf_base.IP_TTL) / TCP()

    INPUT_PACKET_IP_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=cbf_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=cbf_base.IP_TTL) / TCP()

    INPUT_PACKET_IP_EXP_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=cbf_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=cbf_base.IP_TTL, tc=8) / TCP()

    INPUT_PACKET_WITH_EXP_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=cbf_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=cbf_base.INPUT_LABEL0.label, cos=1, ttl=cbf_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=cbf_base.IP_TTL) / TCP()

    EXPECTED_OUTPUT_SWAP_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=cbf_base.OUTPUT_LABEL0.label, ttl=cbf_base.MPLS_TTL - 1) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=cbf_base.IP_TTL) / TCP()

    EXPECTED_OUTPUT_IP_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=cbf_base.OUTPUT_LABEL0.label, ttl=255) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=cbf_base.IP_TTL - 1) / TCP()

    EXPECTED_OUTPUT_SWAP_PACKET_BASE_EXP = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=cbf_base.OUTPUT_LABEL0.label, ttl=cbf_base.MPLS_TTL - 1, cos=1) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=cbf_base.IP_TTL) / TCP()

    EXPECTED_OUTPUT_IP_PACKET_BASE_EXP = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=cbf_base.OUTPUT_LABEL0.label, ttl=255, cos=1) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=cbf_base.IP_TTL - 1, tc=8) / TCP()

    EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=cbf_base.OUTPUT_LABEL2.label, cos=1, ttl=cbf_base.MPLS_TTL - 1) / \
        MPLS(label=cbf_base.OUTPUT_LABEL1.label, cos=1, ttl=cbf_base.MPLS_TTL - 1) / \
        MPLS(label=cbf_base.OUTPUT_LABEL0.label, cos=1, ttl=cbf_base.MPLS_TTL - 1) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=cbf_base.IP_TTL) / TCP()

    EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET_IP_BASE = \
        Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=cbf_base.OUTPUT_LABEL2.label, cos=1, ttl=255) / \
        MPLS(label=cbf_base.OUTPUT_LABEL1.label, cos=1, ttl=255) / \
        MPLS(label=cbf_base.OUTPUT_LABEL0.label, cos=1, ttl=255) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=cbf_base.IP_TTL - 1, tc=8) / TCP()

    INPUT_PACKET_IP, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_IP_BASE)
    EXPECTED_OUTPUT_IP_PACKET = U.add_payload(EXPECTED_OUTPUT_IP_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_IP_PACKET_EXP = U.add_payload(EXPECTED_OUTPUT_IP_PACKET_BASE_EXP, BASE_INPUT_PACKET_PAYLOAD_SIZE)

    INPUT_PACKET_IP_EXP, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_IP_EXP_BASE)
    EXPECTED_OUTPUT_IP_MULTIPLE_LABELS_PACKET = U.add_payload(
        EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET_IP_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

    INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    INPUT_PACKET_WITH_EXP, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_EXP_BASE)
    EXPECTED_OUTPUT_SWAP_PACKET = U.add_payload(EXPECTED_OUTPUT_SWAP_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_SWAP_PACKET_EXP = U.add_payload(EXPECTED_OUTPUT_SWAP_PACKET_BASE_EXP, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET = U.add_payload(
        EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_pacific(), "Test is not yet enabled on Pacific")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_cbf_ecmp_mpls(self):
        self.inputs = [self.INPUT_PACKET, self.INPUT_PACKET_WITH_EXP]
        self.outputs = [
            self.EXPECTED_OUTPUT_SWAP_PACKET,
            self.EXPECTED_OUTPUT_SWAP_PACKET_EXP,
            self.EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET]
        self.prefix_object_class = T.prefix_object
        self.is_ecmp = True
        self._test_swap_cbf()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_pacific(), "Test is not yet enabled on Pacific")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_cbf_nh_mpls(self):
        self.inputs = [self.INPUT_PACKET, self.INPUT_PACKET_WITH_EXP]
        self.outputs = [
            self.EXPECTED_OUTPUT_SWAP_PACKET,
            self.EXPECTED_OUTPUT_SWAP_PACKET_EXP,
            self.EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET]
        self.prefix_object_class = T.prefix_object
        self._test_swap_cbf()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_pacific(), "Test is not yet enabled on Pacific")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_global_cbf_ecmp_mpls(self):
        self.inputs = [self.INPUT_PACKET, self.INPUT_PACKET_WITH_EXP]
        self.outputs = [
            self.EXPECTED_OUTPUT_SWAP_PACKET,
            self.EXPECTED_OUTPUT_SWAP_PACKET_EXP,
            self.EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET]
        self.is_ecmp = True
        self.is_prefix_object_global = True
        self.prefix_object_class = T.global_prefix_object
        self._test_swap_cbf()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_pacific(), "Test is not yet enabled on Pacific")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def _test_global_cbf_nh_mpls(self):
        self.inputs = [self.INPUT_PACKET, self.INPUT_PACKET_WITH_EXP]
        self.outputs = [
            self.EXPECTED_OUTPUT_SWAP_PACKET,
            self.EXPECTED_OUTPUT_SWAP_PACKET_EXP,
            self.EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET]
        self.prefix_object_class = T.global_prefix_object
        self.is_prefix_object_global = True
        self._test_swap_cbf()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_pacific(), "Test is not yet enabled on Pacific")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_cbf_ecmp_ip(self):
        self.inputs = [self.INPUT_PACKET_IP, self.INPUT_PACKET_IP_EXP]
        self.outputs = [
            self.EXPECTED_OUTPUT_IP_PACKET,
            self.EXPECTED_OUTPUT_IP_PACKET_EXP,
            self.EXPECTED_OUTPUT_IP_MULTIPLE_LABELS_PACKET]
        self.prefix_object_class = T.prefix_object
        self.is_ecmp = True
        self._test_swap_cbf()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_pacific(), "Test is not yet enabled on Pacific")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_cbf_nh_ip(self):
        self.inputs = [self.INPUT_PACKET_IP, self.INPUT_PACKET_IP_EXP]
        self.outputs = [
            self.EXPECTED_OUTPUT_IP_PACKET,
            self.EXPECTED_OUTPUT_IP_PACKET_EXP,
            self.EXPECTED_OUTPUT_IP_MULTIPLE_LABELS_PACKET]
        self.prefix_object_class = T.prefix_object
        self._test_swap_cbf()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_pacific(), "Test is not yet enabled on Pacific")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_global_cbf_ecmp_ip(self):
        self.inputs = [self.INPUT_PACKET_IP, self.INPUT_PACKET_IP_EXP]
        self.outputs = [
            self.EXPECTED_OUTPUT_IP_PACKET,
            self.EXPECTED_OUTPUT_IP_PACKET_EXP,
            self.EXPECTED_OUTPUT_IP_MULTIPLE_LABELS_PACKET]
        self.is_ecmp = True
        self.is_prefix_object_global = True
        self.prefix_object_class = T.global_prefix_object
        self._test_swap_cbf()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_pacific(), "Test is not yet enabled on Pacific")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def _test_global_cbf_nh_ip(self):
        self.inputs = [self.INPUT_PACKET_IP, self.INPUT_PACKET_IP_EXP]
        self.outputs = [
            self.EXPECTED_OUTPUT_IP_PACKET,
            self.EXPECTED_OUTPUT_IP_PACKET_EXP,
            self.EXPECTED_OUTPUT_IP_MULTIPLE_LABELS_PACKET]
        self.prefix_object_class = T.global_prefix_object
        self.is_prefix_object_global = True
        self._test_swap_cbf()


if __name__ == '__main__':
    unittest.main()
