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
from mpls_to_mpls_headend_base_disable_mpls_sr import *
import sim_utils
import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
import ip_test_base


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ipv6_svi_test(mpls_to_mpls_headend_base_disable_mpls_sr):
    protocol = sdk.la_l3_protocol_e_IPV6_UC
    l3_port_impl_class = T.ip_svi_base
    SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_to_mpls_headend_base_disable_mpls_sr.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        MPLS(label=mpls_to_mpls_headend_base_disable_mpls_sr.INPUT_LABEL0.label, ttl=mpls_to_mpls_headend_base_disable_mpls_sr.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_to_mpls_headend_base_disable_mpls_sr.IP_TTL)

    INPUT_PACKET_WITH_EXP_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_to_mpls_headend_base_disable_mpls_sr.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        MPLS(label=mpls_to_mpls_headend_base_disable_mpls_sr.INPUT_LABEL0.label, cos=1, ttl=mpls_to_mpls_headend_base_disable_mpls_sr.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_to_mpls_headend_base_disable_mpls_sr.IP_TTL)

    INPUT_PACKET_DOUBLE_LABEL_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_to_mpls_headend_base_disable_mpls_sr.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        MPLS(label=mpls_to_mpls_headend_base_disable_mpls_sr.INPUT_LABEL0.label, ttl=mpls_to_mpls_headend_base_disable_mpls_sr.MPLS_TTL, s=0) / \
        MPLS(label=mpls_to_mpls_headend_base_disable_mpls_sr.INPUT_LABEL1.label, ttl=mpls_to_mpls_headend_base_disable_mpls_sr.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_to_mpls_headend_base_disable_mpls_sr.IP_TTL)

    EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
        MPLS(label=mpls_to_mpls_headend_base_disable_mpls_sr.OUTPUT_LABEL2.label, cos=1, ttl=mpls_to_mpls_headend_base_disable_mpls_sr.MPLS_TTL - 1) / \
        MPLS(label=mpls_to_mpls_headend_base_disable_mpls_sr.OUTPUT_LABEL1.label, cos=1, ttl=mpls_to_mpls_headend_base_disable_mpls_sr.MPLS_TTL - 1) / \
        MPLS(label=mpls_to_mpls_headend_base_disable_mpls_sr.OUTPUT_LABEL0.label, cos=1, ttl=mpls_to_mpls_headend_base_disable_mpls_sr.MPLS_TTL - 1) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_to_mpls_headend_base_disable_mpls_sr.IP_TTL)

    EXPECTED_OUTPUT_PHP_UNIFORM_PACKET_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_to_mpls_headend_base_disable_mpls_sr.MPLS_TTL - 1)

    EXPECTED_OUTPUT_PHP_UNIFORM_PACKET_WITH_VLAN_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=mpls_to_mpls_headend_base_disable_mpls_sr.OUTPUT_VID + 1) /\
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=mpls_to_mpls_headend_base_disable_mpls_sr.MPLS_TTL - 1)

    INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    INPUT_PACKET_WITH_EXP, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_EXP_BASE)
    INPUT_PACKET_DOUBLE_LABEL = U.add_payload(INPUT_PACKET_DOUBLE_LABEL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET = U.add_payload(
        EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PHP_UNIFORM_PACKET = U.add_payload(EXPECTED_OUTPUT_PHP_UNIFORM_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PHP_UNIFORM_PACKET_WITH_VLAN = U.add_payload(
        EXPECTED_OUTPUT_PHP_UNIFORM_PACKET_WITH_VLAN_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_ecmp_uniform(self):
        # lsp counter over SVI not supported.
        self._test_php_ecmp_uniform(add_lsp_counter=False)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_prefix_global_php_ecmp_uniform(self):
        # lsp counter over SVI not supported.
        self._test_prefix_global_php_ecmp_uniform(add_lsp_counter=False, is_svi=True)

    def test_php_uniform(self):
        # lsp counter over SVI not supported.
        self._test_php_uniform(add_lsp_counter=False)


if __name__ == '__main__':
    unittest.main()
