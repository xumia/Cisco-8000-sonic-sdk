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
from mpls_headend_base_disable_mpls_sr import *
import sim_utils
import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
import ip_test_base


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ipv4_l3_ac(mpls_headend_base_disable_mpls_sr):
    protocol = sdk.la_l3_protocol_e_IPV4_UC
    php_protocol = sdk.la_l3_protocol_e_IPV4_UC
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl_class = ip_test_base.ipv4_test_base
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_headend_base_disable_mpls_sr.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base_disable_mpls_sr.IP_TTL)

    EXPECTED_OUTPUT_PACKET_IP_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base_disable_mpls_sr.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_MPLS_UNIFORM_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base_disable_mpls_sr.LDP_LABEL.label, ttl=mpls_headend_base_disable_mpls_sr.IP_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base_disable_mpls_sr.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_SR_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base_disable_mpls_sr.SR_LABEL2.label, ttl=mpls_headend_base_disable_mpls_sr.MPLS_TTL) / \
        MPLS(label=mpls_headend_base_disable_mpls_sr.SR_LABEL1.label, ttl=mpls_headend_base_disable_mpls_sr.MPLS_TTL) / \
        MPLS(label=mpls_headend_base_disable_mpls_sr.SR_LABEL0.label, ttl=mpls_headend_base_disable_mpls_sr.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base_disable_mpls_sr.IP_TTL - 1)

    INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    EXPECTED_OUTPUT_PACKET_IP = U.add_payload(EXPECTED_OUTPUT_PACKET_IP_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_MPLS_UNIFORM = U.add_payload(EXPECTED_OUTPUT_PACKET_MPLS_UNIFORM_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SR = U.add_payload(EXPECTED_OUTPUT_PACKET_SR_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_nh_to_ip_uniform(self):
        self._test_prefix_nh_to_ip_uniform()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_nh_to_mpls_uniform(self):
        self._test_prefix_nh_to_mpls_uniform()


if __name__ == '__main__':
    unittest.main()
