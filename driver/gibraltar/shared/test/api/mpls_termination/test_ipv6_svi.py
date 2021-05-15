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


import sys
import unittest
from leaba import sdk
import ip_test_base
from scapy.all import *
import sim_utils
import topology as T
import packet_test_utils as U
from mpls_termination_base import *
import decor

load_contrib('mpls')


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ipv6_svi_test(mpls_termination_base):
    ip_impl_class = ip_test_base.ipv6_test_base
    l3_port_impl_class = T.ip_svi_base
    SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

    INPUT_PACKET_SINGLE_NULL_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str,
              src=mpls_termination_base.SA.addr_str,
              type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1,
              type=U.Ethertype.MPLS.value) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV4,
             cos=mpls_termination_base.MPLS_QOS,
             ttl=mpls_termination_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str,
             dst=DIP.addr_str,
             hlim=mpls_termination_base.IP_TTL,
             plen=40,
             tc=mpls_termination_base.EXPECTED_IP_TOS)

    INPUT_PACKET_SINGLE_NULL_VPN_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str,
              src=mpls_termination_base.SA.addr_str,
              type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1,
              type=U.Ethertype.MPLS.value) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV4,
             cos=mpls_termination_base.MPLS_QOS,
             ttl=mpls_termination_base.MPLS_TTL,
             s=0) / \
        MPLS(label=mpls_termination_base.VPN_LABEL.label,
             ttl=mpls_termination_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str,
             dst=DIP.addr_str,
             hlim=mpls_termination_base.IP_TTL,
             plen=40,
             tc=mpls_termination_base.EXPECTED_IP_TOS)

    INPUT_PACKET_TWO_NULLS_OUTER_V4_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str,
              src=mpls_termination_base.SA.addr_str,
              type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1,
              type=U.Ethertype.MPLS.value) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV4,
             cos=mpls_termination_base.MPLS_QOS,
             ttl=mpls_termination_base.MPLS_TTL,
             s=0) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV4,
             ttl=mpls_termination_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str,
             dst=DIP.addr_str,
             hlim=mpls_termination_base.IP_TTL,
             plen=40,
             tc=mpls_termination_base.EXPECTED_IP_TOS)

    INPUT_PACKET_TWO_NULLS_OUTER_V4_VPN_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str,
              src=mpls_termination_base.SA.addr_str,
              type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1,
              type=U.Ethertype.MPLS.value) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV4,
             cos=mpls_termination_base.MPLS_QOS,
             ttl=mpls_termination_base.MPLS_TTL,
             s=0) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV4,
             ttl=mpls_termination_base.MPLS_TTL,
             s=0) / \
        MPLS(label=mpls_termination_base.VPN_LABEL.label,
             ttl=mpls_termination_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str,
             dst=DIP.addr_str,
             hlim=mpls_termination_base.IP_TTL,
             plen=40,
             tc=mpls_termination_base.EXPECTED_IP_TOS)

    INPUT_PACKET_TWO_NULLS_OUTER_V6_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str,
              src=mpls_termination_base.SA.addr_str,
              type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1,
              type=U.Ethertype.MPLS.value) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6,
             cos=mpls_termination_base.MPLS_QOS,
             ttl=mpls_termination_base.MPLS_TTL,
             s=0) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV4,
             ttl=mpls_termination_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str,
             dst=DIP.addr_str,
             hlim=mpls_termination_base.IP_TTL,
             plen=40,
             tc=mpls_termination_base.EXPECTED_IP_TOS)

    EXPECTED_OUTPUT_PACKET_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str,
              src=T.TX_SVI_MAC.addr_str) / \
        IPv6(src=SIP.addr_str,
             dst=DIP.addr_str,
             tc=mpls_termination_base.EXPECTED_IP_TOS,
             hlim=mpls_termination_base.IP_TTL - 1,
             plen=40)

    EXPECTED_OUTPUT_PACKET_UNIFORM_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str,
              src=T.TX_SVI_MAC.addr_str) / \
        IPv6(src=SIP.addr_str,
             dst=DIP.addr_str,
             tc=mpls_termination_base.EXPECTED_IP_TOS,
             hlim=mpls_termination_base.MPLS_TTL - 1,
             plen=40)

    INPUT_PACKET_SINGLE_NULL, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_SINGLE_NULL_BASE)
    INPUT_PACKET_SINGLE_NULL_VPN = U.add_payload(INPUT_PACKET_SINGLE_NULL_VPN_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_TWO_NULLS_OUTER_V4 = U.add_payload(INPUT_PACKET_TWO_NULLS_OUTER_V4_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_TWO_NULLS_OUTER_V4_VPN = U.add_payload(INPUT_PACKET_TWO_NULLS_OUTER_V4_VPN_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_TWO_NULLS_OUTER_V6 = U.add_payload(INPUT_PACKET_TWO_NULLS_OUTER_V6_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_UNIFORM = U.add_payload(EXPECTED_OUTPUT_PACKET_UNIFORM_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

    def test_single_null(self):
        self._test_single_null()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_single_null_vpn(self):
        self._test_single_null_vpn()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_single_null_vpn_with_counter(self):
        self._test_single_null_vpn_with_counter()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_single_null_vpn_uniform(self):
        self._test_single_null_vpn_uniform()

    def test_ttl_mode_uniform(self):
        self._test_ttl_mode_uniform()

    def test_two_nulls_outer_v4(self):
        self._test_two_nulls_outer_v4()

    def test_two_nulls_outer_v6(self):
        self._test_two_nulls_outer_v6()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_two_nulls_vpn(self):
        self._test_two_nulls_vpn()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_two_nulls_vpn_uniform(self):
        self._test_two_nulls_vpn_uniform()


if __name__ == '__main__':
    unittest.main()
