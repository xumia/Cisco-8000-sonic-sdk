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
import decor
import topology as T
from urpf_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_l3_ac_get_urpf_mode(urpf_base):
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl_class = ip_test_base.ipv6_test_base
    SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

    INPUT_PACKET_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=urpf_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=urpf_base.TTL, plen=40)

    EXPECTED_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=urpf_base.TTL - 1, plen=40)

    EXPECTED_EXTRA_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str) / \
        S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=urpf_base.TTL - 1, plen=40)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = U.pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
    __, EXPECTED_EXTRA_OUTPUT_PACKET = U.pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_EXTRA_OUTPUT_PACKET_BASE)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_urpf_mode(self):
        self._test_get_urpf_mode()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_no_route_to_sender_rpf_loose(self):
        self._test_no_route_to_sender_rpf_loose()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_no_route_to_sender_rpf_loose_nh(self):
        self._test_no_route_to_sender_rpf_loose_nh()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_loose_route_to_sender_rpf_loose(self):
        self._test_loose_route_to_sender_rpf_loose()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_loose_route_to_sender_in_both_em_and_lpm_rpf_loose_nh(self):
        self._test_loose_route_to_sender_rpf_loose_em_prefix(is_em=True,
                                                             is_em_strict=False, is_lpm=True, is_lpm_strict=False,
                                                             is_fec=False, default_route_in_lpm=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_loose_route_to_sender_in_em_lpm_default_rpf_loose_nh(self):
        self._test_loose_route_to_sender_rpf_loose_em_prefix(is_em=True,
                                                             is_em_strict=False, is_lpm=False, is_lpm_strict=False,
                                                             is_fec=False, default_route_in_lpm=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_loose_route_to_sender_in_both_em_and_lpm_rpf_loose_fec(self):
        self._test_loose_route_to_sender_rpf_loose_em_prefix(is_em=True,
                                                             is_em_strict=False, is_lpm=True, is_lpm_strict=False,
                                                             is_fec=True, default_route_in_lpm=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_loose_route_to_sender_in_em_lpm_default_rpf_loose_fec(self):
        self._test_loose_route_to_sender_rpf_loose_em_prefix(is_em=True,
                                                             is_em_strict=False, is_lpm=False, is_lpm_strict=False,
                                                             is_fec=True, default_route_in_lpm=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - NP2 compound")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_loose_route_to_sender_rpf_strict(self):
        self._test_loose_route_to_sender_rpf_strict()

    @unittest.skipIf(decor.is_hw_gibraltar(), "SKIP-GB-HW")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_loose_route_to_sender_in_both_em_lpm_rpf_strict_nh(self):
        self._test_loose_route_to_sender_rpf_strict_em_prefix(is_em=True,
                                                              is_em_strict=False, is_lpm=True, is_lpm_strict=False,
                                                              is_fec=False, default_route_in_lpm=False)

    @unittest.skipIf(decor.is_hw_gibraltar(), "SKIP-GB-HW")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_loose_route_to_sender_in_both_em_lpm_rpf_strict_fec(self):
        self._test_loose_route_to_sender_rpf_strict_em_prefix(is_em=True,
                                                              is_em_strict=False, is_lpm=True, is_lpm_strict=False,
                                                              is_fec=True, default_route_in_lpm=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_no_route_to_sender_rpf_none(self):
        self._test_no_route_to_sender_rpf_none()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_no_route_to_sender_rpf_strict(self):
        self._test_no_route_to_sender_rpf_strict()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_strict_route_to_sender_rpf_loose(self):
        self._test_strict_route_to_sender_rpf_loose()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_strict_route_to_sender_in_em_rpf_loose_nh(self):
        self._test_strict_route_to_sender_rpf_loose_em_prefix(is_em=True,
                                                              is_em_strict=True, is_lpm=False, is_lpm_strict=False,
                                                              is_fec=False, default_route_in_lpm=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_strict_route_to_sender_in_em_rpf_loose_fec(self):
        self._test_strict_route_to_sender_rpf_loose_em_prefix(is_em=True,
                                                              is_em_strict=True, is_lpm=False, is_lpm_strict=False,
                                                              is_fec=True, default_route_in_lpm=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_strict_route_to_sender_rpf_strict(self):
        self._test_strict_route_to_sender_rpf_strict()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_strict_route_to_sender_in_em_lpm_default_rpf_strict_nh(self):
        self._test_strict_route_to_sender_rpf_strict_em_prefix(is_em=True,
                                                               is_em_strict=True, is_lpm=False, is_lpm_strict=False,
                                                               is_fec=False, default_route_in_lpm=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_strict_route_to_sender_in_both_em_lpm_rpf_strict_nh(self):
        self._test_strict_route_to_sender_rpf_strict_em_prefix(is_em=True,
                                                               is_em_strict=True, is_lpm=True, is_lpm_strict=True,
                                                               is_fec=False, default_route_in_lpm=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_strict_route_to_sender_in_em_lpm_loose_route_rpf_strict_nh(self):
        self._test_strict_route_to_sender_rpf_strict_em_prefix(is_em=True,
                                                               is_em_strict=True, is_lpm=True, is_lpm_strict=False,
                                                               is_fec=False, default_route_in_lpm=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_strict_route_to_sender_in_em_lpm_default_rpf_strict_fec(self):
        self._test_strict_route_to_sender_rpf_strict_em_prefix(is_em=True,
                                                               is_em_strict=True, is_lpm=False, is_lpm_strict=False,
                                                               is_fec=True, default_route_in_lpm=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_strict_route_to_sender_in_both_em_lpm_rpf_strict_fec(self):
        self._test_strict_route_to_sender_rpf_strict_em_prefix(is_em=True,
                                                               is_em_strict=True, is_lpm=True, is_lpm_strict=True,
                                                               is_fec=True, default_route_in_lpm=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_strict_route_to_sender_in_em_lpm_loose_route_rpf_strict_fec(self):
        self._test_strict_route_to_sender_rpf_strict_em_prefix(is_em=True,
                                                               is_em_strict=True, is_lpm=True, is_lpm_strict=False,
                                                               is_fec=True, default_route_in_lpm=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_default_route_to_sender_rpf_loose(self):
        self._test_default_route_to_sender_rpf_loose()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_default_route_to_sender_rpf_loose_allow_default(self):
        self._test_default_route_to_sender_rpf_loose_allow_default()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_for_us_route_to_sender_rpf_loose(self):
        self._test_for_us_route_to_sender_rpf_loose()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_no_route_to_sender_dest_for_us_rpf_loose(self):
        self._test_no_route_to_sender_dest_for_us_rpf_loose()


if __name__ == '__main__':
    unittest.main()
