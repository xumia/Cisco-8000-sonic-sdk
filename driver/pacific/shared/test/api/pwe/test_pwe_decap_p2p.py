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
import unittest
from leaba import sdk
import packet_test_utils as U
from scapy.all import *
from pwe_decap_base import *
import sim_utils
import topology as T

# This test assumes that MPLS bottom-of-stack label is followed by Ether
bind_layers(MPLS, Ether, s=1)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class pwe_decap_p2p(pwe_decap_base):
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_p2p_attach(self):
        self._test_pwe_decap_p2p_attach()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_p2p_null_attach(self):
        self._test_pwe_decap_p2p_null_attach()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_p2p_detach(self):
        self._test_pwe_decap_p2p_detach()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_p2p_cw(self):
        self._test_pwe_decap_p2p_cw()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_p2p_flow_label(self):
        self._test_pwe_decap_p2p_flow_label()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_p2p_ac_vlan_pop_1(self):
        self._test_pwe_decap_p2p_ac_vlan_pop_1()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_p2p_ac_vlan_push_1(self):
        self._test_pwe_decap_p2p_ac_vlan_push_1()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_p2p_ac_translate_1_1(self):
        self._test_pwe_decap_p2p_ac_translate_1_1()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_p2p_cw_flow_label(self):
        self._test_pwe_decap_p2p_cw_flow_label()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_p2p_cw_punt(self):
        self._test_pwe_decap_p2p_cw_punt()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_scale(self):
        self._test_pwe_scale()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_p2p_null_drop_ttl_1(self):
        self._test_pwe_decap_p2p_null_drop_ttl_1()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_p2p_drop_ttl_1(self):
        self._test_pwe_decap_p2p_drop_ttl_1()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_p2p_l3_ac_ingress(self):
        self._test_pwe_decap_p2p_l3_ac_ingress()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_p2p_mpls(self):
        self._test_pwe_decap_p2p_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_p2p_icmp_translate_1(self):
        self._test_pwe_decap_p2p_icmp_translate_1()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_p2p_dhcp_translate_1(self):
        self._test_pwe_decap_p2p_dhcp_translate_1()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_p2p_arp_pop_1(self):
        self._test_pwe_decap_p2p_arp_pop_1()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pwe_decap_p2p_stp_norewrite(self):
        self._test_pwe_decap_p2p_stp_norewrite()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_pwe_decap_p2p_port_channel_ingress(self):
        self._test_pwe_decap_p2p_port_channel_ingress()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_pwe_decap_p2p_port_channel_ingress_pop_1(self):
        self._test_pwe_decap_p2p_port_channel_ingress_pop_1()

    @unittest.skipIf(decor.is_hw_device(), "Skip port channel on egress test for HW device")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_pwe_decap_p2p_port_channel_egress(self):
        self._test_pwe_decap_p2p_port_channel_egress()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_pwe_decap_p2p_multicast_payload(self):
        self._test_pwe_decap_p2p_multicast_payload()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_pwe_decap_p2p_port_channel_ingress_translate_2(self):
        self._test_pwe_decap_p2p_port_channel_ingress_translate_2()

    @unittest.skipIf(decor.is_hw_device(), "Skip inject packet test for HW device")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_pwe_decap_p2p_inject(self):
        self._test_pwe_decap_p2p_inject()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_pwe_decap_p2p_multicast_ipv6_payload(self):
        self._test_pwe_decap_p2p_multicast_ipv6_payload()


if __name__ == '__main__':
    unittest.main()
