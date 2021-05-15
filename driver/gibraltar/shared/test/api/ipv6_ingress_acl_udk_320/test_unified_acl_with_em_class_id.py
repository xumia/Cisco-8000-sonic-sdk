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

import unittest
import decor
from leaba import sdk
from scapy.all import *
from packet_test_utils import *
from ipv6_ingress_acl_class_id_320_base import *
import sim_utils
import topology as T


@unittest.skipUnless(decor.is_gibraltar(), "Class ID tests supported only on GB")
class unified_acl(ipv6_ingress_acl_class_id_320_base):

    @unittest.skipUnless(decor.is_gibraltar(), "Class ID tests supported only on GB")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_unified_acl_with_em_class_id(self):
        acl1 = self.create_lpm_class_id_unified_acl()

        # Test default route
        # Pass packet with no ACL applied, ensure PHB remains default (0).
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0}}
        run_and_compare_inner_fields(self, self.device,
                                     self.INPUT_DEFAULT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3,
                                     control_expected)

        # Attach a Q counter
        q_counter = self.device.create_counter(8)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, q_counter)

        # Attach a P counter
        p_counter = self.device.create_counter(1)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, p_counter)

        # Attach the Unified ACL
        ipv6_acls = []
        ipv6_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # Pass packet with ACL applied, ensure DSCP and PHB changes to non-default.
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1F}}
        expected_output_packet = self.EXPECTED_OUTPUT_EM_PACKET.copy()
        expected_output_packet[IPv6].tc = (QOS_MARK_DSCP << 2)
        run_and_compare_inner_fields(self, self.device,
                                     self.INPUT_EM_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     expected_output_packet, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3,
                                     control_expected)

        # Verify Q counter
        packet_count, byte_count = q_counter.read(SIMPLE_QOS_COUNTER_OFFSET, True, True)
        self.assertEqual(packet_count, 1)
        assertPacketLengthIngress(self, self.INPUT_EM_PACKET, T.RX_SLICE, byte_count)

        # Verify P counter
        packet_count, byte_count = p_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        assertPacketLengthIngress(self, self.INPUT_EM_PACKET, T.RX_SLICE, byte_count)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Pass packet with no ACL applied, ensure PHB remains default (0).
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0}}
        run_and_compare_inner_fields(self, self.device,
                                     self.INPUT_DEFAULT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3,
                                     control_expected)


if __name__ == '__main__':
    unittest.main()
