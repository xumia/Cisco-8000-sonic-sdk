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
from scapy.all import *
from packet_test_utils import *
from ipv4_ingress_acl_udk_160_base import *
import sim_utils
import topology as T


@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
class unified_acl(ipv4_ingress_acl_udk_160_base):

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_acl_override_phb(self):
        acl1 = self.create_simple_unified_acl(True)

        self.device.set_trap_configuration(
            sdk.LA_EVENT_L3_ACL_FORCE_PUNT,
            0,
            None,
            self.punt_dest,
            False,
            False,
            True,
            0)

        # Test default route
        # Pass packet with no ACL applied, ensure PHB remains default (0).
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0}}
        run_and_compare_inner_fields(self, self.device,
                                     INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                     control_expected)

        # Attach the Unified ACL
        ipv4_acls = []
        ipv4_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # Pass packet with ACL applied, ensure DSCP and PHB are default.
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0}}
        expected_output_packet = EXPECTED_EXTRA_OUTPUT_PACKET.copy()
        expected_output_packet[IP].tos = QOS_MARK_DSCP << 2
        run_and_compare_inner_fields(self, self.device,
                                     INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     PUNT_PACKET, self.PUNT_SLICE, PUNT_IFG, PUNT_PIF_FIRST,
                                     control_expected)

        self.device.set_trap_configuration(
            sdk.LA_EVENT_L3_ACL_FORCE_PUNT,
            0,
            None,
            self.punt_dest,
            False,
            False,
            False,
            0)

        # Pass packet with ACL applied, ensure DSCP and PHB changes to non-default.
        # control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1F}}
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1f}}
        expected_output_packet = PUNT_PACKET.copy()
        expected_output_packet[Punt].code = nplapi.NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT + 7
        run_and_compare_inner_fields(self, self.device,
                                     INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     expected_output_packet, self.PUNT_SLICE, PUNT_IFG, PUNT_PIF_FIRST,
                                     control_expected)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Pass packet with no ACL applied, ensure PHB remains default (0).
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0}}
        run_and_compare_inner_fields(self, self.device,
                                     INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                     control_expected)


if __name__ == '__main__':
    unittest.main()
