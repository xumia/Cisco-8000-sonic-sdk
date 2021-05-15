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

from scapy.all import *
from mpls_headend.mpls_headend_ipv6_l3_ac_base import *
import sys
import unittest
from leaba import sdk
import ip_test_base
import sim_utils
import topology as T
import packet_test_utils as U
import decor

U.parse_ip_after_mpls()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_prefix_tenh_to_mpls_CSCvp07859(mpls_headend_ipv6_l3_ac_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_tenh_to_mpls_CSCvp07859(self):
        self.te_tunnel = T.te_tunnel(self, self.device, mpls_headend_base.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        te_labels = []
        te_labels.append(self.PRIMARY_TE_LABEL)

        # This uses a te-tunnel with no associated counter. For usage of TE counter, check ecmp test.
        self.te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, None)
        self.te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        self.pfx_obj = T.prefix_object(self, self.device, mpls_headend_base.PREFIX1_GID, self.te_tunnel.hld_obj)

        prefix = self.ip_impl.build_prefix(self.DIP, length=128)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.pfx_obj,
                               mpls_headend_base.PRIVATE_DATA_DEFAULT, True)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TE, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_TE, byte_count)


if __name__ == '__main__':
    unittest.main()
