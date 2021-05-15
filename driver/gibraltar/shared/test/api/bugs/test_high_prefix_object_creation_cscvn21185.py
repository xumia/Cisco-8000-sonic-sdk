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

# Test covering CSCvn21185.
#
# Creates and verifies a LSP Prefix object with a GID just below the maximum
# supported GID.

from scapy.all import *
import sys
import unittest
from leaba import sdk
import sim_utils
import topology as T
import packet_test_utils as U
import ip_test_base
import decor

U.parse_ip_after_mpls()

SIP = T.ipv4_addr('12.10.12.10')
DIP = T.ipv4_addr('82.81.95.250')
PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
IP_TTL = 0x88
MPLS_TTL = 0xff
SA = T.mac_addr('be:ef:5d:35:7a:35')
LDP_LABEL = sdk.la_mpls_label()
LDP_LABEL.label = 0x64


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class high_prefix_object_creation(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(1)

        self.topology = T.topology(self, self.device)

        self.l3_port_impl = T.ip_l3_ac_base(self.topology)
        self.ip_impl = ip_test_base.ipv4_test_base()

        self.add_default_route()

    def tearDown(self):
        self.device.tearDown()

    def add_default_route(self):
        prefix = self.ip_impl.build_prefix(DIP, length=0)
        self.ip_impl.add_route(
            self.topology.vrf,
            prefix,
            self.l3_port_impl.def_nh,
            PRIVATE_DATA_DEFAULT)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_high_prefix_object_creation(self):
        max_pfx_objs = self.device.get_limit(sdk.limit_type_e_DEVICE__MAX_PREFIX_OBJECT_GIDS)
        pfx_obj = T.prefix_object(self, self.device, max_pfx_objs - 1, self.l3_port_impl.reg_nh.hld_obj)

        lsp_labels = []
        lsp_labels.append(LDP_LABEL)

        pfx_obj.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels,
                                              None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj, PRIVATE_DATA_DEFAULT)

        INPUT_PACKET_BASE = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=IP_TTL)

        EXPECTED_OUTPUT_PACKET_MPLS_BASE = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
            MPLS(label=LDP_LABEL.label, ttl=MPLS_TTL) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=IP_TTL - 1)

        INPUT_PACKET, EXPECTED_OUTPUT_PACKET_MPLS = U.pad_input_and_output_packets(
            INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_MPLS_BASE)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          EXPECTED_OUTPUT_PACKET_MPLS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)


if __name__ == '__main__':
    unittest.main()
