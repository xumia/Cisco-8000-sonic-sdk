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
from meter_getters_base import *
import ip_test_base
import packet_test_utils as U
import scapy.all as S
import sim_utils
import topology as T


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class meter_markdown_profile_ip_routing_dscp(meter_getters_base):

    ip_impl_class = ip_test_base.ipv4_test_base
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    ipvx = 'v4'

    l3_port_impl_class = T.ip_l3_ac_base
    input_ether_0_dst = T.RX_L3_AC_ONE_TAG_MAC.addr_str
    input_dot1q_0_vlan = T.RX_L3_AC_ONE_TAG_PORT_VID
    output_ether_0_dst = T.NH_L3_AC_REG_MAC.addr_str
    output_ether_0_src = T.TX_L3_AC_REG_MAC.addr_str

    PRIVATE_DATA = 0x1234567890abcdef
    TTL = 128
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    OUTPUT_VID = 0xac

    def setUp(self):
        super().setUp()
        self.ip_impl = self.ip_impl_class()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)
        self.create_packets()
        self.set_egress_tag_mode()

    def route_single_fec(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def set_egress_tag_mode(self):
        tag = sdk.la_vlan_tag_t()
        tag.tpid = 0x8100
        tag.tci.fields.pcp = 0
        tag.tci.fields.dei = 0
        tag.tci.fields.vid = self.OUTPUT_VID
        self.l3_port_impl.tx_port.hld_obj.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)

    def create_packets(self):
        INPUT_PACKET_BASE = S.Ether(dst=self.input_ether_0_dst,
                                    src=self.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            U.Dot1QPrio(vlan=self.input_dot1q_0_vlan, pcpdei=IN_PCPDEI.flat) / \
            U.IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str,
                   ttl=self.TTL, dscp=IN_DSCP.value, ecn=IP_ECN) / U.TCP()

        EXPECTED_OUTPUT_PACKET_BASE = S.Ether(dst=self.output_ether_0_dst,
                                              src=self.output_ether_0_src, type=U.Ethertype.Dot1Q.value) / \
            U.Dot1QPrio(vlan=self.OUTPUT_VID, pcpdei=OUT_PCPDEI.flat) / \
            U.IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str,
                   ttl=self.TTL - 1, dscp=OUT_DSCP.value, ecn=IP_ECN) / U.TCP()

        self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET = U.pad_input_and_output_packets(
            INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_meter_markdown_mapping_dscp_ext(self):
        self._test_meter_markdown_mapping_dscp_ext()


if __name__ == '__main__':
    unittest.main()
