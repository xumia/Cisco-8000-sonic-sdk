# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#!/usr/bin/env python3
#
#

from scapy.all import *
from l3_protection_group.l3_protection_group_base import *
import sys
import unittest
from leaba import sdk
from sdk_test_case_base import *
import ip_test_base
import sim_utils
import topology as T
import packet_test_utils as U
import decor
import mtu.mtu_test_utils as MTU
import scapy.all as S

# CSCvw55779
# Tunnel feature GRE/GUE/IP_OVER_IP can have same local_ip_prefix with same mask
# This should be supported from SDK

# CSCvw42308
# GUE/GRE decap need to coexist with overlapping subnet mask for local_ip_prefix

# Any tunnel feature interaction test can be added here for future use


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ip_tunnel_feature_interaction(sdk_test_case_base):
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba987654321
    TUNNEL_TTL = 255
    TTL = 128
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    LOCAL_IP1 = T.ipv4_addr('192.168.95.250')
    GUE_PORT_GID = 0x521
    GRE_PORT_GID = 0x522
    IP_OVER_IP_PORT_GID = 0x523
    LOCAL_IP1 = T.ipv4_addr('192.168.95.250')
    REMOTE_IP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('202.81.95.250')
    SIP = T.ipv4_addr('102.10.12.10')

    INPUT_PACKET_GRE_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=REMOTE_IP.addr_str, dst=LOCAL_IP1.addr_str, ttl=TUNNEL_TTL) / \
        S.GRE() / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

    INPUT_PACKET_GUE_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=REMOTE_IP.addr_str, dst=LOCAL_IP1.addr_str, ttl=TUNNEL_TTL) / \
        S.UDP(sport=0x17ff, dport=0x17c0) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

    INPUT_PACKET_IPIP_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=REMOTE_IP.addr_str, dst=LOCAL_IP1.addr_str, ttl=TUNNEL_TTL) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

    EXPECTED_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1)

    INPUT_PACKET_GUE, EXPECTED_OUTPUT_PACKET_GUE = U.pad_input_and_output_packets(
        INPUT_PACKET_GUE_BASE, EXPECTED_OUTPUT_PACKET_BASE)

    INPUT_PACKET_GRE, EXPECTED_OUTPUT_PACKET_GRE = U.pad_input_and_output_packets(
        INPUT_PACKET_GRE_BASE, EXPECTED_OUTPUT_PACKET_BASE)

    INPUT_PACKET_IPIP, EXPECTED_OUTPUT_PACKET_IPIP = U.pad_input_and_output_packets(
        INPUT_PACKET_IPIP_BASE, EXPECTED_OUTPUT_PACKET_BASE)

    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl = ip_test_base.ipv4_test_base
    ip6_impl = ip_test_base.ipv6_test_base

    def setUp(self):
        super().setUp()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)
        self.add_route()
        self.ingress_counter = self.device.create_counter(1)

    def add_route(self):
        self.overlay_prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(
            self.topology.vrf,
            self.overlay_prefix,
            self.l3_port_impl.reg_fec,
            self.PRIVATE_DATA)

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh, self.PRIVATE_DATA_DEFAULT)
        self.has_default_route = True

    def destroy_route(self):
        self.ip_impl.delete_route(self.topology.vrf, self.overlay_prefix)

    def destroy_default_route(self):
        if self.has_default_route:
            prefix = self.ip_impl.get_default_prefix()
            self.has_default_route = False

    def destroy_gue_port(self):
        self.gue_port.destroy()

    def destroy_gre_port(self):
        self.gre_port.destroy()

    def destroy_ip_over_ip_port(self):
        self.ip_over_ip_tunnel_port.destroy()

    def create_ip_over_ip_port(self, length=32):
        # VRF, Underlay Prefix 1
        self.tunnel_dest1 = self.ip_impl.build_prefix(self.LOCAL_IP1, length)

        self.ip_over_ip_tunnel_port = T.ip_over_ip_tunnel_port(self, self.device,
                                                               self.IP_OVER_IP_PORT_GID,
                                                               self.topology.vrf,
                                                               self.tunnel_dest1,
                                                               self.REMOTE_IP,
                                                               self.topology.vrf)
        self.ip_over_ip_tunnel_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.ingress_counter)
        self.ip_over_ip_tunnel_port.hld_obj.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)

    def create_gue_port(self, length=32):

        self.tunnel_dest1 = self.ip_impl.build_prefix(self.LOCAL_IP1, length)
        self.gue_port = T.gue_port(self, self.device,
                                   self.GUE_PORT_GID,
                                   sdk.la_ip_tunnel_mode_e_DECAP_ONLY,
                                   self.topology.vrf,
                                   self.tunnel_dest1,
                                   self.REMOTE_IP,
                                   self.topology.vrf)
        self.gue_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.ingress_counter)
        self.gue_port.hld_obj.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)

    def create_gre_port(self):

        self.gre_port = T.gre_port(self, self.device,
                                   self.GRE_PORT_GID,
                                   sdk.la_ip_tunnel_mode_e_DECAP_ONLY,
                                   self.topology.vrf,
                                   self.LOCAL_IP1,
                                   self.REMOTE_IP,
                                   self.topology.vrf)
        self.gre_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.ingress_counter)
        self.gre_port.hld_obj.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_ip_tunnel_feature_with_same_src_and_mask(self):

        self.create_gue_port()
        self.create_gre_port()
        self.create_ip_over_ip_port()
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_GUE, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_GUE, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_IPIP_BASE, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IPIP, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_GRE_BASE, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_GRE, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.destroy_gue_port()
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_GRE_BASE, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_GRE, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_IPIP_BASE, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IPIP, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.destroy_gre_port()

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_IPIP_BASE, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IPIP, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
        self.destroy_ip_over_ip_port()

        self.create_gre_port()
        self.create_gue_port()

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_GUE, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_GUE, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_GRE_BASE, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_BASE, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.destroy_gue_port()
        self.destroy_gre_port()
        self.destroy_route()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_ip_tunnel_feature_with_same_src_and_diff_mask(self):

        self.create_gue_port(24)
        self.create_gre_port()
        self.create_ip_over_ip_port(28)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_GUE, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_GUE, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_IPIP_BASE, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IPIP, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_GRE_BASE, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_GRE, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.destroy_gue_port()
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_GRE_BASE, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_GRE, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_IPIP_BASE, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IPIP, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.destroy_gre_port()

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_IPIP_BASE, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_IPIP, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
        self.destroy_ip_over_ip_port()

        self.create_gre_port()
        self.create_gue_port(24)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_GUE, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_GUE, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_GRE_BASE, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_BASE, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.destroy_gue_port()
        self.destroy_gre_port()
        self.destroy_route()


if __name__ == '__main__':
    unittest.main()
