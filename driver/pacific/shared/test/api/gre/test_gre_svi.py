#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import packet_test_utils as U
import scapy.all as S
import sim_utils
import topology as T
import packet_test_defs as P
import ip_test_base
from sdk_test_case_base import *
import mtu.mtu_test_utils as MTU
import decor

S.load_contrib('mpls')


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_gre_svi(sdk_test_case_base):

    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    GRE_PORT_GID = 0x901
    GRE_TUNNEL_DESTINATION_GID = 0x674
    GRE_SIP = T.ipv4_addr('1.1.1.1')
    GRE_DIP = T.ipv4_addr('12.1.95.250')
    NEW_TX_L3_AC_DEF_MAC = T.mac_addr('50:52:53:54:55:56')
    OVL_IP_PACKET_DMAC = NEW_TX_L3_AC_DEF_MAC.addr_str

    OVL_DIP_ROUTE = T.ipv4_addr('21.1.1.0')
    OVL_SIP_ROUTE = T.ipv4_addr('11.1.1.0')
    OVL_IP_PACKET_DIP = '21.1.1.1'
    OVL_IP_PACKET_SIP = '11.1.1.1'

    OVL_DIP_ROUTE_IPv6 = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:0000')
    OVL_SIP_ROUTE_IPv6 = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:0000')

    OVL_IPv6_PACKET_DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')
    OVL_IPv6_PACKET_SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')

    UNL_IP_PACKET_SMAC = '00:11:22:33:44:55'

    PORT_DECAP_OVL_INPUT_IP = S.IP(dst=OVL_IP_PACKET_SIP, src=OVL_IP_PACKET_DIP, ttl=63)
    PORT_DECAP_OVL_EXPECTED_IP = S.IP(dst=OVL_IP_PACKET_SIP, src=OVL_IP_PACKET_DIP, ttl=62)

    PORT_DECAP_OVL_INPUT_IPv6 = S.IPv6(dst=OVL_IPv6_PACKET_SIP.addr_str,
                                       src=OVL_IPv6_PACKET_DIP.addr_str, hlim=63, plen=40)
    PORT_DECAP_OVL_EXPECTED_IPv6 = S.IPv6(dst=OVL_IPv6_PACKET_SIP.addr_str,
                                          src=OVL_IPv6_PACKET_DIP.addr_str, hlim=62, plen=40)

    def setUp(self):
        super().setUp()

        self.ip_impl = ip_test_base.ipv4_test_base
        self.ipv6_impl = ip_test_base.ipv6_test_base
        self.l3_port_impl = T.ip_l3_ac_base(self.topology)

        # enable ipv4/MPLS forwarding
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_MPLS, True)
        self.topology.tx_l3_ac_def.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_def.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_MPLS, True)
        self.topology.tx_l3_ac_ext.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_ext.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_MPLS, True)

        # make the l3 port address unicast mac address
        self.topology.tx_l3_ac_def.hld_obj.set_mac(
            self.NEW_TX_L3_AC_DEF_MAC.hld_obj)

        self.ovl_dip_prefix = self.ip_impl.build_prefix(self.OVL_DIP_ROUTE, length=24)
        self.ovl_sip_prefix = self.ip_impl.build_prefix(self.OVL_SIP_ROUTE, length=24)

        self.topology.tx_l3_ac_reg.hld_obj.set_vrf(self.topology.vrf.hld_obj)
        self.topology.tx_l3_ac_def.hld_obj.set_vrf(self.topology.vrf.hld_obj)

        self.add_default_route()

    def tearDown(self):
        self.destroy_default_route()
        super().tearDown()

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix,
                               self.l3_port_impl.def_nh,
                               self.PRIVATE_DATA_DEFAULT)
        prefix_v6 = self.ipv6_impl.get_default_prefix()
        self.ipv6_impl.add_route(self.topology.vrf, prefix_v6,
                                 self.l3_port_impl.def_nh,
                                 self.PRIVATE_DATA_DEFAULT)
        self.has_default_route = True

    def destroy_default_route(self):
        if self.has_default_route:
            prefix = self.ip_impl.get_default_prefix()
            self.ip_impl.delete_route(self.topology.vrf, prefix)
            self.has_default_route = False

    def gre_port_setup(self, gid, unl_vrf, sip, dip, vrf):
        gre_tunnel = self.device.create_gre_port(
            gid,
            unl_vrf.hld_obj,
            sip.hld_obj,
            dip.hld_obj,
            vrf.hld_obj,
            self.topology.ingress_qos_profile_def.hld_obj,
            self.topology.egress_qos_profile_def.hld_obj)

        # set the counter
        self.l3_egress_counter = self.device.create_counter(1)
        self.l3_ingress_counter = self.device.create_counter(1)
        gre_tunnel.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l3_egress_counter)
        gre_tunnel.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.l3_ingress_counter)

        # enable ipv4/6, MPLS on gre port
        gre_tunnel.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        gre_tunnel.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        gre_tunnel.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)

        gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)

        return gre_tunnel

    def gre_port_single_path(self):
        self.gre_tunnel = self.gre_port_setup(self.GRE_PORT_GID, self.topology.vrf,
                                              self.GRE_SIP, self.GRE_DIP, self.topology.vrf)
        self.gre_destination = self.device.create_ip_tunnel_destination(
            self.GRE_TUNNEL_DESTINATION_GID,
            self.gre_tunnel,
            self.topology.nh_l3_ac_reg.hld_obj)
        self.ovl_ecmp = None
        self.ovl_ecmp_ipv6 = None

    def destory_gre_port_single_path(self):
        if self.ovl_ecmp is not None:
            self.topology.vrf.hld_obj.delete_ipv4_route(self.ovl_dip_prefix)
            self.device.destroy(self.ovl_ecmp)

        if self.ovl_ecmp_ipv6 is not None:
            self.topology.vrf.hld_obj.delete_ipv6_route(self.ovl_dip_prefix_ipv6)
            self.device.destroy(self.ovl_ecmp_ipv6)

        self.device.destroy(self.gre_destination)
        self.device.destroy(self.gre_tunnel)
        self.device.destroy(self.l3_egress_counter)
        self.device.destroy(self.l3_ingress_counter)

    def _test_svi_decap_gre_single_path(self):
        self.topology.rx_svi.hld_obj.set_active(True)

        self.ovl_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.ovl_ecmp.add_member(self.gre_destination)
        self.ovl_dip_prefix = self.ip_impl.build_prefix(self.OVL_DIP_ROUTE, length=24)
        self.topology.vrf.hld_obj.add_ipv4_route(self.ovl_dip_prefix, self.ovl_ecmp, self.PRIVATE_DATA, False)

        input_packet_base = \
            S.Ether(dst=T.RX_SVI_MAC.addr_str, src=self.UNL_IP_PACKET_SMAC, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            S.GRE() / \
            self.PORT_DECAP_OVL_INPUT_IP / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            self.PORT_DECAP_OVL_EXPECTED_IP / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.expected_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

    def _test_svi_decap_gre_single_path_ipv6(self):
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)
        self.topology.rx_svi.hld_obj.set_active(True)

        self.ovl_ecmp_ipv6 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.ovl_ecmp_ipv6.add_member(self.gre_destination)
        self.ovl_dip_prefix_ipv6 = self.ipv6_impl.build_prefix(self.OVL_DIP_ROUTE_IPv6, length=64)
        self.topology.vrf.hld_obj.add_ipv6_route(self.ovl_dip_prefix_ipv6, self.ovl_ecmp_ipv6, self.PRIVATE_DATA, False)

        input_packet_base = \
            S.Ether(dst=T.RX_SVI_MAC.addr_str, src=self.UNL_IP_PACKET_SMAC, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            S.GRE(proto=0x86DD) / \
            self.PORT_DECAP_OVL_INPUT_IPv6 / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            self.PORT_DECAP_OVL_EXPECTED_IPv6 / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.expected_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

    def test_svi_decap_gre_single_path(self):
        self.gre_port_single_path()
        self._test_svi_decap_gre_single_path()
        self.destory_gre_port_single_path()

    def test_svi_decap_gre_single_path_ipv6(self):
        self.gre_port_single_path()
        self._test_svi_decap_gre_single_path_ipv6()
        self.destory_gre_port_single_path()


if __name__ == '__main__':
    unittest.main()
