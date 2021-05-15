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

import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
from sdk_test_case_base import *
import warm_boot_test_utils as wb
import ip_test_base
import os
import decor

wb.support_warm_boot()


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip in auto-WB sanity")
@unittest.skipUnless(decor.is_pacific() or decor.is_gibraltar(), "WB is currently supported by GB and PAC only")
class warm_boot_l3_ac_routing(sdk_test_case_base):

    SA = T.mac_addr('be:ef:5d:35:7a:35')
    PRIVATE_DATA = 0x1234567890abcdef
    TTL = 128

    def setUp(self):
        super().setUp()
        self.l3_port_impl_class = T.ip_l3_ac_base
        self.l3_port_impl = self.l3_port_impl_class(self.topology)

    def test_warm_boot_ipv4_l3_ac_routing_em(self):
        SIP = T.ipv4_addr('12.10.12.10')
        DIP = T.ipv4_addr('82.81.95.250')

        ip_impl = ip_test_base.ipv4_test_base
        subnet = ip_impl.build_prefix(DIP, length=16)

        wb.warm_boot(self.device.device)
        ip_impl.add_subnet(self.l3_port_impl.tx_port, subnet)
        wb.warm_boot(self.device.device)
        ip_impl.add_host(self.l3_port_impl.tx_port, DIP, self.l3_port_impl.reg_nh.mac_addr)
        wb.warm_boot(self.device.device)

        input_packet_base = \
            S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=self.TTL)

        output_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=self.TTL - 1)

        input_packet, output_packet = U.pad_input_and_output_packets(input_packet_base, output_packet_base)

        U.run_and_compare(
            self,
            self.device,
            input_packet,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            output_packet,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

        ip_impl.delete_host(self.l3_port_impl.tx_port, DIP)
        wb.warm_boot(self.device.device)
        ip_impl.delete_subnet(self.l3_port_impl.tx_port, subnet)

    def test_warm_boot_ipv4_l3_ac_routing_lpm(self):
        SIP = T.ipv4_addr('12.10.12.10')
        DIP = T.ipv4_addr('82.81.95.250')

        ip_impl = ip_test_base.ipv4_test_base
        subnet = ip_impl.build_prefix(DIP, length=16)

        wb.warm_boot(self.device.device)
        ip_impl.add_route(self.topology.vrf, subnet, self.topology.nh_l3_ac_reg, self.PRIVATE_DATA)
        wb.warm_boot(self.device.device)

        input_packet_base = \
            S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=self.TTL)

        output_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=self.TTL - 1)

        input_packet, output_packet = U.pad_input_and_output_packets(input_packet_base, output_packet_base)

        U.run_and_compare(
            self,
            self.device,
            input_packet,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            output_packet,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

    def test_warm_boot_ipv6_l3_ac_routing_em(self):
        SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
        DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

        ip_impl = ip_test_base.ipv6_test_base
        subnet = ip_impl.build_prefix(DIP, length=16)

        wb.warm_boot(self.device.device)
        ip_impl.add_subnet(self.l3_port_impl.tx_port, subnet)
        wb.warm_boot(self.device.device)
        ip_impl.add_host(self.l3_port_impl.tx_port, DIP, self.l3_port_impl.reg_nh.mac_addr)
        wb.warm_boot(self.device.device)

        input_packet_base = \
            S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=self.TTL, plen=40)

        output_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=self.TTL - 1, plen=40)

        input_packet, output_packet = U.pad_input_and_output_packets(input_packet_base, output_packet_base)

        U.run_and_compare(
            self,
            self.device,
            input_packet,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            output_packet,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

        ip_impl.delete_host(self.l3_port_impl.tx_port, DIP)
        wb.warm_boot(self.device.device)
        ip_impl.delete_subnet(self.l3_port_impl.tx_port, subnet)

    def test_warm_boot_ipv6_l3_ac_routing_lpm(self):
        SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
        DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

        ip_impl = ip_test_base.ipv6_test_base
        subnet = ip_impl.build_prefix(DIP, length=16)

        wb.warm_boot(self.device.device)
        ip_impl.add_route(self.topology.vrf, subnet, self.topology.nh_l3_ac_reg, self.PRIVATE_DATA)
        wb.warm_boot(self.device.device)

        input_packet_base = \
            S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=self.TTL, plen=40)

        output_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=self.TTL - 1, plen=40)

        input_packet, output_packet = U.pad_input_and_output_packets(input_packet_base, output_packet_base)

        U.run_and_compare(
            self,
            self.device,
            input_packet,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            output_packet,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)


if __name__ == '__main__':
    unittest.main()
