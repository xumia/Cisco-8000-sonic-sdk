#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
from sdk_test_case_base import *
import ip_test_base
import warm_boot_upgrade_rollback_test_utils as wb


class warm_boot_upgrade_rollback_ipv4_l3_ac_routing_base(sdk_test_case_base):

    SA = T.mac_addr('be:ef:5d:35:7a:35')
    PRIVATE_DATA = 0x1234567890abcdef
    TTL = 128

    def setUp(self):
        super().setUp()
        self.l3_port_impl_class = T.ip_l3_ac_base
        self.l3_port_impl = self.l3_port_impl_class(self.topology)

    def _test_warm_boot_ipv4_l3_ac_routing(self, change_config_after_wb):
        SIP = T.ipv4_addr('12.10.12.10')
        DIP = T.ipv4_addr('82.81.95.250')

        ip_impl = ip_test_base.ipv4_test_base
        subnet = ip_impl.build_prefix(DIP, length=16)

        ip_impl.add_subnet(self.l3_port_impl.tx_port, subnet)
        ip_impl.add_host(self.l3_port_impl.tx_port, DIP, self.l3_port_impl.reg_nh.mac_addr)

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

        wb.warm_boot(self.device)

        if change_config_after_wb:
            ip_impl.delete_host(self.l3_port_impl.tx_port, DIP)
            ip_impl.delete_subnet(self.l3_port_impl.tx_port, subnet)

            ip_impl.add_subnet(self.l3_port_impl.tx_port_def, subnet)
            ip_impl.add_host(self.l3_port_impl.tx_port_def, DIP, self.l3_port_impl.reg_nh.mac_addr)

            output_packet[S.Ether].src = T.TX_L3_AC_DEF_MAC.addr_str
            out_slice = T.TX_SLICE_DEF
            out_ifg = T.TX_IFG_DEF
            out_serdes = self.l3_port_impl.serdes_def
        else:
            out_slice = T.TX_SLICE_REG
            out_ifg = T.TX_IFG_REG
            out_serdes = self.l3_port_impl.serdes_reg

        U.run_and_compare(
            self,
            self.device,
            input_packet,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            output_packet,
            out_slice,
            out_ifg,
            out_serdes)
