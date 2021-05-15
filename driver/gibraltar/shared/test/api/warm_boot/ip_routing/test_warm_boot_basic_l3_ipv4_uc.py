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
import sim_utils
import warm_boot_test_utils as wb
import ip_test_base
import os
import decor


IN_SLICE = T.get_device_slice(5)
IN_IFG = T.get_device_ifg(0)
IN_FIRST_SERDES = T.get_device_first_serdes(0)
IN_LAST_SERDES = IN_FIRST_SERDES + 1
OUT_SLICE = T.get_device_slice(1)
OUT_IFG = T.get_device_ifg(1)
OUT_FIRST_SERDES = T.get_device_first_serdes(2)
OUT_LAST_SERDES = OUT_FIRST_SERDES + 1

VRF_GID = 100
RX_SYS_PORT_GID = 0x21
TX_L3_AC_SYS_PORT_GID = 0x25
RX_L3_AC_GID = 0x811
TX_L3_AC_GID = 0x821
NH_L3_AC_GID = 0x611
TX_L3_AC_MAC = T.mac_addr('40:42:43:44:45:46')
NH_L3_AC_MAC = T.mac_addr('70:72:73:74:75:76')
RX_L3_AC_MAC = T.mac_addr('30:32:33:34:35:36')

RX_L3_AC_PORT_VID1 = 0x1
RX_L3_AC_PORT_VID2 = 0x3

SA = T.mac_addr('be:ef:5d:35:7a:35')
SIP = T.ipv4_addr('12.10.12.10')
DIP = T.ipv4_addr('82.81.95.250')
PRIVATE_DATA = 0x1234567890abcdef
TTL = 128


wb.support_warm_boot()


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip in auto-WB sanity")
@unittest.skipUnless(decor.is_pacific() or decor.is_gibraltar(), "WB is currently supported by GB and PAC only")
class warm_boot_basic_l3_ipv4_uc(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(1)
        wb.warm_boot(self.device.device)
        self.topology = T.topology(self, self.device, create_default_topology=False)
        wb.warm_boot(self.device.device)
        self.topology.create_inject_ports()
        wb.warm_boot(self.device.device)
        self.create_topology()

    def tearDown(self):
        self.device.tearDown()

    def create_topology(self):
        global IN_SLICE, OUT_SLICE
        IN_SLICE = T.choose_active_slices(self.device, IN_SLICE, [5, 2, 4])
        OUT_SLICE = T.choose_active_slices(self.device, OUT_SLICE, [1, 3])

        self.vrf = T.vrf(self, self.device, VRF_GID)
        wb.warm_boot(self.device.device)
        self.ac_profile = T.ac_profile(self, self.device)
        wb.warm_boot(self.device.device)

        self.rx_eth_port = T.ethernet_port(
            self,
            self.device,
            IN_SLICE,
            IN_IFG,
            RX_SYS_PORT_GID,
            IN_FIRST_SERDES,
            IN_LAST_SERDES)
        wb.warm_boot(self.device.device)
        self.rx_eth_port.set_ac_profile(self.ac_profile)
        wb.warm_boot(self.device.device)
        self.rx_l3_ac = T.l3_ac_port(
            self,
            self.device,
            RX_L3_AC_GID,
            self.rx_eth_port,
            self.vrf,
            RX_L3_AC_MAC,
            RX_L3_AC_PORT_VID1,
            RX_L3_AC_PORT_VID2)
        wb.warm_boot(self.device.device)
        self.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        wb.warm_boot(self.device.device)

        self.tx_eth_port = T.ethernet_port(
            self,
            self.device,
            OUT_SLICE,
            OUT_IFG,
            TX_L3_AC_SYS_PORT_GID,
            OUT_FIRST_SERDES,
            OUT_LAST_SERDES)
        wb.warm_boot(self.device.device)
        self.tx_eth_port.set_ac_profile(self.ac_profile)
        wb.warm_boot(self.device.device)
        self.tx_l3_ac = T.l3_ac_port(
            self,
            self.device,
            TX_L3_AC_GID,
            self.tx_eth_port,
            self.vrf,
            TX_L3_AC_MAC)
        wb.warm_boot(self.device.device)
        self.tx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        wb.warm_boot(self.device.device)
        self.next_hop = T.next_hop(
            self,
            self.device,
            NH_L3_AC_GID,
            NH_L3_AC_MAC,
            self.tx_l3_ac)
        wb.warm_boot(self.device.device)

    def test_warm_boot_basic_l3_ipv4_uc(self):
        prefix = ip_test_base.ipv4_test_base.build_prefix(DIP, 16)
        ip_test_base.ipv4_test_base.add_route(self.vrf, prefix, self.next_hop, PRIVATE_DATA)
        wb.warm_boot(self.device.device)

        input_packet_base = \
            S.Ether(dst=RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=RX_L3_AC_PORT_VID2) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

        output_packet_base = \
            S.Ether(dst=NH_L3_AC_MAC.addr_str, src=TX_L3_AC_MAC.addr_str) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1)

        input_packet, output_packet = U.pad_input_and_output_packets(input_packet_base, output_packet_base)

        U.run_and_compare(
            self,
            self.device,
            input_packet,
            IN_SLICE,
            IN_IFG,
            IN_FIRST_SERDES,
            output_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_FIRST_SERDES)


if __name__ == '__main__':
    unittest.main()
