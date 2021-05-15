#!/usr/bin/env python3
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


# Bug folowup:
# In early SDK there was a bug that when an  ac_port was destroied  the HW was not updated.
# Thus the port stayed in the SW level without any configuration to the HW.
# It caused traffic to keep on running even if the port was already destroyed.

from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
import decor

IN_SLICE = T.get_device_slice(3)
IN_IFG = 0
IN_SERDES_FIRST = T.get_device_first_serdes(4)
IN_SERDES_LAST = IN_SERDES_FIRST + 1
OUT_SLICE = T.get_device_slice(5)
OUT_IFG = T.get_device_ifg(1)
OUT_SERDES_FIRST = T.get_device_out_first_serdes(8)
OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

SYS_PORT_GID_BASE = 0x100
AC_PORT_GID_BASE = 0x200
TX_AC_PORT_GID_BASE = 0x205
VRF_GID = 0x400 if not decor.is_gibraltar() else 0xF00

IN_SRC_MAC = '04:72:73:74:75:76'
RX_MAC = T.mac_addr('11:12:13:14:15:16')
TX_MAC = T.mac_addr('04:f4:bc:57:d5:00')
HOST_MAC = T.mac_addr('04:ca:fe:aa:bb:00')
SIP = T.ipv4_addr('12.10.12.10')
DIP = T.ipv4_addr('82.81.95.250')


RX_VLAN = 0x100
TX_VLAN_BASE = 0x100


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class lpm_ipv6_insertions(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(1)

        self.topology = T.topology(self, self.device)

        self.create_routing_topology()

        self.create_packets()

    def tearDown(self):
        self.device.tearDown()

    def create_routing_topology(self):
        self.create_eth_ports()
        self.create_routing()

    def create_eth_ports(self):
        # MATILDA_SAVE -- need review
        global IN_SLICE
        global OUT_SLICE
        IN_SLICE = T.choose_active_slices(self.device, IN_SLICE, [3, 2])
        OUT_SLICE = T.choose_active_slices(self.device, OUT_SLICE, [5, 0])

        self.ac_profile = T.ac_profile(self, self.device)
        self.rx_eth_port = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, SYS_PORT_GID_BASE, IN_SERDES_FIRST, IN_SERDES_LAST)
        self.rx_eth_port.set_ac_profile(self.ac_profile)

        self.tx_eth_port = T.ethernet_port(
            self,
            self.device,
            OUT_SLICE,
            OUT_IFG,
            SYS_PORT_GID_BASE + 1,
            OUT_SERDES_FIRST,
            OUT_SERDES_LAST)
        self.tx_eth_port.set_ac_profile(self.ac_profile)

    def create_routing(self):
        self.vrf = self.device.create_vrf(VRF_GID)

        self.rx_ac_port = self.device.create_l3_ac_port(
            AC_PORT_GID_BASE,
            self.rx_eth_port.hld_obj,
            RX_VLAN,
            0,
            RX_MAC.hld_obj,
            self.vrf,
            self.topology.ingress_qos_profile_def.hld_obj,
            self.topology.egress_qos_profile_def.hld_obj)
        self.rx_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

        # TX AC port
        self.tx_ac_port = self.device.create_l3_ac_port(
            TX_AC_PORT_GID_BASE,
            self.tx_eth_port.hld_obj,
            TX_VLAN_BASE,
            0,
            TX_MAC.hld_obj,
            self.vrf,
            self.topology.ingress_qos_profile_def.hld_obj,
            self.topology.egress_qos_profile_def.hld_obj)

        self.tx_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        egress_vlan_tag = sdk.la_vlan_tag_t()
        egress_vlan_tag.tpid = 0x8100
        egress_vlan_tag.tci.fields.vid = TX_VLAN_BASE
        self.tx_ac_port.set_egress_vlan_tag(egress_vlan_tag, sdk.LA_VLAN_TAG_UNTAGGED)

        # Add subnet & host
        addr = sdk.la_ipv4_addr_t()
        addr.s_addr = DIP.to_num()
        prefix = sdk.la_ipv4_prefix_t()
        prefix.length = 16
        prefix.addr.s_addr = addr.s_addr & 0xffff0000

        self.tx_ac_port.add_ipv4_subnet(prefix)
        self.tx_ac_port.add_ipv4_host(addr, HOST_MAC.hld_obj)

    def create_packets(self):
        in_packet_base = \
            Ether(dst=RX_MAC.addr_str, src=IN_SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=RX_VLAN, type=Ethertype.IPv4.value) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=40)

        out_packet_base = \
            Ether(dst=HOST_MAC.addr_str, src=TX_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=RX_VLAN, type=Ethertype.IPv4.value) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=39)

        self.in_packet, self.out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

    # destroy the port
    def destroy_and_create_ac(self):
        self.device.destroy(self.tx_ac_port)
        self.tx_ac_port = self.device.create_l3_ac_port(
            TX_AC_PORT_GID_BASE,
            self.tx_eth_port.hld_obj,
            TX_VLAN_BASE,
            0,
            TX_MAC.hld_obj,
            self.vrf,
            self.topology.ingress_qos_profile_def.hld_obj,
            self.topology.egress_qos_profile_def.hld_obj)

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - serdes")
    def test_run_destroy_drop(self):
        self.run_and_compare()
        self.destroy_and_create_ac()
        self.run_and_drop()

    # makes sure everything is configured correctly and traffic flows.
    def run_and_compare(self):
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

    def run_and_drop(self):
        run_and_drop(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST)


if __name__ == '__main__':
    unittest.main()
