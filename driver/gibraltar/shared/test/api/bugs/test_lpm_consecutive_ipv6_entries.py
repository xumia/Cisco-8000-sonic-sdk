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
NH_GID_BASE = 0x300
VRF_GID = 0x400 if not decor.is_gibraltar() else 0xF00

IN_SRC_MAC = '04:72:73:74:75:76'
RX_MAC = T.mac_addr('10:12:13:14:15:16')
TX_MAC = T.mac_addr('04:f4:bc:57:d5:00')
SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
DIP_STR = "1111:0db8:0a0b:12f0:0000:0000:0000:TTTT"
DIP_Q1 = 0x11110db80a0b12f0

RX_VLAN = 0x100
TX_VLAN_BASE = 0x100
DIP_NIBBLE_BASE = 0x100

NUM_PACKETS = 200


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class lpm_ipv6_insertions(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(1)

        # MATILDA_SAVE -- need review
        if (IN_SLICE not in self.device.get_used_slices()) or (OUT_SLICE not in self.device.get_used_slices()):
            self.skipTest("In this model the tested slice has been deactivated, thus the test is irrelevant.")
            return

        self.topology = T.topology(self, self.device)

        self.create_routing_topology()

    def tearDown(self):
        # self.destroy_ports()
        self.device.tearDown()

    def create_routing_topology(self):
        self.create_eth_ports()
        self.create_routing()

    def create_eth_ports(self):
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

        ac_gid = AC_PORT_GID_BASE
        self.rx_ac_port = self.device.create_l3_ac_port(
            ac_gid,
            self.rx_eth_port.hld_obj,
            RX_VLAN,
            0,
            RX_MAC.hld_obj,
            self.vrf,
            self.topology.ingress_qos_profile_def.hld_obj,
            self.topology.egress_qos_profile_def.hld_obj)
        self.rx_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

        egress_vlan_tag = sdk.la_vlan_tag_t()
        egress_vlan_tag.tpid = 0x8100

        ipv6_prefix = sdk.la_ipv6_prefix_t()
        ipv6_prefix.length = 128
        self.tx_ac_ports = []
        self.dips = []

        for i in range(NUM_PACKETS):
            ac_gid = AC_PORT_GID_BASE + i + 1
            tx_vlan = TX_VLAN_BASE + i

            # TX AC port
            tx_ac_port = self.device.create_l3_ac_port(
                ac_gid,
                self.tx_eth_port.hld_obj,
                tx_vlan,
                0,
                TX_MAC.hld_obj,
                self.vrf,
                self.topology.ingress_qos_profile_def.hld_obj,
                self.topology.egress_qos_profile_def.hld_obj)

            tx_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
            egress_vlan_tag.tci.fields.vid = tx_vlan
            tx_ac_port.set_egress_vlan_tag(egress_vlan_tag, sdk.LA_VLAN_TAG_UNTAGGED)
            self.tx_ac_ports.append(tx_ac_port)

            # NH
            nh_gid = NH_GID_BASE + i
            nh = self.device.create_next_hop(nh_gid, RX_MAC.hld_obj, tx_ac_port, sdk.la_next_hop.nh_type_e_NORMAL)

            # DIP
            dip_nibble = DIP_NIBBLE_BASE + i
            dip_str = DIP_STR.replace('TTTT', "{:04x}".format(dip_nibble))
            self.dips.append(dip_str)

            # FEC
            fec = self.device.create_l3_fec(nh)
            sdk.set_ipv6_addr(ipv6_prefix.addr, dip_nibble, DIP_Q1)
            self.vrf.add_ipv6_route(ipv6_prefix, fec, 0, True)

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_multiple_packets(self):
        for i in range(NUM_PACKETS):
            self.run_packet(i)

    def run_packet(self, index):
        in_packet_base = \
            Ether(dst=RX_MAC.addr_str, src=IN_SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=RX_VLAN, type=Ethertype.IPv6.value) / \
            IPv6(src=SIP.addr_str, dst=self.dips[index], hlim=127, plen=40)

        out_packet_base = \
            Ether(dst=RX_MAC.addr_str, src=TX_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=(RX_VLAN + index), type=Ethertype.IPv6.value) / \
            IPv6(src=SIP.addr_str, dst=self.dips[index], hlim=126, plen=40)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)


if __name__ == '__main__':
    unittest.main()
