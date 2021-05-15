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
import ipaddress
import decor
import os
import random
import warm_boot_test_utils as wb


wb.support_warm_boot()


IN_SLICE = 2
IN_IFG = 0
IN_SERDES_FIRST = 4
IN_SERDES_LAST = IN_SERDES_FIRST + 1
OUT_SLICE = 1
OUT_IFG = 1
OUT_SERDES_FIRST = 8
OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

SYS_PORT_GID_BASE = 0x100
AC_PORT_GID_BASE = 0x200
NH_GID_BASE = 0x300
VRF_GID = 0x400

IN_SRC_MAC = '04:72:73:74:75:76'
TX_MAC = T.mac_addr('04:f4:bc:57:d5:00')
RX_MAC = T.mac_addr('11:12:13:14:15:16')

IPV4_SIP = T.ipv4_addr('12.10.12.10')
IPV4_DIP_START_STR = '12.10.1.0'
IPV6_SIP = T.ipv6_addr('1234:1234:1234:1234:0000:0000:0000:abcd')
IPV6_DIP_START_STR = '1111:2222:3333:0000:0000:0000:0000:0000'
LONG_IPV6_DIP_START_STR = 'aaaa:bbbb:cccc:dddd:eeee:ffff:0000:0000'

TTL = 50
HLIM = 128

RX_VLAN = 0x100
TX_VLAN_BASE = 1
NUM_OF_ROUTES_OF_EACH_TYPE = 100
NUM_OF_ROUTES_FOR_WARM_BOOT = 20
NUM_PACKETS_TO_VALIDATE_EACH_ITERATION = 10

SEED = 1

IS_HW_PACIFIC_OR_GB_DEVICE = decor.is_hw_pacific() or decor.is_hw_gibraltar()


@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip in auto-WB sanity")
@unittest.skipUnless(IS_HW_PACIFIC_OR_GB_DEVICE, "Requires HW Pacific or Gb device")
class lpm_ipv4_insertions(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(1)
        self.topology = T.topology(self, self.device)
        self.create_eth_ports()
        self.device.set_int_property(sdk.la_device_property_e_LPM_REBALANCE_INTERVAL, 10)

    def tearDown(self):
        self.device.tearDown()

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

    def test_create_routing_make_warm_boot_and_run_packets(self):
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
        self.rx_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.rx_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

        egress_vlan_tag = sdk.la_vlan_tag_t()
        egress_vlan_tag.tpid = 0x8100

        long_ipv6_prefix = sdk.la_ipv6_prefix_t()
        long_ipv6_prefix.length = 127
        self.long_ipv6_dips = []
        self.long_ipv6_vlans = []
        long_ipv6_dip_base = int(ipaddress.ip_address(LONG_IPV6_DIP_START_STR))

        ipv4_prefix = sdk.la_ipv4_prefix_t()
        ipv4_prefix.length = 24
        self.ipv4_dips = []
        self.ipv4_vlans = []
        ipv4_dip_base = int(ipaddress.ip_address(IPV4_DIP_START_STR))

        ipv6_prefix = sdk.la_ipv6_prefix_t()
        ipv6_prefix.length = 64
        self.ipv6_dips = []
        self.ipv6_vlans = []
        ipv6_dip_base = int(ipaddress.ip_address(IPV6_DIP_START_STR))

        random_generator = random.Random(SEED)
        last_checked_index = -1
        for i in range(NUM_OF_ROUTES_OF_EACH_TYPE):
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

            tx_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
            tx_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
            egress_vlan_tag.tci.fields.vid = tx_vlan
            tx_ac_port.set_egress_vlan_tag(egress_vlan_tag, sdk.LA_VLAN_TAG_UNTAGGED)

            # NH
            nh_gid = NH_GID_BASE + i
            nh = self.device.create_next_hop(nh_gid, RX_MAC.hld_obj, tx_ac_port, sdk.la_next_hop.nh_type_e_NORMAL)

            # FEC
            fec = self.device.create_l3_fec(nh)

            # DIP - long ipv6
            dip_long_ipv6 = long_ipv6_dip_base + (i << 112)
            dip_lsb_long_ipv6 = dip_long_ipv6 & ((1 << 64) - 1)
            dip_msb_long_ipv6 = dip_long_ipv6 >> 64
            sdk.set_ipv6_addr(long_ipv6_prefix.addr, dip_lsb_long_ipv6, dip_msb_long_ipv6)

            current_dip_str = ipaddress.ip_address(dip_long_ipv6).exploded
            self.long_ipv6_dips.append(current_dip_str)
            self.long_ipv6_vlans.append(tx_vlan)

            self.vrf.add_ipv6_route(long_ipv6_prefix, fec, 0, False)

            # DIP - ipv4
            dip_ipv4 = ipv4_dip_base + (i << (32 - ipv4_prefix.length))
            ipv4_prefix.addr.s_addr = dip_ipv4

            current_dip_str = str(ipaddress.ip_address(dip_ipv4))
            self.ipv4_dips.append(current_dip_str)
            self.ipv4_vlans.append(tx_vlan)

            self.vrf.add_ipv4_route(ipv4_prefix, fec, 0, False)

            # DIP - ipv6
            dip_ipv6 = ipv6_dip_base + (i << (128 - ipv6_prefix.length))
            dip_lsb_ipv6 = dip_ipv6 & ((1 << 64) - 1)
            dip_msb_ipv6 = dip_ipv6 >> 64
            sdk.set_ipv6_addr(ipv6_prefix.addr, dip_lsb_ipv6, dip_msb_ipv6)

            current_dip_str = ipaddress.ip_address(dip_ipv6).exploded
            self.ipv6_dips.append(current_dip_str)
            self.ipv6_vlans.append(tx_vlan)

            self.vrf.add_ipv6_route(ipv6_prefix, fec, 0, False)

            if (i + 1) % NUM_OF_ROUTES_FOR_WARM_BOOT == 0:
                new_indexes = list(range(last_checked_index + 1, i))
                random_generator.shuffle(new_indexes)
                for j in new_indexes[0:NUM_PACKETS_TO_VALIDATE_EACH_ITERATION]:
                    self.run_packets(j)
                if last_checked_index > 0:
                    old_indexes = list(range(last_checked_index + 1 - NUM_OF_ROUTES_FOR_WARM_BOOT, last_checked_index))
                    random_generator.shuffle(old_indexes)
                    for j in old_indexes[0:NUM_PACKETS_TO_VALIDATE_EACH_ITERATION]:
                        self.run_packets(j)
                wb.warm_boot(self.device.device)
                last_checked_index = i

    def run_ipv4_packet(self, index):
        in_packet_base = \
            Ether(dst=RX_MAC.addr_str, src=IN_SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=RX_VLAN) / \
            IP(src=IPV4_SIP.addr_str, dst=self.ipv4_dips[index], ttl=TTL)

        out_packet_base = \
            Ether(dst=RX_MAC.addr_str, src=TX_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=(self.ipv4_vlans[index])) / \
            IP(src=IPV4_SIP.addr_str, dst=self.ipv4_dips[index], ttl=TTL - 1)

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

    def run_ipv6_packet(self, index):
        in_packet_base = \
            Ether(dst=RX_MAC.addr_str, src=IN_SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=RX_VLAN, type=Ethertype.IPv6.value) / \
            IPv6(src=IPV6_SIP.addr_str, dst=self.ipv6_dips[index], hlim=HLIM)

        out_packet_base = \
            Ether(dst=RX_MAC.addr_str, src=TX_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=(self.ipv6_vlans[index]), type=Ethertype.IPv6.value) / \
            IPv6(src=IPV6_SIP.addr_str, dst=self.ipv6_dips[index], hlim=HLIM - 1)

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

    def run_long_ipv6_packet(self, index):
        in_packet_base = \
            Ether(dst=RX_MAC.addr_str, src=IN_SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=RX_VLAN, type=Ethertype.IPv6.value) / \
            IPv6(src=IPV6_SIP.addr_str, dst=self.long_ipv6_dips[index], hlim=HLIM)

        out_packet_base = \
            Ether(dst=RX_MAC.addr_str, src=TX_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=(self.long_ipv6_vlans[index]), type=Ethertype.IPv6.value) / \
            IPv6(src=IPV6_SIP.addr_str, dst=self.long_ipv6_dips[index], hlim=HLIM - 1)

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

    def run_packets(self, index):
        self.run_long_ipv6_packet(index)
        self.run_ipv4_packet(index)
        self.run_ipv6_packet(index)


if __name__ == '__main__':
    unittest.main()
