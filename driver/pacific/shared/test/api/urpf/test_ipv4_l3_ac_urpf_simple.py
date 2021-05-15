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

from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import ip_test_base
import topology as T
from sdk_test_case_base import *
import decor

TX_SLICE = T.get_device_slice(1)
TX_IFG = 0
TX_SERDES = T.get_device_first_serdes(1)

PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
SA = T.mac_addr('be:ef:5d:35:7a:35')

SIP = T.ipv4_addr('192.193.194.195')
DIP = T.ipv4_addr('208.209.210.211')

SIP1 = T.ipv4_addr('193.193.194.195')

TTL = 127

INPUT_PACKET_BASE = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
    ICMP()

EXPECTED_DEFAULT_OUTPUT_PACKET_BASE = \
    Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1) / \
    ICMP()

INPUT_PACKET, PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_BASE)
EXPECTED_DEFAULT_OUTPUT_PACKET = add_payload(EXPECTED_DEFAULT_OUTPUT_PACKET_BASE, PAYLOAD_SIZE)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l3_ac_urpf_simple(sdk_test_case_base):
    PRIVATE_DATA = 0x1234567890abcdef
    TTL = 128
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    def setUp(self):
        super().setUp(create_default_topology=False)
        self.create_network_topology()
        self.topology.create_inject_ports()
        self.inserted_drop_counter = None

    def tearDown(self):
        super().tearDown()

    def create_network_topology(self):
        # Create L2 objects
        self.rx_eth_port = T.ethernet_port(
            self,
            self.device,
            T.RX_SLICE,
            T.RX_IFG,
            T.RX_SYS_PORT_GID,
            T.FIRST_SERDES,
            T.LAST_SERDES)

        self.tx_eth_port = T.ethernet_port(
            self,
            self.device,
            TX_SLICE,
            TX_IFG,
            T.TX_L3_AC_SYS_PORT_REG_GID,
            TX_SERDES,
            TX_SERDES)

        # Create VRF
        self.vrf = T.vrf(self, self.device, T.VRF_GID)

        # Create L3 objects
        self.rx_l3_ac = T.l3_ac_port(self, self.device,
                                     T.RX_L3_AC_GID,
                                     self.rx_eth_port,
                                     self.vrf,
                                     T.RX_L3_AC_MAC,
                                     T.RX_L3_AC_PORT_VID1,
                                     T.RX_L3_AC_PORT_VID2)

        self.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

        self.tx_l3_ac = T.l3_ac_port(self, self.device,
                                     T.TX_L3_AC_REG_GID,
                                     self.tx_eth_port,
                                     self.vrf,
                                     T.TX_L3_AC_REG_MAC)

        self.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

        # Create L3 destination
        # self.nh_l3_ac = T.next_hop(self, self.device, T.NH_L3_AC_REG_GID, T.NH_L3_AC_REG_MAC, self.tx_l3_ac_reg)

        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = 0x0
        prefix.length = 24

        # self.vrf.hld_obj.add_ipv4_route(prefix, next_hop.hld_obj, self.PRIVATE_DATA, False)

        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = ip_test_base.ipv4_test_base.apply_prefix_mask(SIP.to_num(), 24)
        prefix.length = 24
        self.rx_l3_ac.hld_obj.add_ipv4_subnet(prefix)

        # prefix = sdk.la_ipv4_prefix_t()
        # prefix.addr.s_addr = ip_test_base.ipv4_test_base.apply_prefix_mask(DIP.to_num(), 24)
        # prefix.length = 24
        # self.tx_l3_ac.hld_obj.add_ipv4_subnet(prefix)

        # Create L3 destinations
        self.nh_l3_ac = T.next_hop(self, self.device, T.NH_L3_AC_REG_GID, T.NH_L3_AC_REG_MAC, self.tx_l3_ac)

        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = 0x0
        prefix.length = 0

        self.vrf.hld_obj.add_ipv4_route(prefix, self.nh_l3_ac.hld_obj, self.PRIVATE_DATA, False)

        # self.nh_l3_ac_rx = T.next_hop(self, self.device, T.NH_L3_AC_DEF_GID, T.NH_L3_AC_DEF_MAC, self.rx_l3_ac)
        # prefix = sdk.la_ipv4_prefix_t()
        # prefix.addr.s_addr = prefix.addr.s_addr = ip_test_base.ipv4_test_base.apply_prefix_mask(SIP1.to_num(), 24)
        # prefix.length = 24

        # self.vrf.hld_obj.add_ipv4_route(prefix, self.nh_l3_ac_rx.hld_obj, self.PRIVATE_DATA, False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l3_ac_urpf_simple(self):

        self.rx_l3_ac.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_STRICT)

        run_and_compare(self, self.device,
                        INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_DEFAULT_OUTPUT_PACKET, TX_SLICE, TX_IFG, TX_SERDES)


if __name__ == '__main__':
    unittest.main()
