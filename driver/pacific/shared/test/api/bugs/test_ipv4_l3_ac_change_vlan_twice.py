#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

# Test to check solution for CSCvh50533.

# Problem description:
#
# SDK does not properly update PxVxV mapping tables when set_service_mapping_vid is called.
# Changing the VID to VID2 and back to original VID reports an EBUSY.

import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import sim_utils
import topology as T
import decor

CHAR_BIT = 8
BYTES_NUM_IN_ADDR = 4


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l3_ac_change_vlan_twice(unittest.TestCase):

    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    TTL = 128
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    VID1_2 = 0x44
    VID2_2 = 0x55

    INPUT_PACKET_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

    INPUT_PACKET_2_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=VID1_2, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=VID2_2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

    EXPECTED_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1)

    INPUT_PACKET, pad_len = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    INPUT_PACKET_2 = U.add_payload(INPUT_PACKET_2_BASE, pad_len)  # we assume len(INPUT_PACKET_2) >= len(INPUT_PACKET)
    EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, pad_len)

    def setUp(self):

        self.maxDiff = None  # Show whole strings on failures (unittest variable)

        self.device = sim_utils.create_device(1)

        self.topology = T.topology(self, self.device)

        self.add_default_route()

    def tearDown(self):
        self.device.tearDown()

    def add_default_route(self):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = 0
        prefix.length = 0
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.topology.nh_l3_ac_def.hld_obj,
                                                 self.PRIVATE_DATA_DEFAULT, False)

    def apply_prefix_mask(self, addr_num, prefix_length):
        mask = ~((1 << (CHAR_BIT * BYTES_NUM_IN_ADDR - prefix_length)) - 1)
        masked_addr_num = addr_num & mask
        return masked_addr_num

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_l3_ac_change_vlan_twice(self):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = self.apply_prefix_mask(self.DIP.to_num(), 16)
        prefix.length = 16
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.topology.fec_l3_ac_reg.hld_obj,
                                                 self.PRIVATE_DATA, False)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.topology.rx_l3_ac.hld_obj.set_service_mapping_vids(
            self.VID1_2,
            self.VID2_2)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_2, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.topology.rx_l3_ac.hld_obj.set_service_mapping_vids(T.RX_L3_AC_PORT_VID1, T.RX_L3_AC_PORT_VID2)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)


if __name__ == '__main__':
    unittest.main()
