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

# Test covering CSCvj80789 in addition to CSCvh81682.
#
# Description
#
#-----------
# This test covers the update of an SPA with a new member, adding a new slice,
# after the forwarding hierarchy (SP/SPA/Ethernet/L3AC) has been created
#
# The test does the following:
# 1. Create SPA with 2 Members M1(4,0,4), M2(4,1,8)
# Packet1: Ingress on SPA1:M1 -> Default NH
# 2. Add M3 to SPA (5,0,4)
# Packet2: Ingress on SPA1:M3 -> Default NH
# 3. Destroy L3AC and EP.
# 4. Recreate EP and L3AC on same SPA.
# Packet3:  Ingress on SPA1:M1 -> Default NH


from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
import scapy.all as S
import packet_test_utils as U
import ip_test_base
import decor

# Helper class


SLICE = T.get_device_slice(4)
IFG = 0

FIRST_SERDES1 = T.get_device_first_serdes(4)
LAST_SERDES1 = T.get_device_last_serdes(5)
FIRST_SERDES2 = T.get_device_next_first_serdes(8)
LAST_SERDES2 = T.get_device_next_last_serdes(9)

VRF_GID = 0x4bc if not decor.is_gibraltar() else 0xabc

CHAR_BIT = 8
BYTES_NUM_IN_ADDR = 4


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l3_ac_on_spa(unittest.TestCase):

    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    TTL = 128
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    INPUT_PACKET_BASE = \
        S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str, src=SA.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

    EXPECTED_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = U.pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)

    def setUp(self):
        self.device = sim_utils.create_device(1)
        self.topology = T.topology(self, self.device)
        # MATILDA_SAVE -- need review
        if (SLICE not in self.device.get_used_slices()) or (SLICE + 1 not in self.device.get_used_slices()):
            self.skipTest("In this model the tested slice is deactiveated, thus the test is irrelevant.")
            return

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l3_ac_port_on_spa(self):
        mac_port_member_1 = T.mac_port(
            self,
            self.device,
            SLICE,
            IFG,
            FIRST_SERDES1,
            LAST_SERDES1)
        sys_port_member_1 = T.system_port(self, self.device, 100, mac_port_member_1)

        mac_port_member_2 = T.mac_port(
            self,
            self.device,
            SLICE,
            IFG + 1,
            FIRST_SERDES2,
            LAST_SERDES2)
        sys_port_member_2 = T.system_port(self, self.device, 101, mac_port_member_2)

        mac_port_member_3 = T.mac_port(
            self,
            self.device,
            SLICE + 1,
            IFG,
            FIRST_SERDES1,
            LAST_SERDES1)
        sys_port_member_3 = T.system_port(self, self.device, 102, mac_port_member_3)

        spa_port = T.spa_port(self, self.device, 123)

        spa_port.add(sys_port_member_1)
        spa_port.add(sys_port_member_2)

        vrf = T.vrf(self, self.device, VRF_GID)

        eth_port = T.sa_ethernet_port(self, self.device, spa_port)
        l3_ac = T.l3_ac_port(
            self,
            self.device,
            T.TX_L3_AC_REG_SPA_GID,
            eth_port,
            vrf,
            T.TX_L3_AC_REG_MAC)

        l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        # add route
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = ip_test_base.ipv4_test_base.apply_prefix_mask(self.DIP.to_num(), 16)
        prefix.length = 16
        vrf.hld_obj.add_ipv4_route(prefix, self.topology.fec_l3_ac_reg.hld_obj,
                                   self.PRIVATE_DATA, False)

        # send packet SPA Memeber 1 -> DEF NH
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, SLICE, IFG, FIRST_SERDES1,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        spa_port.add(sys_port_member_3)
        # send packet SPA New member -> DEF NH
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, SLICE + 1, IFG, FIRST_SERDES1,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)
        l3_ac.destroy()
        eth_port.destroy()

        eth_port = T.sa_ethernet_port(self, self.device, spa_port)
        l3_ac = T.l3_ac_port(
            self,
            self.device,
            T.TX_L3_AC_REG_SPA_GID,
            eth_port,
            vrf,
            T.TX_L3_AC_REG_MAC)
        l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

        # send packet again SPA Member 1 -> DEF NH
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, SLICE, IFG, FIRST_SERDES1,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)


if __name__ == '__main__':
    unittest.main()
