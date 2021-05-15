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

# Test covering CSCvr14084.
#
# Description
#
#-----------
# This test covers the inject up packet forwarding with SSP as one of the
# SPA member's system port.
#
# The test does the following:
# 1. Create SPA with 2 Members M1, M2
# 2. Test1: Inject up header with SSP as SPA:M1 -> Default NH
# 3. Test2: Inject up header with SSP as SPA:M2 -> Default NH
# 4. Test4: Remove SPA:M2 and then Inject up header with SSP as SPA:M1 -> Default NH
# 5. Test5: Add SPA:M2 and Remove SPA:M1 and then Inject up header with SSP as SPA:M2 -> Default NH
# 6. Test6: Add SPA:M1 and then Inject up header with SSP as SPA:M1 -> Default NH

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


IN_SLICE = 0
IN_IFG = 0
INJECT_SLICE = 0
INJECT_IFG = 0

FIRST_SERDES1 = T.get_device_first_serdes(4)
LAST_SERDES1 = T.get_device_last_serdes(5)
FIRST_SERDES2 = T.get_device_next_first_serdes(8)
LAST_SERDES2 = T.get_device_next_last_serdes(9)
INJECT_PIF_FIRST = T.get_device_out_first_serdes(8)

VRF_GID = 0x4bc if not decor.is_gibraltar() else 0xbcc

SYS_PORT_GID_BASE = 23
INJECT_SP_GID = SYS_PORT_GID_BASE + 2
MEMBER1_SYS_PORT = SYS_PORT_GID_BASE + 3
MEMBER2_SYS_PORT = SYS_PORT_GID_BASE + 4
SPA_SYS_PORT = SYS_PORT_GID_BASE + 5

SRC_MAC = T.mac_addr('4e:41:50:00:00:10')
PUNT_INJECT_PORT_MAC_ADDR = "4e:41:50:00:00:11"


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class inject_up_with_spa(unittest.TestCase):

    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    TTL = 128

    INNER_PACKET_BASE = \
        S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str, src=SRC_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
        S.ICMP(type=8, code=0)

    INNER_PACKET, pad_len = U.enlarge_packet_to_min_length(INNER_PACKET_BASE)

    INPUT_PACKET1 = \
        Ether(dst=PUNT_INJECT_PORT_MAC_ADDR, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=1030, type=Ethertype.Inject.value) / \
        InjectUp(ssp_gid=MEMBER1_SYS_PORT, ts_opcode=1, ts_offset=54) / \
        INNER_PACKET

    INPUT_PACKET2 = \
        Ether(dst=PUNT_INJECT_PORT_MAC_ADDR, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=1030, type=Ethertype.Inject.value) / \
        InjectUp(ssp_gid=MEMBER2_SYS_PORT, ts_opcode=1, ts_offset=54) / \
        INNER_PACKET

    EXPECTED_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1) / \
        S.ICMP(type=8, code=0)

    EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, pad_len)

    def setUp(self):
        self.device = sim_utils.create_device(1)
        self.topology = T.topology(self, self.device)
        pi_port = T.punt_inject_port(
            self,
            self.device,
            INJECT_SLICE,
            INJECT_IFG,
            INJECT_SP_GID,
            INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        mac_port_member_1 = T.mac_port(
            self,
            self.device,
            IN_SLICE,
            IN_IFG,
            FIRST_SERDES1,
            LAST_SERDES1)
        self.sys_port_member_1 = T.system_port(self, self.device, MEMBER1_SYS_PORT, mac_port_member_1)

        in_ifg2 = T.get_device_ifg(IN_IFG + 1)
        mac_port_member_2 = T.mac_port(
            self,
            self.device,
            IN_SLICE,
            in_ifg2,
            FIRST_SERDES2,
            LAST_SERDES2)
        self.sys_port_member_2 = T.system_port(self, self.device, MEMBER2_SYS_PORT, mac_port_member_2)

        vrf = T.vrf(self, self.device, VRF_GID)
        self.spa_port = T.spa_port(self, self.device, SPA_SYS_PORT)
        eth_port = T.sa_ethernet_port(self, self.device, self.spa_port)
        l3_ac = T.l3_ac_port(
            self,
            self.device,
            T.TX_L3_AC_REG_SPA_GID + 1,
            eth_port,
            vrf,
            T.TX_L3_AC_REG_MAC)

        l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_ICMP_REDIRECT)

        self.spa_port.add(self.sys_port_member_1)
        self.spa_port.add(self.sys_port_member_2)

        # add route
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = ip_test_base.ipv4_test_base.apply_prefix_mask(self.DIP.to_num(), 16)
        prefix.length = 16
        vrf.hld_obj.add_ipv4_route(prefix, self.topology.fec_l3_ac_reg.hld_obj,
                                   self.PRIVATE_DATA, False)

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_inject_up_with_spa(self):

        # send inject up packet with SSP of SPA Memeber 1 -> DEF NH
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET1, INJECT_SLICE, INJECT_IFG, INJECT_PIF_FIRST,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        # send inject up packet with SSP of SPA Memeber 2 -> DEF NH
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET2, INJECT_SLICE, INJECT_IFG, INJECT_PIF_FIRST,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        # remove member2 from SPA, and send inject up packet with SSP of SPA Memeber 1 -> DEF NH
        self.spa_port.remove(self.sys_port_member_2)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET1, INJECT_SLICE, INJECT_IFG, INJECT_PIF_FIRST,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        # remove member1 and add member2 from SPA, and send inject up packet with SSP of SPA Memeber 2 -> DEF NH
        self.spa_port.remove(self.sys_port_member_1)
        self.spa_port.add(self.sys_port_member_2)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET2, INJECT_SLICE, INJECT_IFG, INJECT_PIF_FIRST,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        # add member1 to SPA, and send inject up packet with SSP of SPA Memeber 1 -> DEF NH
        self.spa_port.add(self.sys_port_member_1)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET1, INJECT_SLICE, INJECT_IFG, INJECT_PIF_FIRST,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)


if __name__ == '__main__':
    unittest.main()
