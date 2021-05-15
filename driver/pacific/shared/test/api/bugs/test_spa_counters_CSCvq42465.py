#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import sim_utils
import packet_test_utils as U
import scapy.all as S
import topology as T
import ip_test_base
from sdk_test_case_base import sdk_test_case_base
import decor

SPA_L3AC_GID = 2399
SLICE = T.get_device_slice(3)
IFG = 0
FIRST_SERDES1 = T.get_device_first_serdes(4)
LAST_SERDES1 = T.get_device_last_serdes(5)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_spa_counters(sdk_test_case_base):
    SIP = T.ipv4_addr('192.168.0.1')
    DIP = T.ipv4_addr('192.168.1.1')
    OUTPUT_VID = 0xac
    TTL = 200
    PAYLOAD_SIZE = 64
    PRIVATE_DATA = 0x1234567890abcdef
    EXPECTED_OUT_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1) / \
        S.TCP(sport=0x65, dport=0x64)
    EXPECTED_OUT_PACKET = U.add_payload(EXPECTED_OUT_BASE, PAYLOAD_SIZE)

    IN_PACKET_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=T.RX_L3_AC_MAC1.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
        S.TCP(sport=0x65, dport=0x64)
    IN_PACKET = U.add_payload(IN_PACKET_BASE, PAYLOAD_SIZE)

    def create_lag(self):
        mac_port_member_1 = T.mac_port(
            self,
            self.device,
            SLICE,
            IFG,
            FIRST_SERDES1,
            LAST_SERDES1)
        mac_port_member_1.activate()
        self.sys_port_member_1 = T.system_port(self, self.device, 100, mac_port_member_1)
        mac_port_member_2 = T.mac_port(
            self,
            self.device,
            SLICE + 1,
            IFG,
            FIRST_SERDES1,
            LAST_SERDES1)
        mac_port_member_2.activate()
        self.sys_port_member_2 = T.system_port(self, self.device, 101, mac_port_member_2)
        self.spa_port = T.spa_port(self, self.device, 123)

        self.spa_port.add(self.sys_port_member_1)
        self.spa_port.add(self.sys_port_member_2)

        eth_port = T.sa_ethernet_port(self, self.device, self.spa_port)
        topology_tc = self.topology.tc_profile_def
        self.spa_l3_ac = T.l3_ac_port(
            self,
            self.device,
            SPA_L3AC_GID,
            eth_port,
            self.topology.vrf,
            T.TX_L3_AC_REG_MAC,
            vid1=self.OUTPUT_VID,
            vid2=0)
        self.spa_l3_ac.hld_obj.set_tc_profile(topology_tc.hld_obj)
        self.device.set_spa_hash_seed(0xa2bf)

    def add_spa_prefix(self):
        prefix = ip_test_base.ipv4_test_base.build_prefix(self.DIP, length=16)
        nh_l3_ac = T.next_hop(self, self.device, T.NH_L3_AC_REG_GID + 1, T.NH_L3_AC_REG_MAC, self.spa_l3_ac)
        fec = T.fec(self, self.device, nh_l3_ac)
        ip_test_base.ipv4_test_base.add_route(self.topology.vrf, prefix, fec, self.PRIVATE_DATA)

    def attach_port_counters(self, l3ac):
        self.egress_counter = self.device.create_counter(sdk.la_l3_protocol_e_LAST)
        l3ac.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.egress_counter)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_spa_port_counters(self):
        # MATILDA_SAVE -- need review
        if (SLICE not in self.device.get_used_slices()) or (SLICE + 1 not in self.device.get_used_slices()):
            self.skipTest("In this model the tested slice is deactiveated, thus the test is irrelevant.")
            return

        self.create_lag()
        self.add_spa_prefix()
        self.attach_port_counters(self.spa_l3_ac)
        # Test packet
        self.run_and_compare_spa(self.spa_port,
                                 self.IN_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                 self.EXPECTED_OUT_PACKET)
        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_IPV4_UC, True, False)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUT_PACKET, byte_count)

        self.spa_port.remove(self.sys_port_member_1)
        self.spa_port.remove(self.sys_port_member_2)

        packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_IPV4_UC, True, False)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUT_PACKET, byte_count)

    def run_and_compare_spa(self, spa_port, input_packet, input_slice, input_ifg, input_serdes, out_packet):
        dip = T.ipv4_addr(input_packet[S.IP].dst)
        sip = T.ipv4_addr(input_packet[S.IP].src)
        dport = input_packet[S.TCP].dport
        sport = input_packet[S.TCP].sport

        lb_vec = sdk.la_lb_vector_t()
        lb_vec.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
        lb_vec.ipv4.sip = sip.hld_obj.s_addr
        lb_vec.ipv4.dip = dip.hld_obj.s_addr
        lb_vec.ipv4.src_port = sport
        lb_vec.ipv4.dest_port = dport
        lb_vec.ipv4.protocol = input_packet[S.IP].proto

        lb_vec_entry_list = []
        lb_vec_entry_list.append(lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(spa_port.hld_obj, lb_vec_entry_list)

        self.assertEqual(out_dest_chain[-1].type(), sdk.la_object.object_type_e_SYSTEM_PORT)

        out_dsp = out_dest_chain[-1].downcast()
        U.run_and_compare(self, self.device,
                          input_packet, input_slice, input_ifg, input_serdes,
                          out_packet, out_dsp.get_slice(), out_dsp.get_ifg(), out_dsp.get_base_pif())


if __name__ == '__main__':
    unittest.main()
