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

import decor
from ipv4_ecmp_routing_base import *
import sim_utils
import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
from ipaddress import IPv4Address
import packet_test_defs as P


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class test_ipv4_ecmp_routing(ipv4_ecmp_routing_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_destroy(self):
        self.create_network_topology()

        # ecmp1 cannot be destroyed because it is used by ecmp_rec
        try:
            self.device.destroy(self.m_ecmp1)
            self.assertFail()
        except sdk.BaseException:
            pass

        self.device.destroy(self.m_ecmp_rec)
        self.device.destroy(self.m_fec1)
        self.device.destroy(self.m_ecmp1)

        self.m_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)

        # Add 1 members
        self.m_ecmp1.add_member(self.m_nh1.hld_obj)

        self.m_fec1 = self.device.create_l3_fec(self.m_ecmp1)
        self.assertIsNotNone(self.m_fec1)

        prefix2 = sdk.la_ipv4_prefix_t()
        addr = T.ipv4_addr('10.01.01.01').hld_obj
        addr.s_addr &= 0xffff0000
        prefix2.addr = addr
        prefix2.length = 16

        self.m_vrf.hld_obj.add_ipv4_route(prefix2, self.m_ecmp1, PRIVATE_DATA, False)
        self.m_vrf.hld_obj.delete_ipv4_route(prefix2)

        self.m_ecmp_rec_attached_members = [self.m_ecmp1]

        self.m_ecmp_rec = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.assertNotEqual(self.m_ecmp_rec, None)

        for member in self.m_ecmp_rec_attached_members:
            self.m_ecmp_rec.add_member(member)

        self.create_routing_entry()

        output_packet = ipv4_ecmp_routing_base.get_output_packet(self.OUTPUT1_PACKET, self.m_nh1.hld_obj)
        U.run_and_compare(self, self.device,
                          self.INPUT1_PACKET, self.s_rx_slice, self.s_rx_ifg, self.s_rx_first_serdes,
                          output_packet, self.s_tx1_slice, self.s_tx1_ifg, self.s_tx1_first_serdes)

        output_packet = ipv4_ecmp_routing_base.get_output_packet(self.OUTPUT_REC2_PACKET, self.m_nh1.hld_obj)
        U.run_and_compare(self, self.device,
                          self.INPUT_REC_PACKET, self.s_rx_slice, self.s_rx_ifg, self.s_rx_first_serdes,
                          output_packet, self.s_tx1_slice, self.s_tx1_ifg, self.s_tx1_first_serdes)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_duplicate_nh(self):
        self.create_network_topology()

        self.m_ecmp1.add_member(self.m_nh1.hld_obj)
        self.m_ecmp1.remove_member(self.m_nh1.hld_obj)
        self.m_ecmp1.remove_member(self.m_nh1.hld_obj)

        try:
            self.m_ecmp1.remove_member(self.m_nh1.hld_obj)
            self.assertFail()
        except sdk.BaseException:
            pass

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_get_members(self):
        self.create_network_topology()

        # Check get_member
        res_l3_destination = self.m_ecmp1.get_member(0)
        self.assertEqual(res_l3_destination.this, self.m_nh1.hld_obj.this)
        res_l3_destination = self.m_ecmp1.get_member(1)
        self.assertEqual(res_l3_destination.this, self.m_nh_spa.hld_obj.this)

        try:
            self.m_ecmp1.get_member(5)
            self.assertFail()
        except sdk.BaseException:
            pass

        # Check get_members
        res_l3_destinations = self.m_ecmp1.get_members()

        for i in range(0, len(self.m_ecmp1_attached_members)):
            self.assertEqual(res_l3_destinations[i].this, self.m_ecmp1_attached_members[i].hld_obj.this)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_invalid_use(self):
        self.create_network_topology()

        ip_impl = ip_test_base.ipv4_test_base()

        # Use ECMP group for plain IP routing
        lpm_prefix = ip_impl.build_prefix(self.s_dip1, length=0)
        self.m_vrf.hld_obj.add_ipv4_route(lpm_prefix, self.m_ecmp3, PRIVATE_DATA, False)

        try:
            # Try to use the above ECMP group also for an LDP prefix - this should fail
            pfx_obj = T.prefix_object(self, self.device, PREFIX_OBJ_GID, self.m_ecmp3)
            self.assertFail()
        except sdk.BaseException:
            pass

        # Delete the prefix
        self.m_vrf.hld_obj.delete_ipv4_route(lpm_prefix)

        # Try to reuse the above ECMP group for an LDP prefix - this should pass
        pfx_obj = T.prefix_object(self, self.device, PREFIX_OBJ_GID, self.m_ecmp3)

        try:
            # Try to use the above ECMP group also for plain IP routing - this should fail
            self.m_vrf.hld_obj.add_ipv4_route(lpm_prefix, self.m_ecmp3, PRIVATE_DATA, False)
            self.assertFail()
        except sdk.BaseException:
            pass

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_remove_invalid_nh(self):
        self.create_network_topology()

        try:
            self.m_ecmp1.remove_member(self.m_nh3.hld_obj)
            self.assertFail()
        except sdk.BaseException:
            pass

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_remove_member(self):
        self.create_network_topology()

        # Add 3 members
        self.m_ecmp1.add_member(self.m_nh3.hld_obj)
        self.m_ecmp1.add_member(self.m_nh4.hld_obj)
        self.m_ecmp1.add_member(self.m_nh5.hld_obj)

        # Remove the last member
        self.m_ecmp1.remove_member(self.m_nh5.hld_obj)

        # Confirm that the last member got removed

        try:
            self.m_ecmp1.remove_member(self.m_nh5.hld_obj)
            self.assertFail()
        except sdk.BaseException:
            pass

        # Remove any other member
        self.m_ecmp1.remove_member(self.m_nh3.hld_obj)

        # Confirm that the member got removed

        try:
            self.m_ecmp1.remove_member(self.m_nh3.hld_obj)
            self.assertFail()
        except sdk.BaseException:
            pass

        # Cleanup the other members that were added
        self.m_ecmp1.remove_member(self.m_nh4.hld_obj)

        try:
            self.m_ecmp1.remove_member(self.m_nh4.hld_obj)
            self.assertFail()
        except sdk.BaseException:
            pass

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_set_members(self):
        self.create_network_topology()
        self.create_routing_entry()

        members = []

        try:
            self.m_ecmp1.set_members(members)
            self.assertFail()
        except sdk.BaseException:
            pass

        members.append(self.m_nh1.hld_obj)
        members.append(self.m_nh2.hld_obj)
        self.m_ecmp1.set_members(members)

        members.append(self.m_nh2.hld_obj)
        self.m_ecmp1.set_members(members)

        members.append(self.m_nh3.hld_obj)
        self.m_ecmp1.set_members(members)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_ecmp_routing_after_nh1_delete(self):
        self.create_network_topology()
        self.m_ecmp1.remove_member(self.m_nh1.hld_obj)
        self.m_ecmp1.remove_member(self.m_nh2.hld_obj)
        self.create_routing_entry()

        # After nh1 is deleted, the current last member (spa) would be moved to entry 0
        # Packet 3 destination mac is the same as the SPA destination MAC. But the
        # payload is the same as input packet1 payload
        U.run_and_compare(self, self.device,
                          self.INPUT_DELETE_NH1_PACKET, self.s_rx_slice, self.s_rx_ifg, self.s_rx_first_serdes,
                          self.OUTPUT_DELETE_NH1_PACKET, self.s_tx_spa_slice, self.s_tx_spa_ifg, self.s_tx_first_serdes)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_ecmp_routing_modify(self):
        self.create_network_topology()
        self.create_routing_entry()

        prefix = sdk.la_ipv4_prefix_t()
        addr = self.s_dip1.hld_obj
        addr.s_addr &= 0xffff0000
        prefix.addr = addr
        prefix.length = 16

        self.m_ecmp3 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)

        # Add 1 members
        self.m_ecmp3.add_member(self.m_nh2.hld_obj)
        self.m_vrf.hld_obj.modify_ipv4_route(prefix, self.m_ecmp3)

        load_bal_vector = sdk.la_lb_vector_t()
        load_bal_vector.type = sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP
        load_bal_vector.ipv4.sip = self.s_sip.hld_obj.s_addr
        load_bal_vector.ipv4.dip = self.s_dip2.hld_obj.s_addr
        load_bal_vector.ipv4.protocol = 0

        lb_vec_entry_list = []
        lb_vec_entry_list.append(load_bal_vector)

        self.device.set_ecmp_hash_seed(0x1111)
        out_dest_chain = self.device.get_forwarding_load_balance_chain(self.m_ecmp3, lb_vec_entry_list)
        U.check_forwarding_load_balance_chain(self, out_dest_chain, self.s_tx2_slice, self.s_tx2_ifg, self.s_tx2_first_serdes)
        U.run_and_compare(self, self.device,
                          self.INPUT2_PACKET, self.s_rx_slice, self.s_rx_ifg, self.s_rx_first_serdes,
                          self.OUTPUT3_PACKET, self.s_tx2_slice, self.s_tx2_ifg, self.s_tx2_first_serdes)

        self.m_ecmp3.remove_member(self.m_nh2.hld_obj)
        self.m_vrf.hld_obj.delete_ipv4_route(prefix)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_ecmp_routing_nh_spa(self):
        self.create_network_topology()
        self.create_routing_entry()
        self.device.set_spa_hash_seed(0xa2bf)
        self.run_and_compare_ecmp(self.m_ecmp1,
                                  self.INPUT_SPA_PACKET, self.s_rx_slice, self.s_rx_ifg, self.s_rx_first_serdes,
                                  self.OUTPUT_SPA_PACKET)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_ecmp_routing_nh1(self):
        self.create_network_topology()
        self.create_routing_entry()
        self.device.set_ecmp_hash_seed(0xffff)
        self.run_and_compare_ecmp(self.m_ecmp1,
                                  self.INPUT1_PACKET, self.s_rx_slice, self.s_rx_ifg, self.s_rx_first_serdes,
                                  self.OUTPUT1_PACKET)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_ecmp_routing_nh2(self):
        self.create_network_topology()
        self.create_routing_entry()
        self.device.set_ecmp_hash_seed(0xa7b2)
        self.run_and_compare_ecmp(self.m_ecmp1,
                                  self.INPUT2_PACKET, self.s_rx_slice, self.s_rx_ifg, self.s_rx_first_serdes,
                                  self.OUTPUT2_PACKET)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_ecmp_routing_recursive(self):
        self.create_network_topology()
        self.create_routing_entry()
        self.device.set_ecmp_hash_seed(0xcccc)
        self.run_and_compare_ecmp(self.m_ecmp_rec,
                                  self.INPUT_REC_PACKET, self.s_rx_slice, self.s_rx_ifg, self.s_rx_first_serdes,
                                  self.OUTPUT_REC_PACKET)

        # Testing that we can't set ECMP of level 1 to FEC destination
        try:
            self.m_fec1.set_destination(self.m_ecmp_rec)
            self.assertFail()
        except sdk.BaseException:
            pass

        try:
            self.m_ecmp2.add_member(self.m_ecmp1)
            self.assertFail()
        except sdk.BaseException:
            pass

        self.m_ecmp_rec.add_member(self.m_ecmp2)

        self.m_ecmp_rec.add_member(self.m_nh1.hld_obj)

        self.run_and_compare_ecmp(self.m_ecmp_rec,
                                  self.INPUT_REC_PACKET, self.s_rx_slice, self.s_rx_ifg, self.s_rx_first_serdes,
                                  self.OUTPUT_REC1_PACKET)

        self.m_ecmp_rec_attached_members = [self.m_ecmp1, self.m_nh1.hld_obj, self.m_nh1.hld_obj, self.m_ecmp2]
        self.m_ecmp_rec.set_members(self.m_ecmp_rec_attached_members)

        try:
            self.m_ecmp2.add_member(self.m_ecmp1)
            self.assertFail()
        except sdk.BaseException:
            pass

        self.m_ecmp_rec.add_member(self.m_ecmp2)

        self.m_ecmp_rec.add_member(self.m_nh1.hld_obj)

        self.run_and_compare_ecmp(self.m_ecmp_rec,
                                  self.INPUT_REC_PACKET, self.s_rx_slice, self.s_rx_ifg, self.s_rx_first_serdes,
                                  self.OUTPUT_REC3_PACKET)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_ecmp_loadbalance_hash(self):
        self.topology.create_topology()
        self.topology.topology_created = True

        NUM_OF_NH = 5
        NH_GID_BASE = 0x613
        NH_DST_MAC_BASE = T.mac_addr('11:11:11:11:11:00')
        SIP_local = T.ipv4_addr('155.24.162.37')
        DIP_BASE_local = T.ipv4_addr('111.111.111.111')

        l3_port_impl = T.ip_l3_ac_base(self.topology)
        ip_impl = ip_test_base.ipv4_test_base

        prefix = ip_impl.build_prefix(DIP_BASE_local, length=16)

        ecmp_level = sdk.la_ecmp_group.level_e_LEVEL_1 if decor.is_asic3() else sdk.la_ecmp_group.level_e_LEVEL_2
        ecmp_group = self.device.create_ecmp_group(ecmp_level)
        for nh_num in range(NUM_OF_NH):
            nh = T.next_hop(
                self,
                self.device,
                NH_GID_BASE + nh_num,
                NH_DST_MAC_BASE.create_offset_mac(nh_num),
                l3_port_impl.tx_port)
            ecmp_group.add_member(nh.hld_obj)

        self.topology.vrf.hld_obj.add_ipv4_route(prefix, ecmp_group, PRIVATE_DATA, False)

        for packet_num in range(self.NUM_OF_PACKETS):
            DIP_local = IPv4Address(DIP_BASE_local.to_num() + (self.PACKETS_OFFSET * packet_num))

            lb_vec_entry_list = []
            load_bal_vector_ecmp_stress = sdk.la_lb_vector_t()
            load_bal_vector_ecmp_stress.type = sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP
            load_bal_vector_ecmp_stress.ipv4.sip = T.ipv4_addr(SIP_local.addr_str).to_num()
            load_bal_vector_ecmp_stress.ipv4.dip = T.ipv4_addr(DIP_local).to_num()
            load_bal_vector_ecmp_stress.ipv4.protocol = 0

            lb_vec_entry_list.append(load_bal_vector_ecmp_stress)

            out_dest_chain = self.device.get_forwarding_load_balance_chain(ecmp_group, lb_vec_entry_list)
            U.check_forwarding_load_balance_chain(self, out_dest_chain, T.TX_SLICE_REG, T.TX_IFG_REG, l3_port_impl.serdes_reg)

            INPUT_PACKET_BASE_local = \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.EXT_MAC.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=SIP_local.addr_str, dst=str(DIP_local), ttl=self.TTL)
            INPUT_PACKET_local = U.add_payload(INPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            expected_mac = out_dest_chain[0].downcast().get_mac().flat
            expected_mac_str = T.mac_addr.mac_num_to_str(expected_mac)

            EXPECTED_OUTPUT_PACKET_BASE_local = \
                S.Ether(dst=expected_mac_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
                S.IP(src=SIP_local.addr_str, dst=str(DIP_local), ttl=self.TTL - 1)
            EXPECTED_OUTPUT_PACKET_local = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            U.run_and_compare(self, self.device,
                              INPUT_PACKET_local, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                              EXPECTED_OUTPUT_PACKET_local, T.TX_SLICE_REG, T.TX_IFG_REG, l3_port_impl.serdes_reg)

        ip_impl.delete_route(self.topology.vrf, prefix)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_loadbalance_hash_gre_ipv4_transit(self):
        self.topology.create_topology()
        self.topology.topology_created = True

        SIP_UNL = T.ipv4_addr('10.1.1.1')
        DIP_UNL = T.ipv4_addr('10.1.1.2')
        SPORT_UNL_BASE = 4000
        DPORT_UNL_BASE = 2000

        l3_port_impl = T.ip_l3_ac_base(self.topology)
        ip_impl = ip_test_base.ipv4_test_base

        self.create_ecmp_group_for_transit()
        prefix = ip_impl.build_prefix(self.DIP_BASE_OVL, length=16)
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.ecmp_group, PRIVATE_DATA, False)

        # Transit GRE packets with TCP underlay
        for packet_num in range(self.NUM_OF_PACKETS):
            DIP_OVL = IPv4Address(self.DIP_BASE_OVL.to_num() + (self.PACKETS_OFFSET * packet_num))
            SPORT_UNL = SPORT_UNL_BASE + packet_num
            DPORT_UNL = DPORT_UNL_BASE + packet_num

            INPUT_PACKET_BASE_local = \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.EXT_MAC.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL) / \
                S.GRE() / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str) / \
                S.TCP(sport=SPORT_UNL, dport=DPORT_UNL)
            INPUT_PACKET_local = U.add_payload(INPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            EXPECTED_OUTPUT_PACKET_BASE_local = \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL - 1) / \
                S.GRE() / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str) / \
                S.TCP(sport=SPORT_UNL, dport=DPORT_UNL)
            EXPECTED_OUTPUT_PACKET_local = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            self.run_and_compare_ecmp_for_gre_transit(INPUT_PACKET_local, EXPECTED_OUTPUT_PACKET_local)

        # Transit GRE packets with IP underlay
        for packet_num in range(self.NUM_OF_PACKETS):
            DIP_OVL = IPv4Address(self.DIP_BASE_OVL.to_num() + (self.PACKETS_OFFSET * packet_num))

            INPUT_PACKET_BASE_local = \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.EXT_MAC.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL) / \
                S.GRE() / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str)
            INPUT_PACKET_local = U.add_payload(INPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            EXPECTED_OUTPUT_PACKET_BASE_local = \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL - 1) / \
                S.GRE() / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str)
            EXPECTED_OUTPUT_PACKET_local = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)
            self.run_and_compare_ecmp_for_gre_transit(INPUT_PACKET_local, EXPECTED_OUTPUT_PACKET_local)

        ip_impl.delete_route(self.topology.vrf, prefix)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_loadbalance_hash_gre_ipv6_transit(self):
        self.topology.create_topology()
        self.topology.topology_created = True

        SIP_UNL = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')
        DIP_UNL = T.ipv6_addr('2222:0db8:0a0b:12f0:aaaa:ffff:3333:2222')
        SPORT_UNL_BASE = 4000
        DPORT_UNL_BASE = 2000

        l3_port_impl = T.ip_l3_ac_base(self.topology)
        ip_impl = ip_test_base.ipv4_test_base

        self.create_ecmp_group_for_transit()
        prefix = ip_impl.build_prefix(self.DIP_BASE_OVL, length=16)
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.ecmp_group, PRIVATE_DATA, False)

        # Transit GRE packets with TCP underlay
        for packet_num in range(self.NUM_OF_PACKETS):
            DIP_OVL = IPv4Address(self.DIP_BASE_OVL.to_num() + (self.PACKETS_OFFSET * packet_num))
            SPORT_UNL = SPORT_UNL_BASE + packet_num
            DPORT_UNL = DPORT_UNL_BASE + packet_num

            INPUT_PACKET_BASE_local = \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.EXT_MAC.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL) / \
                S.GRE(proto=0x86DD) / \
                S.IPv6(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str) / \
                S.TCP(sport=SPORT_UNL, dport=DPORT_UNL)
            INPUT_PACKET_local = U.add_payload(INPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            EXPECTED_OUTPUT_PACKET_BASE_local = \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL - 1) / \
                S.GRE(proto=0x86DD) / \
                S.IPv6(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str) / \
                S.TCP(sport=SPORT_UNL, dport=DPORT_UNL)
            EXPECTED_OUTPUT_PACKET_local = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            self.run_and_compare_ecmp_for_gre_transit(INPUT_PACKET_local, EXPECTED_OUTPUT_PACKET_local)

        # Transit GRE packets with IPv6 underlay
        for packet_num in range(self.NUM_OF_PACKETS):
            DIP_OVL = IPv4Address(self.DIP_BASE_OVL.to_num() + (self.PACKETS_OFFSET * packet_num))

            INPUT_PACKET_BASE_local = \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.EXT_MAC.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL) / \
                S.GRE(proto=0x86DD) / \
                S.IPv6(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str)
            INPUT_PACKET_local = U.add_payload(INPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            EXPECTED_OUTPUT_PACKET_BASE_local = \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL - 1) / \
                S.GRE(proto=0x86DD) / \
                S.IPv6(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str)
            EXPECTED_OUTPUT_PACKET_local = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            self.run_and_compare_ecmp_for_gre_transit(INPUT_PACKET_local, EXPECTED_OUTPUT_PACKET_local)

        ip_impl.delete_route(self.topology.vrf, prefix)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_loadbalance_hash_gre_mpls_transit(self):
        self.topology.create_topology()
        self.topology.topology_created = True

        SIP_UNL = T.ipv4_addr('10.1.1.1')
        DIP_UNL = T.ipv4_addr('10.1.1.2')
        SPORT_UNL_BASE = 4000
        DPORT_UNL_BASE = 2000
        MPLS_TRANSIT_LABEL = 100

        l3_port_impl = T.ip_l3_ac_base(self.topology)
        ip_impl = ip_test_base.ipv4_test_base

        self.create_ecmp_group_for_transit()
        prefix = ip_impl.build_prefix(self.DIP_BASE_OVL, length=16)
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.ecmp_group, PRIVATE_DATA, False)

        # Transit GRE packets with TCP underlay
        for packet_num in range(self.NUM_OF_PACKETS):
            DIP_OVL = IPv4Address(self.DIP_BASE_OVL.to_num() + (self.PACKETS_OFFSET * packet_num))
            SPORT_UNL = SPORT_UNL_BASE + packet_num
            DPORT_UNL = DPORT_UNL_BASE + packet_num

            INPUT_PACKET_BASE_local = \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.EXT_MAC.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL) / \
                S.GRE(proto=U.Ethertype.MPLS.value) / \
                MPLS(label=MPLS_TRANSIT_LABEL) / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str) / \
                S.TCP(sport=SPORT_UNL, dport=DPORT_UNL)
            INPUT_PACKET_local = U.add_payload(INPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            EXPECTED_OUTPUT_PACKET_BASE_local = \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL - 1) / \
                S.GRE(proto=U.Ethertype.MPLS.value) / \
                MPLS(label=MPLS_TRANSIT_LABEL) / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str) / \
                S.TCP(sport=SPORT_UNL, dport=DPORT_UNL)
            EXPECTED_OUTPUT_PACKET_local = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            self.run_and_compare_ecmp_for_gre_transit(INPUT_PACKET_local, EXPECTED_OUTPUT_PACKET_local)

        # Transit GRE packets with IP underlay
        for packet_num in range(self.NUM_OF_PACKETS):
            DIP_OVL = IPv4Address(self.DIP_BASE_OVL.to_num() + (self.PACKETS_OFFSET * packet_num))

            INPUT_PACKET_BASE_local = \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.EXT_MAC.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL) / \
                S.GRE() / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str)
            INPUT_PACKET_local = U.add_payload(INPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            EXPECTED_OUTPUT_PACKET_BASE_local = \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL - 1) / \
                S.GRE() / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str)
            EXPECTED_OUTPUT_PACKET_local = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)
            self.run_and_compare_ecmp_for_gre_transit(INPUT_PACKET_local, EXPECTED_OUTPUT_PACKET_local)

        ip_impl.delete_route(self.topology.vrf, prefix)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_loadbalance_hash_gtp_transit(self):
        self.topology.create_topology()
        self.topology.topology_created = True

        SIP_UNL = T.ipv4_addr('10.1.1.1')
        DIP_UNL = T.ipv4_addr('10.1.1.2')
        IPOVL_LEN = 60
        IPUNL_LEN = 20
        UDP_LEN = 40
        UDP_SPORT = 4000
        GTP_PORT = 2152
        GTP_TEID = 0xabcdffff
        GTP_VER_ascii = '\x90\x44\x00\x1c'      # GTP Version + TEID Flag + Message type
        GTP_TEID_ascii = '\xab\xcd\xff\xff'     # Tunnel ID 0xabcdffff in ascii
        GTP_SEQ_ascii = '\x00\x00\x01\x00'      # GTP sequence number

        l3_port_impl = T.ip_l3_ac_base(self.topology)
        ip_impl = ip_test_base.ipv4_test_base

        self.create_ecmp_group_for_transit()
        prefix = ip_impl.build_prefix(self.DIP_BASE_OVL, length=16)
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.ecmp_group, PRIVATE_DATA, False)

        gtp_raw = S.Raw()
        gtp_raw.load = GTP_VER_ascii + GTP_TEID_ascii + GTP_SEQ_ascii

        # Transit GTP packets with IP underlay
        for packet_num in range(self.NUM_OF_PACKETS):
            DIP_OVL = IPv4Address(self.DIP_BASE_OVL.to_num() + (self.PACKETS_OFFSET * packet_num))

            INPUT_PACKET_BASE_local = \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.EXT_MAC.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL, len=IPOVL_LEN) / \
                S.UDP(sport=UDP_SPORT, dport=GTP_PORT, len=UDP_LEN) / \
                gtp_raw / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str, ttl=self.TTL, len=IPUNL_LEN)
            INPUT_PACKET_local = U.add_payload(INPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            EXPECTED_OUTPUT_PACKET_BASE_local = \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL - 1, len=IPOVL_LEN) / \
                S.UDP(sport=UDP_SPORT, dport=GTP_PORT, len=UDP_LEN) / \
                gtp_raw  / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str, ttl=self.TTL, len=IPUNL_LEN)
            EXPECTED_OUTPUT_PACKET_local = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            self.run_and_compare_ecmp_for_gtp_transit(INPUT_PACKET_local, EXPECTED_OUTPUT_PACKET_local, GTP_TEID)

        ip_impl.delete_route(self.topology.vrf, prefix)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_loadbalance_hash_gue_transit(self):
        self.topology.create_topology()
        self.topology.topology_created = True
        self.GUE_PORT = 6080

        SIP_UNL = T.ipv4_addr('192.168.100.98')
        DIP_UNL = T.ipv4_addr('192.168.100.99')
        UDP_SPORT = 4000
        GUE_PORT_MPLS = 6635
        MPLS_TRANSIT_LABEL = 100

        l3_port_impl = T.ip_l3_ac_base(self.topology)
        ip_impl = ip_test_base.ipv4_test_base

        self.create_ecmp_group_for_transit()
        prefix = ip_impl.build_prefix(self.DIP_BASE_OVL, length=16)
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.ecmp_group, PRIVATE_DATA, False)

        # Transit GUE packets with TCP underlay
        for packet_num in range(self.NUM_OF_PACKETS):
            DIP_OVL = IPv4Address(self.DIP_BASE_OVL.to_num() + (self.PACKETS_OFFSET * packet_num))

            INPUT_PACKET_BASE_local = \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.EXT_MAC.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL) / \
                S.UDP(sport=UDP_SPORT, dport=self.GUE_PORT) / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str, ttl=self.TTL) / \
                S.TCP()
            INPUT_PACKET_local = U.add_payload(INPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            EXPECTED_OUTPUT_PACKET_BASE_local = \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL - 1) / \
                S.UDP(sport=UDP_SPORT, dport=self.GUE_PORT) / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str, ttl=self.TTL) / \
                S.TCP()
            EXPECTED_OUTPUT_PACKET_local = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            self.run_and_compare_ecmp_for_gue_transit(
                INPUT_PACKET_local,
                EXPECTED_OUTPUT_PACKET_local,
                sdk.la_l3_protocol_e_IPV4_UC)

        ip_impl.delete_route(self.topology.vrf, prefix)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_loadbalance_hash_gue_ipv6_transit(self):
        self.topology.create_topology()
        self.topology.topology_created = True
        self.GUE_PORT = 6080

        SIP_UNL = T.ipv6_addr('1111:0db8:0a0b:12f0:ffff:eeee:abcd:1111')
        DIP_UNL = T.ipv6_addr('2222:0db8:0a0b:12f0:aaaa:ffff:3333:2222')
        UDP_SPORT = 4000

        l3_port_impl = T.ip_l3_ac_base(self.topology)
        ip_impl = ip_test_base.ipv4_test_base

        self.create_ecmp_group_for_transit()
        prefix = ip_impl.build_prefix(self.DIP_BASE_OVL, length=16)
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.ecmp_group, PRIVATE_DATA, False)

        # Transit GUE packets with TCP underlay
        for packet_num in range(self.NUM_OF_PACKETS):
            DIP_OVL = IPv4Address(self.DIP_BASE_OVL.to_num() + (self.PACKETS_OFFSET * packet_num))
            UDP_SPORT = UDP_SPORT + packet_num

            INPUT_PACKET_BASE_local = \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.EXT_MAC.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL) / \
                S.UDP(sport=UDP_SPORT, dport=self.GUE_PORT) / \
                S.IPv6(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str)
            INPUT_PACKET_local = INPUT_PACKET_BASE_local

            EXPECTED_OUTPUT_PACKET_BASE_local = \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL - 1) / \
                S.UDP(sport=UDP_SPORT, dport=self.GUE_PORT) / \
                S.IPv6(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str)
            EXPECTED_OUTPUT_PACKET_local = EXPECTED_OUTPUT_PACKET_BASE_local

            self.run_and_compare_ecmp_for_gue_transit(
                INPUT_PACKET_local,
                EXPECTED_OUTPUT_PACKET_local,
                sdk.la_l3_protocol_e_IPV6_UC)

        ip_impl.delete_route(self.topology.vrf, prefix)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_loadbalance_hash_gue_mpls_transit(self):
        self.topology.create_topology()
        self.topology.topology_created = True

        SIP_UNL = T.ipv4_addr('192.168.100.98')
        DIP_UNL = T.ipv4_addr('192.168.100.99')
        UDP_SPORT = 4000
        GUE_PORT_MPLS = 6635
        MPLS_TRANSIT_LABEL = 100

        l3_port_impl = T.ip_l3_ac_base(self.topology)
        ip_impl = ip_test_base.ipv4_test_base

        self.create_ecmp_group_for_transit()
        prefix = ip_impl.build_prefix(self.DIP_BASE_OVL, length=16)
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.ecmp_group, PRIVATE_DATA, False)

        # Transit GUE packets with TCP underlay
        for packet_num in range(self.NUM_OF_PACKETS):
            DIP_OVL = IPv4Address(self.DIP_BASE_OVL.to_num() + (self.PACKETS_OFFSET * packet_num))
            UDP_SPORT = UDP_SPORT + packet_num

            INPUT_PACKET_BASE_local = \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.EXT_MAC.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL) / \
                S.UDP(sport=UDP_SPORT, dport=GUE_PORT_MPLS) / \
                MPLS(label=MPLS_TRANSIT_LABEL) / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str, ttl=self.TTL)
            INPUT_PACKET_local = U.add_payload(INPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            EXPECTED_OUTPUT_PACKET_BASE_local = \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL - 1) / \
                S.UDP(sport=UDP_SPORT, dport=GUE_PORT_MPLS) / \
                MPLS(label=MPLS_TRANSIT_LABEL) / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str, ttl=self.TTL)
            EXPECTED_OUTPUT_PACKET_local = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            self.run_and_compare_ecmp_for_gue_transit(INPUT_PACKET_local, EXPECTED_OUTPUT_PACKET_local, sdk.la_l3_protocol_e_MPLS)

        ip_impl.delete_route(self.topology.vrf, prefix)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_loadbalance_hash_nvgre_transit(self):
        self.topology.create_topology()
        self.topology.topology_created = True

        DST_MAC_UNL = T.mac_addr('aa:bb:cc:aa:bb:cc')
        SRC_MAC_UNL = T.mac_addr('ab:cd:ab:cd:ab:cd')
        VLAN_UNL = 2000
        SIP_UNL = T.ipv4_addr('10.1.1.1')
        DIP_UNL = T.ipv4_addr('10.1.1.2')
        SPORT_UNL_BASE = 4000
        DPORT_UNL_BASE = 2000

        l3_port_impl = T.ip_l3_ac_base(self.topology)
        ip_impl = ip_test_base.ipv4_test_base

        self.create_ecmp_group_for_transit()
        prefix = ip_impl.build_prefix(self.DIP_BASE_OVL, length=16)
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.ecmp_group, PRIVATE_DATA, False)

        # Transit NVGRE packets with tagged ether underlay
        for packet_num in range(self.NUM_OF_PACKETS):
            DIP_OVL = IPv4Address(self.DIP_BASE_OVL.to_num() + (self.PACKETS_OFFSET * packet_num))
            SPORT_UNL = SPORT_UNL_BASE + packet_num
            DPORT_UNL = DPORT_UNL_BASE + packet_num

            INPUT_PACKET_BASE_local = \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.EXT_MAC.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL) / \
                S.GRE(proto=0x6558) / \
                S.Ether(dst=DST_MAC_UNL.addr_str, src=SRC_MAC_UNL.addr_str, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=VLAN_UNL) / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str) / \
                S.TCP(sport=SPORT_UNL, dport=DPORT_UNL)
            INPUT_PACKET_local = U.add_payload(INPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            EXPECTED_OUTPUT_PACKET_BASE_local = \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL - 1) / \
                S.GRE(proto=0x6558) / \
                S.Ether(dst=DST_MAC_UNL.addr_str, src=SRC_MAC_UNL.addr_str, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=VLAN_UNL) / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str) / \
                S.TCP(sport=SPORT_UNL, dport=DPORT_UNL)
            EXPECTED_OUTPUT_PACKET_local = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            self.run_and_compare_ecmp_for_nvgre_vxlan_transit(INPUT_PACKET_local, EXPECTED_OUTPUT_PACKET_local, True, True)

        # Transit NVGRE packets with untagged ether underlay
        for packet_num in range(self.NUM_OF_PACKETS):
            DIP_OVL = IPv4Address(self.DIP_BASE_OVL.to_num() + (self.PACKETS_OFFSET * packet_num))
            SPORT_UNL = SPORT_UNL_BASE + packet_num
            DPORT_UNL = DPORT_UNL_BASE + packet_num

            INPUT_PACKET_BASE_local = \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.EXT_MAC.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL) / \
                S.GRE(proto=0x6558) / \
                S.Ether(dst=DST_MAC_UNL.addr_str, src=SRC_MAC_UNL.addr_str) / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str) / \
                S.TCP(sport=SPORT_UNL, dport=DPORT_UNL)
            INPUT_PACKET_local = U.add_payload(INPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            EXPECTED_OUTPUT_PACKET_BASE_local = \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL - 1) / \
                S.GRE(proto=0x6558) / \
                S.Ether(dst=DST_MAC_UNL.addr_str, src=SRC_MAC_UNL.addr_str) / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str) / \
                S.TCP(sport=SPORT_UNL, dport=DPORT_UNL)
            EXPECTED_OUTPUT_PACKET_local = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            self.run_and_compare_ecmp_for_nvgre_vxlan_transit(INPUT_PACKET_local, EXPECTED_OUTPUT_PACKET_local, True, False)

        ip_impl.delete_route(self.topology.vrf, prefix)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_loadbalance_hash_vxlan_transit(self):
        self.topology.create_topology()
        self.topology.topology_created = True

        DST_MAC_UNL = T.mac_addr('aa:bb:cc:aa:bb:cc')
        SRC_MAC_UNL = T.mac_addr('ab:cd:ab:cd:ab:cd')
        VLAN_UNL = 2000
        SIP_UNL = T.ipv4_addr('10.1.1.1')
        DIP_UNL = T.ipv4_addr('10.1.1.2')
        SPORT_UNL_BASE = 4000
        DPORT_UNL_BASE = 2000

        l3_port_impl = T.ip_l3_ac_base(self.topology)
        ip_impl = ip_test_base.ipv4_test_base

        self.create_ecmp_group_for_transit()
        prefix = ip_impl.build_prefix(self.DIP_BASE_OVL, length=16)
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.ecmp_group, PRIVATE_DATA, False)

        # Transit VXLAN packets with tagged ether underlay
        for packet_num in range(self.NUM_OF_PACKETS):
            DIP_OVL = IPv4Address(self.DIP_BASE_OVL.to_num() + (self.PACKETS_OFFSET * packet_num))
            SPORT_UNL = SPORT_UNL_BASE + packet_num
            DPORT_UNL = DPORT_UNL_BASE + packet_num

            INPUT_PACKET_BASE_local = \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.EXT_MAC.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL) / \
                S.UDP(sport=9999, dport=4789, chksum=0) / \
                P.VXLAN(flags='Instance', vni=10000) / \
                S.Ether(dst=DST_MAC_UNL.addr_str, src=SRC_MAC_UNL.addr_str, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=VLAN_UNL) / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str) / \
                S.TCP(sport=SPORT_UNL, dport=DPORT_UNL)
            INPUT_PACKET_local = U.add_payload(INPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            EXPECTED_OUTPUT_PACKET_BASE_local = \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL - 1) / \
                S.UDP(sport=9999, dport=4789, chksum=0) / \
                P.VXLAN(flags='Instance', vni=10000) / \
                S.Ether(dst=DST_MAC_UNL.addr_str, src=SRC_MAC_UNL.addr_str, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=VLAN_UNL) / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str) / \
                S.TCP(sport=SPORT_UNL, dport=DPORT_UNL)
            EXPECTED_OUTPUT_PACKET_local = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            self.run_and_compare_ecmp_for_nvgre_vxlan_transit(INPUT_PACKET_local, EXPECTED_OUTPUT_PACKET_local, False, True)

        # Transit VXLAN packets with untagged ether underlay
        for packet_num in range(self.NUM_OF_PACKETS):
            DIP_OVL = IPv4Address(self.DIP_BASE_OVL.to_num() + (self.PACKETS_OFFSET * packet_num))
            SPORT_UNL = SPORT_UNL_BASE + packet_num
            DPORT_UNL = DPORT_UNL_BASE + packet_num

            INPUT_PACKET_BASE_local = \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.EXT_MAC.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL) / \
                S.UDP(sport=9999, dport=4789, chksum=0) / \
                P.VXLAN(flags='Instance', vni=10000) / \
                S.Ether(dst=DST_MAC_UNL.addr_str, src=SRC_MAC_UNL.addr_str) / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str) / \
                S.TCP(sport=SPORT_UNL, dport=DPORT_UNL)
            INPUT_PACKET_local = U.add_payload(INPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            EXPECTED_OUTPUT_PACKET_BASE_local = \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL - 1) / \
                S.UDP(sport=9999, dport=4789, chksum=0) / \
                P.VXLAN(flags='Instance', vni=10000) / \
                S.Ether(dst=DST_MAC_UNL.addr_str, src=SRC_MAC_UNL.addr_str) / \
                S.IP(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str) / \
                S.TCP(sport=SPORT_UNL, dport=DPORT_UNL)
            EXPECTED_OUTPUT_PACKET_local = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            self.run_and_compare_ecmp_for_nvgre_vxlan_transit(INPUT_PACKET_local, EXPECTED_OUTPUT_PACKET_local, False, False)

        ip_impl.delete_route(self.topology.vrf, prefix)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_loadbalance_hash_ipnip_transit(self):
        self.topology.create_topology()
        self.topology.topology_created = True

        self.SIP_UNL = T.ipv4_addr('192.168.100.98')
        self.DIP_UNL = T.ipv4_addr('192.168.100.99')

        l3_port_impl = T.ip_l3_ac_base(self.topology)
        ip_impl = ip_test_base.ipv4_test_base

        self.create_ecmp_group_for_transit()
        prefix = ip_impl.build_prefix(self.DIP_BASE_OVL, length=16)
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.ecmp_group, PRIVATE_DATA, False)

        # Transit GUE packets with TCP underlay
        for packet_num in range(self.NUM_OF_PACKETS):
            DIP_OVL = IPv4Address(self.DIP_BASE_OVL.to_num() + (self.PACKETS_OFFSET * packet_num))

            INPUT_PACKET_BASE_local = \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.EXT_MAC.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL) / \
                S.IP(src=self.SIP_UNL.addr_str, dst=self.DIP_UNL.addr_str, ttl=self.TTL)
            INPUT_PACKET_local = U.add_payload(INPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            EXPECTED_OUTPUT_PACKET_BASE_local = \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL - 1) / \
                S.IP(src=self.SIP_UNL.addr_str, dst=self.DIP_UNL.addr_str, ttl=self.TTL)
            EXPECTED_OUTPUT_PACKET_local = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            self.run_and_compare_ecmp_for_ipnip_transit(
                INPUT_PACKET_local,
                EXPECTED_OUTPUT_PACKET_local,
                sdk.la_l3_protocol_e_IPV4_UC)

        ip_impl.delete_route(self.topology.vrf, prefix)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_loadbalance_hash_ipnip6_transit(self):
        self.topology.create_topology()
        self.topology.topology_created = True

        SIP_UNL = T.ipv6_addr('1111:0db8:0a0b:12f0:ffff:eeee:abcd:1111')
        DIP_UNL = T.ipv6_addr('2222:0db8:0a0b:12f0:aaaa:ffff:3333:2222')

        l3_port_impl = T.ip_l3_ac_base(self.topology)
        ip_impl = ip_test_base.ipv4_test_base

        self.create_ecmp_group_for_transit()
        prefix = ip_impl.build_prefix(self.DIP_BASE_OVL, length=16)
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.ecmp_group, PRIVATE_DATA, False)

        # Transit GUE packets with TCP underlay
        for packet_num in range(self.NUM_OF_PACKETS):
            DIP_OVL = IPv4Address(self.DIP_BASE_OVL.to_num() + (self.PACKETS_OFFSET * packet_num))

            INPUT_PACKET_BASE_local = \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.EXT_MAC.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL) / \
                S.IPv6(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str)
            INPUT_PACKET_local = U.add_payload(INPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            EXPECTED_OUTPUT_PACKET_BASE_local = \
                S.IP(src=self.SIP_OVL.addr_str, dst=str(DIP_OVL), ttl=self.TTL - 1) / \
                S.IPv6(src=SIP_UNL.addr_str, dst=DIP_UNL.addr_str)
            EXPECTED_OUTPUT_PACKET_local = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE_local, self.PAYLOAD_SIZE)

            self.run_and_compare_ecmp_for_ipnip_transit(
                INPUT_PACKET_local,
                EXPECTED_OUTPUT_PACKET_local,
                sdk.la_l3_protocol_e_IPV6_UC)

        ip_impl.delete_route(self.topology.vrf, prefix)


if __name__ == '__main__':
    unittest.main()
