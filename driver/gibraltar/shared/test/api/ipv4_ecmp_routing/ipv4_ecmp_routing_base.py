#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import unittest
from leaba import sdk
import sim_utils
import ip_test_base
import packet_test_utils as U
import scapy.all as S
import topology as T
from sdk_test_case_base import *
import packet_test_defs as P
import decor

PRIVATE_DATA = 0x1234567890abcdef
PREFIX_OBJ_GID = 0x691
VRF_GID = 0x0400 if not decor.is_gibraltar() else 0x0900


class ipv4_ecmp_routing_base(sdk_test_case_base):
    # create network topology
    #
    #             RX -------> | ----------->  TX
    #                         |
    #                         |                transmit                      nh (over sp)
    #                         |               /                             /
    #  receive--switch--svi--VRF--svi--switch ---spa--transmit        ECMP< --- nh (over spa)
    #                         |               \                             \
    #                         |                transmit                      nh (over sp)
    #                         |

    def setUp(self):
        super().setUp(create_default_topology=False)
        if not any(self.topology.inject_ports):
            self.topology.create_inject_ports()
            self._add_objects_to_keep()

    def create_network_topology(self):
        # MATILDA_SAVE -- need review
        self.s_rx_slice = T.choose_active_slices(self.device, self.s_rx_slice, [0, 5])
        self.s_tx1_slice = T.choose_active_slices(self.device, self.s_tx1_slice, [2, 3])
        self.s_tx2_slice = T.choose_active_slices(self.device, self.s_tx2_slice, [3, 1])
        self.s_tx_spa_slice = T.choose_active_slices(self.device, self.s_tx_spa_slice, [4, 1])
        if self.s_tx2_slice == self.s_tx1_slice:
            self.s_tx2_ifg = T.get_device_ifg(1)

        self.create_l2_stuff()

        self.m_vrf = T.vrf(self, self.device, VRF_GID)

        self.create_svi_ports()
        self.create_l3_destinations()

    def create_l2_stuff(self):
        self.m_rx_switch = T.switch(self, self.device, 0x100)
        self.m_tx_switch = T.switch(self, self.device, 0x200)

        self.m_rx_mac_port = T.mac_port(
            self,
            self.device,
            self.s_rx_slice,
            self.s_rx_ifg,
            self.s_rx_first_serdes,
            self.s_rx_last_serdes)
        self.m_rx_sys_port = T.system_port(self, self.device, 0x11, self.m_rx_mac_port)
        self.m_rx_eth_port = T.sa_ethernet_port(self, self.device, self.m_rx_sys_port)
        self.m_rx_port = T.l2_ac_port(self, self.device, 0x13, self.topology.filter_group_def,
                                      None, self.m_rx_eth_port, None, self.s_vlan1, self.s_vlan2)
        self.m_rx_port.hld_obj.attach_to_switch(self.m_rx_switch.hld_obj)

        self.m_rx_mac_port.activate()

        self.m_tx1_mac_port = T.mac_port(
            self,
            self.device,
            self.s_tx1_slice,
            self.s_tx1_ifg,
            self.s_tx1_first_serdes,
            self.s_tx1_last_serdes)
        self.m_tx1_sys_port = T.system_port(self, self.device, 0x21, self.m_tx1_mac_port)
        self.m_tx1_eth_port = T.sa_ethernet_port(self, self.device, self.m_tx1_sys_port)
        self.m_tx1_port = T.l2_ac_port(
            self,
            self.device,
            0x23,
            self.topology.filter_group_def,
            None,
            self.m_tx1_eth_port,
            None,
            0,
            0)

        self.m_tx1_port.hld_obj.attach_to_switch(self.m_tx_switch.hld_obj)

        self.m_tx1_mac_port.activate()

        self.m_tx_switch.hld_obj.set_mac_entry(
            self.s_nh1_mac.hld_obj,
            self.m_tx1_port.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        self.m_tx2_mac_port = T.mac_port(
            self,
            self.device,
            self.s_tx2_slice,
            self.s_tx2_ifg,
            self.s_tx2_first_serdes,
            self.s_tx2_last_serdes)
        self.m_tx2_sys_port = T.system_port(self, self.device, 0x31, self.m_tx2_mac_port)
        self.m_tx2_eth_port = T.sa_ethernet_port(self, self.device, self.m_tx2_sys_port)
        self.m_tx2_port = T.l2_ac_port(
            self,
            self.device,
            0x33,
            self.topology.filter_group_def,
            None,
            self.m_tx2_eth_port,
            None,
            0,
            0)

        self.m_tx2_port.hld_obj.attach_to_switch(self.m_tx_switch.hld_obj)

        self.m_tx2_mac_port.activate()

        self.m_tx_switch.hld_obj.set_mac_entry(
            self.s_nh2_mac.hld_obj,
            self.m_tx2_port.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        self.m_tx_mac_port = T.mac_port(
            self,
            self.device,
            self.s_tx_spa_slice,
            self.s_tx_spa_ifg,
            self.s_tx_first_serdes,
            self.s_tx_last_serdes)
        self.m_tx_sys_port = T.system_port(self, self.device, 0x41, self.m_tx_mac_port)
        self.spa_port = T.spa_port(self, self.device, 0x42)
        self.spa_port.add(self.m_tx_sys_port)
        self.m_tx_spa_eth_port = T.sa_ethernet_port(self, self.device, self.spa_port)
        self.m_tx_spa_port = T.l2_ac_port(
            self,
            self.device,
            0x43,
            self.topology.filter_group_def,
            None,
            self.m_tx_spa_eth_port,
            None,
            0,
            0)

        self.m_tx_spa_port.hld_obj.attach_to_switch(self.m_tx_switch.hld_obj)

        self.m_tx_mac_port.activate()

        self.m_tx_switch.hld_obj.set_mac_entry(
            self.s_nh_spa_mac.hld_obj,
            self.m_tx_spa_port.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

    def create_svi_ports(self):
        self.m_rx_svi = T.svi_port(self, self.device, 0x110, self.m_rx_switch, self.m_vrf, self.s_rx_svi_mac)
        self.m_rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

        self.m_tx_svi = T.svi_port(self, self.device, 0x210, self.m_tx_switch, self.m_vrf, self.s_tx_svi_mac)
        self.m_tx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

    def create_l3_destinations(self):
        self.m_nh1 = T.next_hop(self, self.device, 0x220, self.s_nh1_mac, self.m_tx_svi)
        self.m_nh2 = T.next_hop(self, self.device, 0x320, self.s_nh2_mac, self.m_tx_svi)
        self.m_nh_spa = T.next_hop(self, self.device, 0x420, self.s_nh_spa_mac, self.m_tx_svi)
        self.m_nh3 = T.next_hop(self, self.device, 0x530, self.s_nh2_mac, self.m_tx_svi)
        self.m_nh4 = T.next_hop(self, self.device, 0x540, self.s_nh2_mac, self.m_tx_svi)
        self.m_nh5 = T.next_hop(self, self.device, 0x550, self.s_nh2_mac, self.m_tx_svi)
        self.m_ecmp1_attached_members = [self.m_nh1, self.m_nh_spa, self.m_nh2]
        self.m_ecmp2_attached_members = [self.m_nh1, self.m_nh_spa, self.m_nh2]
        self.m_ecmp3_attached_members = [self.m_nh1, self.m_nh_spa, self.m_nh2]

        self.m_ecmp1 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(self.m_ecmp1, None)

        for member in self.m_ecmp1_attached_members:
            self.m_ecmp1.add_member(member.hld_obj)

        self.m_ecmp2 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(self.m_ecmp2, None)

        for member in self.m_ecmp2_attached_members:
            self.m_ecmp2.add_member(member.hld_obj)

        self.m_ecmp_rec_attached_members = [self.m_ecmp1, self.m_nh5.hld_obj, self.m_ecmp2]

        self.m_ecmp_rec = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.assertNotEqual(self.m_ecmp_rec, None)

        for member in self.m_ecmp_rec_attached_members:
            self.m_ecmp_rec.add_member(member)

        self.m_ecmp3 = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(self.m_ecmp3, None)

        for member in self.m_ecmp3_attached_members:
            self.m_ecmp3.add_member(member.hld_obj)

        self.m_fec1 = self.device.create_l3_fec(self.m_ecmp1)
        self.assertIsNotNone(self.m_fec1)

    def create_routing_entry(self):
        prefix = sdk.la_ipv4_prefix_t()
        addr = self.s_dip1.hld_obj
        addr.s_addr &= 0xffff0000
        prefix.addr = addr
        prefix.length = 16

        self.m_vrf.hld_obj.add_ipv4_route(prefix, self.m_ecmp1, PRIVATE_DATA, False)

        prefix = sdk.la_ipv4_prefix_t()
        addr = self.s_dip3.hld_obj
        addr.s_addr &= 0xffff0000
        prefix.addr = addr
        prefix.length = 16

        self.m_vrf.hld_obj.add_ipv4_route(prefix, self.m_ecmp2, PRIVATE_DATA, False)

        prefix = sdk.la_ipv4_prefix_t()
        addr = self.s_dip_rec.hld_obj
        addr.s_addr &= 0xffff0000
        prefix.addr = addr
        prefix.length = 16

        self.m_vrf.hld_obj.add_ipv4_route(prefix, self.m_ecmp_rec, PRIVATE_DATA, False)

        prefix = sdk.la_ipv4_prefix_t()
        addr = self.s_dip_rec_via_fec.hld_obj
        addr.s_addr &= 0xffff0000
        prefix.addr = addr
        prefix.length = 16

        self.m_vrf.hld_obj.add_ipv4_route(prefix, self.m_fec1, PRIVATE_DATA, False)

    # Static member
    s_rx_first_serdes = T.get_device_first_serdes(0)
    s_rx_last_serdes = T.get_device_last_serdes(1)

    s_tx_first_serdes = T.get_device_tx_first_serdes(0)
    s_tx_last_serdes = T.get_device_tx_last_serdes(1)

    s_tx1_first_serdes = T.get_device_tx1_first_serdes(0)
    s_tx1_last_serdes = T.get_device_tx1_last_serdes(1)

    s_tx2_first_serdes = T.get_device_tx2_first_serdes(0)
    s_tx2_last_serdes = T.get_device_tx2_last_serdes(1)

    s_rx_slice = T.get_device_slice(5)
    s_tx1_slice = T.get_device_slice(2)
    s_tx2_slice = T.get_device_slice(3)
    s_tx_spa_slice = T.get_device_slice(4)
    s_rx_ifg = 0
    s_tx1_ifg = T.get_device_ifg(1)
    s_tx2_ifg = 0
    s_tx_spa_ifg = T.get_device_ifg(1)
    s_vlan1 = 0x000a
    s_vlan2 = 0
    s_ttl = 176

    s_input_mac = T.mac_addr('be:ef:5d:35:7a:35')
    s_rx_svi_mac = T.mac_addr('84:20:75:3e:8c:05')
    s_tx_svi_mac = T.mac_addr('6c:68:14:ab:b8:27')
    s_nh1_mac = T.mac_addr('a2:af:77:14:24:7c')
    s_nh2_mac = T.mac_addr('48:ca:d1:3e:f6:a3')
    s_nh_spa_mac = T.mac_addr('1c:f5:7d:e9:61:eb')
    s_sip = T.ipv4_addr('12.10.12.10')
    s_dip1 = T.ipv4_addr('16.04.222.222')
    s_dip2 = T.ipv4_addr('16.04.111.111')
    s_dip_spa = T.ipv4_addr('16.04.04.149')
    s_dip_after_delete1 = T.ipv4_addr('16.04.111.222')
    s_dip3 = T.ipv4_addr('17.04.04.247')
    s_dip_rec = T.ipv4_addr('19.04.04.246')
    s_dip_rec_via_fec = T.ipv4_addr('20.04.111.246')

    s_nh_eth_headers = {
        s_nh1_mac.hld_obj.flat: S.Ether(dst=s_nh1_mac.addr_str, src=s_tx_svi_mac.addr_str),
        s_nh2_mac.hld_obj.flat: S.Ether(dst=s_nh2_mac.addr_str, src=s_tx_svi_mac.addr_str),
        s_nh_spa_mac.hld_obj.flat: S.Ether(dst=s_nh_spa_mac.addr_str, src=s_tx_svi_mac.addr_str),
    }

    @staticmethod
    def get_output_packet(base_packet, nh):
        # add the eth header to the packet with the details of the given next hop
        eth_header = ipv4_ecmp_routing_base.s_nh_eth_headers[nh.get_mac().flat]
        return eth_header / base_packet

    def run_and_compare_ecmp(self, ecmp, input_packet, input_slice, input_ifg, input_serdes, base_out_packet):

        dip = T.ipv4_addr(input_packet[IP].dst)
        sip = T.ipv4_addr(input_packet[IP].src)

        lb_vec = sdk.la_lb_vector_t()
        lb_vec.type = sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP  # all ipv4 ecmp tests use non-tcp-udp type
        lb_vec.ipv4.sip = sip.hld_obj.s_addr
        lb_vec.ipv4.dip = dip.hld_obj.s_addr
        lb_vec.ipv4.protocol = 0

        lb_vec_entry_list = []
        lb_vec_entry_list.append(lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(ecmp, lb_vec_entry_list)
        # For Debug purpose:
        # U.display_forwarding_load_balance_chain(ecmp, out_dest_chain)
        self.assertEqual(out_dest_chain[-1].type(), sdk.la_object.object_type_e_SYSTEM_PORT)
        # find the NH in the chain
        nh_obj = None
        for e in reversed(out_dest_chain):
            if e.type() == sdk.la_object.object_type_e_NEXT_HOP:
                nh_obj = e
                break
        assert nh_obj is not None, 'No next hop in chain'

        out_nh = nh_obj.downcast()
        out_dsp = out_dest_chain[-1].downcast()
        # build the output packet with the NH
        out_packet = ipv4_ecmp_routing_base.get_output_packet(base_out_packet, out_nh)
        U.run_and_compare(self, self.device,
                          input_packet, input_slice, input_ifg, input_serdes,
                          out_packet, out_dsp.get_slice(), out_dsp.get_ifg(), out_dsp.get_base_serdes())

    def create_ecmp_group_for_transit(self):
        NUM_OF_NH = 5
        NH_GID_BASE = 0x613
        NH_DST_MAC_BASE = T.mac_addr('11:11:11:11:11:00')

        l3_port_impl = T.ip_l3_ac_base(self.topology)

        self.ecmp_group = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        for nh_num in range(NUM_OF_NH):
            nh = T.next_hop(
                self,
                self.device,
                NH_GID_BASE + nh_num,
                NH_DST_MAC_BASE.create_offset_mac(nh_num),
                l3_port_impl.tx_port)
            self.ecmp_group.add_member(nh.hld_obj)

    def run_and_compare_ecmp_for_gre_transit(self, input_packet, output_packet_base):
        l3_port_impl = T.ip_l3_ac_base(self.topology)

        lb_vec_entry_list = []
        if not decor.is_akpg():
            hw_lb_vec = sdk.la_lb_vector_t()
            hw_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP
            hw_lb_vec.ipv4.sip = T.ipv4_addr(input_packet[IP].src).to_num()
            hw_lb_vec.ipv4.dip = T.ipv4_addr(input_packet[IP].dst).to_num()
            hw_lb_vec.ipv4.protocol = input_packet[IP].proto
            lb_vec_entry_list.append(hw_lb_vec)

        soft_lb_vec = sdk.la_lb_vector_t()
        if input_packet[GRE].proto == U.Ethertype.IPv4.value:
            soft_lb_vec.ipv4.sip = T.ipv4_addr(input_packet[GRE][IP].src).to_num()
            soft_lb_vec.ipv4.dip = T.ipv4_addr(input_packet[GRE][IP].dst).to_num()
            soft_lb_vec.ipv4.protocol = input_packet[GRE][IP].proto
            if input_packet[GRE][IP].proto == 6:
                if decor.is_akpg():
                    soft_lb_vec.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV4_L4
                else:
                    soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
                soft_lb_vec.ipv4.src_port = input_packet[TCP].sport
                soft_lb_vec.ipv4.dest_port = input_packet[TCP].dport
            else:
                if decor.is_akpg():
                    soft_lb_vec.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV4_L4
                else:
                    soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP
        elif input_packet[GRE].proto == U.Ethertype.IPv6.value:
            soft_lb_vec.ipv6.sip = U.split_bits(T.ipv6_addr(input_packet[IPv6].src).to_num(), 32)
            soft_lb_vec.ipv6.dip = U.split_bits(T.ipv6_addr(input_packet[IPv6].dst).to_num(), 32)
            soft_lb_vec.ipv6.next_header = input_packet[IPv6].nh
            soft_lb_vec.ipv6.flow_label = input_packet[IPv6].fl
            if input_packet[IPv6].nh == 6:
                if decor.is_akpg():
                    soft_lb_vec.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV6_L4
                else:
                    soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV6_TCP_UDP
                soft_lb_vec.ipv6.src_port = input_packet[TCP].sport
                soft_lb_vec.ipv6.dest_port = input_packet[TCP].dport
            else:
                if decor.is_akpg():
                    soft_lb_vec.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV6_L4
                else:
                    soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV6_NON_TCP_UDP
        else:
            soft_lb_vec.ipv4.sip = T.ipv4_addr(input_packet[GRE][IP].src).to_num()
            soft_lb_vec.ipv4.dip = T.ipv4_addr(input_packet[GRE][IP].dst).to_num()
            soft_lb_vec.ipv4.protocol = input_packet[GRE][IP].proto
            if decor.is_akpg():
                soft_lb_vec.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV4_L4
            else:
                soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
            soft_lb_vec.ipv4.src_port = input_packet[TCP].sport
            soft_lb_vec.ipv4.dest_port = input_packet[TCP].dport

        lb_vec_entry_list.append(soft_lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(self.ecmp_group, lb_vec_entry_list)
        U.check_forwarding_load_balance_chain(self, out_dest_chain, T.TX_SLICE_REG, T.TX_IFG_REG, l3_port_impl.serdes_reg)

        expected_mac = out_dest_chain[0].downcast().get_mac().flat
        expected_mac_str = T.mac_addr.mac_num_to_str(expected_mac)

        expected_packet = \
            S.Ether(dst=expected_mac_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            output_packet_base

        U.run_and_compare(self, self.device,
                          input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          expected_packet, T.TX_SLICE_REG, T.TX_IFG_REG, l3_port_impl.serdes_reg)

    def run_and_compare_ecmp_for_gtp_transit(self, input_packet, output_packet_base, gtp_teid):
        l3_port_impl = T.ip_l3_ac_base(self.topology)

        lb_vec_entry_list = []
        if not decor.is_akpg():
            hw_lb_vec = sdk.la_lb_vector_t()
            hw_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
            hw_lb_vec.ipv4.sip = T.ipv4_addr(input_packet[IP].src).to_num()
            hw_lb_vec.ipv4.dip = T.ipv4_addr(input_packet[IP].dst).to_num()
            hw_lb_vec.ipv4.protocol = input_packet[IP].proto
            hw_lb_vec.ipv4.src_port = input_packet[UDP].sport
            hw_lb_vec.ipv4.dest_port = input_packet[UDP].dport
            lb_vec_entry_list.append(hw_lb_vec)

        soft_lb_vec = sdk.la_lb_vector_t()
        soft_lb_vec.type = sdk.LA_LB_VECTOR_GTP
        soft_lb_vec.gtp_tunnel_id = gtp_teid
        lb_vec_entry_list.append(soft_lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(self.ecmp_group, lb_vec_entry_list)
        U.check_forwarding_load_balance_chain(self, out_dest_chain, T.TX_SLICE_REG, T.TX_IFG_REG, l3_port_impl.serdes_reg)

        expected_mac = out_dest_chain[0].downcast().get_mac().flat
        expected_mac_str = T.mac_addr.mac_num_to_str(expected_mac)

        expected_packet = \
            S.Ether(dst=expected_mac_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            output_packet_base

        U.run_and_compare(self, self.device,
                          input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          expected_packet, T.TX_SLICE_REG, T.TX_IFG_REG, l3_port_impl.serdes_reg)

    def run_and_compare_ecmp_for_gue_transit(self, input_packet, output_packet_base, proto):
        l3_port_impl = T.ip_l3_ac_base(self.topology)

        lb_vec_entry_list = []
        if not decor.is_akpg():
            hw_lb_vec = sdk.la_lb_vector_t()
            hw_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
            hw_lb_vec.ipv4.sip = T.ipv4_addr(input_packet[IP].src).to_num()
            hw_lb_vec.ipv4.dip = T.ipv4_addr(input_packet[IP].dst).to_num()
            hw_lb_vec.ipv4.protocol = input_packet[IP].proto
            hw_lb_vec.ipv4.src_port = input_packet[UDP].sport
            hw_lb_vec.ipv4.dest_port = input_packet[UDP].dport
            lb_vec_entry_list.append(hw_lb_vec)

        soft_lb_vec = sdk.la_lb_vector_t()
        if proto == sdk.la_l3_protocol_e_IPV4_UC:
            if decor.is_akpg():
                soft_lb_vec.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV4_L4
            else:
                soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
            soft_lb_vec.ipv4.sip = T.ipv4_addr(input_packet[UDP][IP].src).to_num()
            soft_lb_vec.ipv4.dip = T.ipv4_addr(input_packet[UDP][IP].dst).to_num()
            soft_lb_vec.ipv4.protocol = input_packet[UDP][IP].proto
            soft_lb_vec.ipv4.src_port = input_packet[TCP].sport
            soft_lb_vec.ipv4.dest_port = input_packet[TCP].dport
            lb_vec_entry_list.append(soft_lb_vec)
        elif proto == sdk.la_l3_protocol_e_IPV6_UC:
            if decor.is_akpg():
                soft_lb_vec.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV6_L4
            else:
                soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV6_NON_TCP_UDP
            soft_lb_vec.ipv6.sip = U.split_bits(T.ipv6_addr(input_packet[IPv6].src).to_num(), 32)
            soft_lb_vec.ipv6.dip = U.split_bits(T.ipv6_addr(input_packet[IPv6].dst).to_num(), 32)
            soft_lb_vec.ipv6.next_header = input_packet[IPv6].nh
            soft_lb_vec.ipv6.flow_label = input_packet[IPv6].fl
            lb_vec_entry_list.append(soft_lb_vec)
        elif proto == sdk.la_l3_protocol_e_MPLS:
            if decor.is_akpg():
                soft_lb_vec.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV4_L4
                soft_lb_vec.ipv4.sip = T.ipv4_addr(input_packet[UDP][IP].src).to_num()
                soft_lb_vec.ipv4.dip = T.ipv4_addr(input_packet[UDP][IP].dst).to_num()
                soft_lb_vec.ipv4.protocol = input_packet[UDP][IP].proto
                lb_vec_entry_list.append(soft_lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(self.ecmp_group, lb_vec_entry_list)
        U.check_forwarding_load_balance_chain(self, out_dest_chain, T.TX_SLICE_REG, T.TX_IFG_REG, l3_port_impl.serdes_reg)

        expected_mac = out_dest_chain[0].downcast().get_mac().flat
        expected_mac_str = T.mac_addr.mac_num_to_str(expected_mac)

        expected_packet = \
            S.Ether(dst=expected_mac_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            output_packet_base

        U.run_and_compare(self, self.device,
                          input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          expected_packet, T.TX_SLICE_REG, T.TX_IFG_REG, l3_port_impl.serdes_reg)

    def run_and_compare_ecmp_for_nvgre_vxlan_transit(self, input_packet, output_packet_base, is_nvgre, tagged):
        l3_port_impl = T.ip_l3_ac_base(self.topology)

        lb_vec_entry_list = []
        if not decor.is_akpg():
            hw_lb_vec = sdk.la_lb_vector_t()
            hw_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP
            hw_lb_vec.ipv4.sip = T.ipv4_addr(input_packet[IP].src).to_num()
            hw_lb_vec.ipv4.dip = T.ipv4_addr(input_packet[IP].dst).to_num()
            hw_lb_vec.ipv4.protocol = input_packet[IP].proto
            if not is_nvgre:
                hw_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
                hw_lb_vec.ipv4.src_port = input_packet[UDP].sport
                hw_lb_vec.ipv4.dest_port = input_packet[UDP].dport
            lb_vec_entry_list.append(hw_lb_vec)

        soft_lb_vec = sdk.la_lb_vector_t()
        if is_nvgre:
            if decor.is_akpg():
                soft_lb_vec.ipv4.sip = T.ipv4_addr('10.1.1.1').to_num()
                soft_lb_vec.ipv4.dip = T.ipv4_addr('10.1.1.2').to_num()
                soft_lb_vec.ipv4.protocol = 0x06
                soft_lb_vec.ipv4.src_port = input_packet[TCP].sport
                soft_lb_vec.ipv4.dest_port = input_packet[TCP].dport
                soft_lb_vec.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV4_L4
            else:
                dst_mac = T.mac_addr(input_packet[GRE][Ether].dst)
                src_mac = T.mac_addr(input_packet[GRE][Ether].src)
                soft_lb_vec.ethernet.da = dst_mac.hld_obj
                soft_lb_vec.ethernet.sa = src_mac.hld_obj
                soft_lb_vec.ethernet.ether_type = input_packet[GRE][Ether].type
                soft_lb_vec.type = sdk.LA_LB_VECTOR_ETHERNET_NON_VLAN_TAG
                if tagged:
                    soft_lb_vec.ethernet.vlan_id = input_packet[GRE][Ether][Dot1Q].vlan
                    soft_lb_vec.type = sdk.LA_LB_VECTOR_ETHERNET_VLAN_TAG
        else:
            if decor.is_akpg():
                soft_lb_vec.ipv4.sip = T.ipv4_addr('10.1.1.1').to_num()
                soft_lb_vec.ipv4.dip = T.ipv4_addr('10.1.1.2').to_num()
                soft_lb_vec.ipv4.protocol = 0x06
                soft_lb_vec.ipv4.src_port = input_packet[TCP].sport
                soft_lb_vec.ipv4.dest_port = input_packet[TCP].dport
                soft_lb_vec.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV4_L4
            else:
                dst_mac = T.mac_addr(input_packet[P.VXLAN][Ether].dst)
                src_mac = T.mac_addr(input_packet[P.VXLAN][Ether].src)
                soft_lb_vec.ethernet.da = dst_mac.hld_obj
                soft_lb_vec.ethernet.sa = src_mac.hld_obj
                soft_lb_vec.ethernet.ether_type = input_packet[P.VXLAN][Ether].type
                soft_lb_vec.type = sdk.LA_LB_VECTOR_ETHERNET_NON_VLAN_TAG
                if tagged:
                    soft_lb_vec.ethernet.vlan_id = input_packet[P.VXLAN][Ether][Dot1Q].vlan
                    soft_lb_vec.type = sdk.LA_LB_VECTOR_ETHERNET_VLAN_TAG
        lb_vec_entry_list.append(soft_lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(self.ecmp_group, lb_vec_entry_list)
        U.check_forwarding_load_balance_chain(self, out_dest_chain, T.TX_SLICE_REG, T.TX_IFG_REG, l3_port_impl.serdes_reg)

        expected_mac = out_dest_chain[0].downcast().get_mac().flat
        expected_mac_str = T.mac_addr.mac_num_to_str(expected_mac)

        expected_packet = \
            S.Ether(dst=expected_mac_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            output_packet_base

        U.run_and_compare(self, self.device,
                          input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          expected_packet, T.TX_SLICE_REG, T.TX_IFG_REG, l3_port_impl.serdes_reg)

    def run_and_compare_ecmp_for_ipnip_transit(self, input_packet, output_packet_base, proto):
        l3_port_impl = T.ip_l3_ac_base(self.topology)

        lb_vec_entry_list = []
        if not decor.is_akpg():
            hw_lb_vec = sdk.la_lb_vector_t()
            hw_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP
            hw_lb_vec.ipv4.sip = T.ipv4_addr(input_packet[IP].src).to_num()
            hw_lb_vec.ipv4.dip = T.ipv4_addr(input_packet[IP].dst).to_num()
            hw_lb_vec.ipv4.protocol = input_packet[IP].proto
            lb_vec_entry_list.append(hw_lb_vec)

        soft_lb_vec = sdk.la_lb_vector_t()
        if proto == sdk.la_l3_protocol_e_IPV4_UC:
            if decor.is_akpg():
                soft_lb_vec.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV4_L4
            else:
                soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP
            soft_lb_vec.ipv4.sip = self.SIP_UNL.to_num()
            soft_lb_vec.ipv4.dip = self.DIP_UNL.to_num()
            soft_lb_vec.ipv4.protocol = 0
        else:
            if decor.is_akpg():
                soft_lb_vec.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV6_L4
            else:
                soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV6_NON_TCP_UDP
            soft_lb_vec.ipv6.sip = U.split_bits(T.ipv6_addr(input_packet[IPv6].src).to_num(), 32)
            soft_lb_vec.ipv6.dip = U.split_bits(T.ipv6_addr(input_packet[IPv6].dst).to_num(), 32)
            soft_lb_vec.ipv6.next_header = input_packet[IPv6].nh
            soft_lb_vec.ipv6.flow_label = input_packet[IPv6].fl
        lb_vec_entry_list.append(soft_lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(self.ecmp_group, lb_vec_entry_list)
        U.check_forwarding_load_balance_chain(self, out_dest_chain, T.TX_SLICE_REG, T.TX_IFG_REG, l3_port_impl.serdes_reg)

        expected_mac = out_dest_chain[0].downcast().get_mac().flat
        expected_mac_str = T.mac_addr.mac_num_to_str(expected_mac)

        expected_packet = \
            S.Ether(dst=expected_mac_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            output_packet_base

        U.run_and_compare(self, self.device,
                          input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          expected_packet, T.TX_SLICE_REG, T.TX_IFG_REG, l3_port_impl.serdes_reg)

    INPUT1_PACKET_base = \
        S.Ether(dst=s_rx_svi_mac.addr_str, src=s_input_mac.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=s_vlan1) / \
        S.IP(src=s_sip.addr_str, dst=s_dip1.addr_str, ttl=s_ttl)

    INPUT2_PACKET_base = \
        S.Ether(dst=s_rx_svi_mac.addr_str, src=s_input_mac.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=s_vlan1) / \
        S.IP(src=s_sip.addr_str, dst=s_dip2.addr_str, ttl=s_ttl)

    INPUT_SPA_PACKET_base = \
        S.Ether(dst=s_rx_svi_mac.addr_str, src=s_input_mac.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=s_vlan1) / \
        S.IP(src=s_sip.addr_str, dst=s_dip_spa.addr_str, ttl=s_ttl)

    INPUT_DELETE_NH1_PACKET_base = \
        S.Ether(dst=s_rx_svi_mac.addr_str, src=s_input_mac.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=s_vlan1) / \
        S.IP(src=s_sip.addr_str, dst=s_dip_after_delete1.addr_str, ttl=s_ttl)

    INPUT_REC_PACKET_base = \
        S.Ether(dst=s_rx_svi_mac.addr_str, src=s_input_mac.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=s_vlan1) / \
        S.IP(src=s_sip.addr_str, dst=s_dip_rec.addr_str, ttl=s_ttl)

    INPUT_REC_VIA_FEC_PACKET_base = \
        S.Ether(dst=s_rx_svi_mac.addr_str, src=s_input_mac.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=s_vlan1) / \
        S.IP(src=s_sip.addr_str, dst=s_dip_rec_via_fec.addr_str, ttl=s_ttl)

    # Ethernet header is prepended based on expected ECMP LB result
    OUTPUT1_PACKET_base = \
        S.IP(src=s_sip.addr_str, dst=s_dip1.addr_str, ttl=s_ttl - 1)

    # Ethernet header is prepended based on expected ECMP LB result
    OUTPUT2_PACKET_base = \
        S.IP(src=s_sip.addr_str, dst=s_dip2.addr_str, ttl=s_ttl - 1)

    OUTPUT3_PACKET_base = \
        S.Ether(dst=s_nh2_mac.addr_str, src=s_tx_svi_mac.addr_str) / \
        S.IP(src=s_sip.addr_str, dst=s_dip2.addr_str, ttl=s_ttl - 1)

    OUTPUT4_PACKET_base = \
        S.Ether(dst=s_nh2_mac.addr_str, src=s_tx_svi_mac.addr_str) / \
        S.IP(src=s_sip.addr_str, dst=s_dip1.addr_str, ttl=s_ttl - 1)

    # Ethernet header is prepended based on expected ECMP LB result
    OUTPUT_SPA_PACKET_base = \
        S.IP(src=s_sip.addr_str, dst=s_dip_spa.addr_str, ttl=s_ttl - 1)

    OUTPUT_DELETE_NH1_PACKET_base = \
        S.Ether(dst=s_nh_spa_mac.addr_str, src=s_tx_svi_mac.addr_str) / \
        S.IP(src=s_sip.addr_str, dst=s_dip_after_delete1.addr_str, ttl=s_ttl - 1)

    # Ethernet header is prepended based on expected ECMP LB result
    OUTPUT_REC_PACKET_base = \
        S.IP(src=s_sip.addr_str, dst=s_dip_rec.addr_str, ttl=s_ttl - 1)

    # Ethernet header is prepended based on expected ECMP LB result
    OUTPUT_REC1_PACKET_base = \
        S.IP(src=s_sip.addr_str, dst=s_dip_rec.addr_str, ttl=s_ttl - 1)

    # Ethernet header is prepended based on expected ECMP LB result
    OUTPUT_REC2_PACKET_base = \
        S.IP(src=s_sip.addr_str, dst=s_dip_rec.addr_str, ttl=s_ttl - 1)

    # Ethernet header is prepended based on expected ECMP LB result
    OUTPUT_REC3_PACKET_base = \
        S.IP(src=s_sip.addr_str, dst=s_dip_rec.addr_str, ttl=s_ttl - 1)

    # Ethernet header is prepended based on expected ECMP LB result
    OUTPUT_REC_VIA_FEC_PACKET_base = \
        S.IP(src=s_sip.addr_str, dst=s_dip_rec_via_fec.addr_str, ttl=s_ttl - 1)

    PAYLOAD_SIZE = 40
    INPUT1_PACKET = U.add_payload(INPUT1_PACKET_base, PAYLOAD_SIZE)
    INPUT2_PACKET = U.add_payload(INPUT2_PACKET_base, PAYLOAD_SIZE)
    INPUT_SPA_PACKET = U.add_payload(INPUT_SPA_PACKET_base, PAYLOAD_SIZE)
    INPUT_DELETE_NH1_PACKET = U.add_payload(INPUT_DELETE_NH1_PACKET_base, PAYLOAD_SIZE)
    INPUT_REC_PACKET = U.add_payload(INPUT_REC_PACKET_base, PAYLOAD_SIZE)
    INPUT_REC_VIA_FEC_PACKET = U.add_payload(INPUT_REC_VIA_FEC_PACKET_base, PAYLOAD_SIZE)
    OUTPUT1_PACKET = U.add_payload(OUTPUT1_PACKET_base, PAYLOAD_SIZE)
    OUTPUT2_PACKET = U.add_payload(OUTPUT2_PACKET_base, PAYLOAD_SIZE)
    OUTPUT3_PACKET = U.add_payload(OUTPUT3_PACKET_base, PAYLOAD_SIZE)
    OUTPUT4_PACKET = U.add_payload(OUTPUT4_PACKET_base, PAYLOAD_SIZE)
    OUTPUT_SPA_PACKET = U.add_payload(OUTPUT_SPA_PACKET_base, PAYLOAD_SIZE)
    OUTPUT_DELETE_NH1_PACKET = U.add_payload(OUTPUT_DELETE_NH1_PACKET_base, PAYLOAD_SIZE)
    OUTPUT_REC_PACKET = U.add_payload(OUTPUT_REC_PACKET_base, PAYLOAD_SIZE)
    OUTPUT_REC1_PACKET = U.add_payload(OUTPUT_REC1_PACKET_base, PAYLOAD_SIZE)
    OUTPUT_REC2_PACKET = U.add_payload(OUTPUT_REC2_PACKET_base, PAYLOAD_SIZE)
    OUTPUT_REC3_PACKET = U.add_payload(OUTPUT_REC3_PACKET_base, PAYLOAD_SIZE)
    OUTPUT_REC_VIA_FEC_PACKET = U.add_payload(OUTPUT_REC_VIA_FEC_PACKET_base, PAYLOAD_SIZE)

    NUM_OF_PACKETS = 100
    PACKETS_OFFSET = 128
    EXT_MAC = T.mac_addr('be:be:be:be:be:be')
    TTL = 128
    SIP_OVL = T.ipv4_addr('155.24.162.37')
    DIP_BASE_OVL = T.ipv4_addr('111.111.111.111')
