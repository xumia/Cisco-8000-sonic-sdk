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


import sys
import unittest
from leaba import sdk
import ip_test_base
from scapy.all import *
import sim_utils
import topology as T
import packet_test_utils as U
from sdk_test_case_base import *
import mtu.mtu_test_utils as MTU

load_contrib('mpls')


class mpls_termination_base(sdk_test_case_base):
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    IP_TTL = 0x80
    MPLS_TTL = 0x40
    MPLS_QOS = 0x7
    EXPECTED_IP_DSCP = 0x17
    EXPECTED_IP_TOS = EXPECTED_IP_DSCP << 2
    VPN_LABEL = sdk.la_mpls_label()
    VPN_LABEL.label = 0x30
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    def setUp(self):
        super().setUp()
        self.ip_impl = self.ip_impl_class()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)
        self.add_default_route()

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh, self.PRIVATE_DATA_DEFAULT)

    def _test_get_info(self):
        lsr = self.device.get_lsr()

        decap = lsr.add_vpn_decap(
            self.VPN_LABEL, self.topology.vrf.hld_obj)

        label = decap.get_label()
        self.assertEqual(label.label, self.VPN_LABEL.label)

        vrf = decap.get_vrf()
        self.assertEqual(vrf.this, self.topology.vrf.hld_obj.this)

        lsr.delete_vpn_decap(decap)

    def _test_single_null(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_SINGLE_NULL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_single_null_vpn(self):
        lsr = self.device.get_lsr()

        decap = lsr.add_vpn_decap(
            self.VPN_LABEL, self.topology.vrf2.hld_obj)
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf2, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_SINGLE_NULL_VPN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf2, prefix)
        lsr.delete_vpn_decap(decap)

    def _test_vpn_ip_disabled(self):
        lsr = self.device.get_lsr()

        decap = lsr.add_vpn_decap(
            self.VPN_LABEL, self.topology.vrf2.hld_obj)
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf2, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_VPN_IP_DISABLED, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf2, prefix)
        lsr.delete_vpn_decap(decap)

    def _test_single_null_vpn_with_counter(self):
        lsr = self.device.get_lsr()
        counter = self.device.create_counter(2)
        decap = lsr.add_vpn_decap(
            self.VPN_LABEL, self.topology.vrf2.hld_obj)
        decap.set_counter(counter)
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf2, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_SINGLE_NULL_VPN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        count = decap.get_counter()
        v4_packets, v4_bytes = count.read(sdk.la_mpls_vpn_decap.counter_offset_e_IPV4, True, False)
        v6_packets, v6_bytes = count.read(sdk.la_mpls_vpn_decap.counter_offset_e_IPV6, True, False)
        self.assertEqual((v4_packets + v6_packets), 1)

        self.ip_impl.delete_route(self.topology.vrf2, prefix)
        lsr.delete_vpn_decap(decap)

    def _test_single_null_vpn_uniform(self):
        lsr = self.device.get_lsr()

        decap = lsr.add_vpn_decap(
            self.VPN_LABEL, self.topology.vrf2.hld_obj)
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf2, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_SINGLE_NULL_VPN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_UNIFORM, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf2, prefix)
        lsr.delete_vpn_decap(decap)

        # Restore state
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)

    def _test_ttl_mode_uniform(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_SINGLE_NULL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_UNIFORM, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

        # Restore state
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)

    def _test_two_nulls_outer_v4(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_TWO_NULLS_OUTER_V4, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_two_nulls_outer_v6(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_TWO_NULLS_OUTER_V6, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_two_nulls_vpn(self):
        lsr = self.device.get_lsr()

        decap = lsr.add_vpn_decap(
            self.VPN_LABEL, self.topology.vrf.hld_obj)
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_TWO_NULLS_OUTER_V4_VPN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        lsr.delete_vpn_decap(decap)

    def _test_two_nulls_vpn_uniform(self):
        lsr = self.device.get_lsr()

        decap = lsr.add_vpn_decap(
            self.VPN_LABEL, self.topology.vrf.hld_obj)
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_TWO_NULLS_OUTER_V4_VPN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_UNIFORM, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        lsr.delete_vpn_decap(decap)

        # Restore state
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)

    def _test_two_nulls_outer_v6_mtu(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        MTU.run_mtu_test(self, self.device,
                         self.INPUT_PACKET_TWO_NULLS_OUTER_V6, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                         self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_two_nulls_vpn_uniform_mtu(self):
        lsr = self.device.get_lsr()

        decap = lsr.add_vpn_decap(
            self.VPN_LABEL, self.topology.vrf.hld_obj)
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)

        MTU.run_mtu_test(self, self.device,
                         self.INPUT_PACKET_TWO_NULLS_OUTER_V4_VPN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                         self.EXPECTED_OUTPUT_PACKET_UNIFORM, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        lsr.delete_vpn_decap(decap)

        # Restore state
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)

    def _test_vpn_null(self):
        lsr = self.device.get_lsr()

        decap = lsr.add_vpn_decap(
            self.VPN_LABEL, self.topology.vrf2.hld_obj)
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf2, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_VPN_NULL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf2, prefix)
        lsr.delete_vpn_decap(decap)

    def create_ecmp_group_multipath(self):
        NUM_OF_NH = 10
        NH_GID_BASE = 0x613
        NH_DST_MAC_BASE = T.mac_addr('11:11:11:11:11:00')

        self.nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        for nh_num in range(NUM_OF_NH):
            nh = T.next_hop(
                self,
                self.device,
                NH_GID_BASE + nh_num,
                NH_DST_MAC_BASE.create_offset_mac(nh_num),
                self.l3_port_impl.tx_port)
            self.nh_ecmp.add_member(nh.hld_obj)

    def _test_null_ecmp_multipath_ip(self):
        self.create_ecmp_group_multipath()

        input_packet = self.INPUT_PACKET_SINGLE_NULL_VPN_MULTI
        lb_vec_entry_list = []
        lb_vec = sdk.la_lb_vector_t()

        if self.protocol == sdk.la_l3_protocol_e_IPV4_UC:
            prefix = self.ip_impl.build_prefix(self.DIP, length=16)
            self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.nh_ecmp, self.PRIVATE_DATA, False)

            lb_vec.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
            lb_vec.ipv4.sip = T.ipv4_addr(input_packet[IP].src).to_num()
            lb_vec.ipv4.dip = T.ipv4_addr(input_packet[IP].dst).to_num()
            lb_vec.ipv4.protocol = input_packet[IP].proto
            lb_vec.ipv4.src_port = input_packet[TCP].sport
            lb_vec.ipv4.dest_port = input_packet[TCP].dport
        else:
            prefix = self.ip_impl.build_prefix(self.DIP, length=64)
            self.topology.vrf.hld_obj.add_ipv6_route(prefix, self.nh_ecmp, self.PRIVATE_DATA, False)

            lb_vec.type = sdk.LA_LB_VECTOR_IPV6_TCP_UDP
            lb_vec.ipv6.sip = U.split_bits(T.ipv6_addr(input_packet[IPv6].src).to_num(), 32)
            lb_vec.ipv6.dip = U.split_bits(T.ipv6_addr(input_packet[IPv6].dst).to_num(), 32)
            lb_vec.ipv6.next_header = input_packet[IPv6].nh
            lb_vec.ipv6.flow_label = input_packet[IPv6].fl
            lb_vec.ipv6.src_port = input_packet[TCP].sport
            lb_vec.ipv6.dest_port = input_packet[TCP].dport
        lb_vec_entry_list.append(lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(self.nh_ecmp, lb_vec_entry_list)
        U.check_forwarding_load_balance_chain(self, out_dest_chain, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        expected_mac = out_dest_chain[0].downcast().get_mac().flat
        expected_mac_str = T.mac_addr.mac_num_to_str(expected_mac)

        expected_packet = \
            Ether(dst=expected_mac_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            self.EXPECTED_OUTPUT_PACKET_MULTI

        U.run_and_compare(self, self.device,
                          input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          expected_packet, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
