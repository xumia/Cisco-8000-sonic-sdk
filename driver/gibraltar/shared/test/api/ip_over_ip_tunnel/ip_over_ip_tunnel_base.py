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
import packet_test_utils as U
import scapy.all as S
import sim_utils
import topology as T
from sdk_test_case_base import *
import ip_test_base
from copy import deepcopy
from packet_test_utils import *
import mtu.mtu_test_utils as MTU


class ip_over_ip_tunnel_base(sdk_test_case_base):
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    TUNNEL_TTL = 255
    TTL = 128
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    def setUp(self):
        super().setUp()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)
        self.create_ip_over_ip_tunnel_ports()

    def create_ip_over_ip_tunnel_ports(self):
        # Overlay Prefix in 'vrf'
        self.overlay_prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(
            self.topology.vrf,
            self.overlay_prefix,
            self.l3_port_impl.reg_fec,
            ip_over_ip_tunnel_base.PRIVATE_DATA)
        # Overlay Prefix in 'vrf2'
        self.ip_impl.add_route(
            self.topology.vrf2,
            self.overlay_prefix,
            self.l3_port_impl.reg_fec,
            ip_over_ip_tunnel_base.PRIVATE_DATA)

        # VRF, Underlay Prefix 1
        self.tunnel_dest1 = self.ip_impl.build_prefix(self.LOCAL_IP1, length=16)

        self.ip_over_ip_tunnel_port = T.ip_over_ip_tunnel_port(self, self.device,
                                                               self.TUNNEL_PORT_GID1,
                                                               self.topology.vrf,
                                                               self.tunnel_dest1,
                                                               self.REMOTE_IP,
                                                               self.topology.vrf)

        self.ingress_counter = self.device.create_counter(1)
        self.ip_over_ip_tunnel_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.ingress_counter)
        self.ip_over_ip_tunnel_port.hld_obj.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)

        # VRF, Underlay Prefix 2
        self.tunnel_dest2 = self.ip_impl.build_prefix(self.LOCAL_IP2, length=16)

        self.ip_over_ip_any_src_tunnel_port = T.ip_over_ip_tunnel_port(self, self.device,
                                                                       self.TUNNEL_PORT_GID2,
                                                                       self.topology.vrf,
                                                                       self.tunnel_dest2,
                                                                       self.ANY_IP,
                                                                       self.topology.vrf)

        self.ingress_counter_any_src = self.device.create_counter(1)
        self.ip_over_ip_any_src_tunnel_port.hld_obj.set_ingress_counter(
            sdk.la_counter_set.type_e_PORT, self.ingress_counter_any_src)
        self.ip_over_ip_any_src_tunnel_port.hld_obj.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)

    def destroy_ip_over_ip_tunnel_ports(self):

        self.ip_over_ip_any_src_tunnel_port.destroy()
        self.ip_over_ip_tunnel_port.destroy()
        self.ip_impl.delete_route(self.topology.vrf2, self.overlay_prefix)
        self.ip_impl.delete_route(self.topology.vrf, self.overlay_prefix)

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh, ip_over_ip_tunnel_base.PRIVATE_DATA_DEFAULT)
        self.has_default_route = True

    def destroy_default_route(self):
        if self.has_default_route:
            prefix = self.ip_impl.get_default_prefix()
            self.ip_impl.delete_route(self.topology.vrf, prefix)
            self.has_default_route = False

    def create_ip_over_ip_tunnel_port_over_ecmp(self):
        NUM_OF_NH = 10
        NH_GID_BASE = 0x613
        NH_DST_MAC_BASE = T.mac_addr('11:11:11:11:11:00')

        self.ecmp_group = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        for nh_num in range(NUM_OF_NH):
            nh = T.next_hop(
                self,
                self.device,
                NH_GID_BASE + nh_num,
                NH_DST_MAC_BASE.create_offset_mac(nh_num),
                self.l3_port_impl.tx_port)
            self.ecmp_group.add_member(nh.hld_obj)

        # Overlay Prefix in 'vrf'
        self.overlay_prefix_ecmp = self.ip_impl.build_prefix(self.DIP1, length=16)
        self.topology.vrf.hld_obj.add_ipv4_route(self.overlay_prefix_ecmp,
                                                 self.ecmp_group,
                                                 ip_over_ip_tunnel_base.PRIVATE_DATA, False)

        # VRF, Underlay Prefix
        tunnel_dest = self.ip_impl.build_prefix(self.LOCAL_IP3, length=16)

        self.ip_over_ip_tunnel_port_ecmp = T.ip_over_ip_tunnel_port(self, self.device,
                                                                    self.TUNNEL_PORT_GID5,
                                                                    self.topology.vrf,
                                                                    tunnel_dest,
                                                                    self.REMOTE_IP,
                                                                    self.topology.vrf)

        self.ip_over_ip_tunnel_port_ecmp.hld_obj.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)

    def destroy_ip_over_ip_tunnel_port_over_ecmp(self):
        self.ip_over_ip_tunnel_port_ecmp.destroy()
        self.topology.vrf.hld_obj.delete_ipv4_route(self.overlay_prefix_ecmp)
        self.device.destroy(self.ecmp_group)

    def _test_ip_over_ip_tunnel_decap(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET, T.RX_SLICE)
        self.assertTrue(byte_count, expected_bytes)

        self.device.set_decap_ttl_decrement_enabled(sdk.la_ip_tunnel_type_e_IP_IN_IP, False)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_NO_TTL_DECR, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.device.set_decap_ttl_decrement_enabled(sdk.la_ip_tunnel_type_e_IP_IN_IP, True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.destroy_ip_over_ip_tunnel_ports()

    def _test_ip_over_ip_tunnel_decap_mtu(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        MTU.run_mtu_test(self, self.device,
                         self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                         self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                         T.TX_IFG_EXT, self.l3_port_impl.serdes_reg)

        self.device.set_decap_ttl_decrement_enabled(sdk.la_ip_tunnel_type_e_IP_IN_IP, False)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_NO_TTL_DECR, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.device.set_decap_ttl_decrement_enabled(sdk.la_ip_tunnel_type_e_IP_IN_IP, True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.destroy_ip_over_ip_tunnel_ports()

    def _test_ip_over_ip_any_src_tunnel_decap(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        U.run_and_compare(self, self.device,
                          self.INPUT_ANY_IP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.ingress_counter_any_src.read(0, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_ANY_IP_PACKET, T.RX_SLICE)
        self.assertTrue(byte_count, expected_bytes)

        self.device.set_decap_ttl_decrement_enabled(sdk.la_ip_tunnel_type_e_IP_IN_IP, False)
        U.run_and_compare(self, self.device,
                          self.INPUT_ANY_IP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_NO_TTL_DECR, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.device.set_decap_ttl_decrement_enabled(sdk.la_ip_tunnel_type_e_IP_IN_IP, True)
        U.run_and_compare(self, self.device,
                          self.INPUT_ANY_IP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.destroy_ip_over_ip_tunnel_ports()

    def _test_ip_over_ip_tunnel_update_overlay_vrf(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        self.ip_over_ip_tunnel_port.hld_obj.set_overlay_vrf(self.topology.vrf2.hld_obj)
        vrf = self.ip_over_ip_tunnel_port.hld_obj.get_overlay_vrf()
        self.assertEqual(vrf.this, self.topology.vrf2.hld_obj.this)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET, T.RX_SLICE)
        self.assertTrue(byte_count, expected_bytes)

        self.destroy_ip_over_ip_tunnel_ports()

    def _test_ip_over_ip_tunnel_update_underlay_vrf(self):
        self.ip_over_ip_tunnel_port.hld_obj.set_underlay_vrf(self.topology.vrf2.hld_obj)
        vrf = self.ip_over_ip_tunnel_port.hld_obj.get_underlay_vrf()
        self.assertEqual(vrf.this, self.topology.vrf2.hld_obj.this)

        self.destroy_ip_over_ip_tunnel_ports()

    def _test_ip_over_ip_tunnel_update_remote_ip_addr(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        ip_addr = self.ip_over_ip_tunnel_port.hld_obj.get_remote_ip_addr()
        self.assertEqual(ip_addr.s_addr, self.REMOTE_IP.hld_obj.s_addr)

        self.ip_over_ip_tunnel_port.hld_obj.set_remote_ip_address(self.NEW_REMOTE_IP.hld_obj)

        ip_addr = self.ip_over_ip_tunnel_port.hld_obj.get_remote_ip_addr()
        self.assertEqual(ip_addr.s_addr, self.NEW_REMOTE_IP.hld_obj.s_addr)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_NEW_REMOTE_IP, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET_NEW_REMOTE_IP, T.RX_SLICE)
        self.assertTrue(byte_count, expected_bytes)

        # Try updating the address to ANY_IP
        self.ip_over_ip_tunnel_port.hld_obj.set_remote_ip_address(self.ANY_IP.hld_obj)

        ip_addr = self.ip_over_ip_tunnel_port.hld_obj.get_remote_ip_addr()
        self.assertEqual(ip_addr.s_addr, self.ANY_IP.hld_obj.s_addr)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_NEW_REMOTE_IP, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET_NEW_REMOTE_IP, T.RX_SLICE)
        self.assertTrue(byte_count, expected_bytes)

        self.destroy_ip_over_ip_tunnel_ports()

    def _test_ip_over_ip_tunnel_update_local_ip_addr(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        prefix = self.ip_over_ip_tunnel_port.hld_obj.get_local_ip_prefix()
        self.assertEqual(prefix.addr.s_addr, self.tunnel_dest1.addr.s_addr)
        self.assertEqual(prefix.length, self.tunnel_dest1.length)

        tunnel_dest = self.ip_impl.build_prefix(self.NEW_LOCAL_IP, length=24)
        self.ip_over_ip_tunnel_port.hld_obj.set_local_ip_prefix(tunnel_dest)

        prefix = self.ip_over_ip_tunnel_port.hld_obj.get_local_ip_prefix()
        self.assertEqual(prefix.addr.s_addr, tunnel_dest.addr.s_addr)
        self.assertEqual(prefix.length, tunnel_dest.length)

        U.run_and_drop(self, self.device,
                       self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_NEW_LOCAL_IP, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET_NEW_LOCAL_IP, T.RX_SLICE)
        self.assertTrue(byte_count, expected_bytes)

        self.destroy_ip_over_ip_tunnel_ports()

    def _test_ip_over_ip_tunnel_ttl_qos_uniform(self):
        self.ip_over_ip_tunnel_port.hld_obj.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_TTL_QOS_UNIFORM, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TTL_QOS_UNIFORM, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET, T.RX_SLICE)
        self.assertTrue(byte_count, expected_bytes)

        self.destroy_ip_over_ip_tunnel_ports()

    def _test_ip_over_ip_tunnel_ttl_qos_uniform_mtu(self):
        self.ip_over_ip_tunnel_port.hld_obj.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        self.topology.rx_l3_ac.hld_obj.set_qos_inheritance_mode(sdk.la_mpls_qos_inheritance_mode_e_UNIFORM)
        MTU.run_mtu_test(self, self.device,
                         self.INPUT_PACKET_TTL_QOS_UNIFORM, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                         self.EXPECTED_OUTPUT_PACKET_TTL_QOS_UNIFORM, T.TX_SLICE_REG,
                         T.TX_IFG_EXT, self.l3_port_impl.serdes_reg)

        self.destroy_ip_over_ip_tunnel_ports()

    def _test_ip_over_ip_tunnel_decap_acl_outer_header(self):
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        # ACL match on the Outer Header
        DIP = self.LOCAL_IP1
        k = []
        f = sdk.la_acl_field()
        f.type = sdk.la_acl_field_type_e_IPV4_DIP
        f.val.ipv4_dip.s_addr = DIP.to_num()
        f.mask.ipv4_dip.s_addr = 0xffffffff
        k.append(f)

        cmd_drop = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = True
        cmd_drop.append(action1)

        acl1.append(k, cmd_drop)

        ipv4_acls = []
        ipv4_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        U.run_and_drop(self, self.device,
                       self.INPUT_PACKET, T.RX_SLICE,
                       T.RX_IFG, T.FIRST_SERDES)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.destroy_ip_over_ip_tunnel_ports()

    def _test_ip_over_ip_tunnel_duplicates(self):

        tunnel_dest = self.ip_impl.build_prefix(self.LOCAL_IP1, length=16)

        with self.assertRaises(sdk.ExistException):
            ip_over_ip_tunnel_port = T.ip_over_ip_tunnel_port(self, self.device,
                                                              self.TUNNEL_PORT_GID4,
                                                              self.topology.vrf,
                                                              tunnel_dest,
                                                              self.REMOTE_IP,
                                                              self.topology.vrf2)
        self.destroy_ip_over_ip_tunnel_ports()

    def _test_ip_over_ip_tunnel_decap_ecmp(self):
        self.create_ip_over_ip_tunnel_port_over_ecmp()
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)

        lb_vec_entry_list = []
        hw_lb_vec = sdk.la_lb_vector_t()
        hw_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP
        hw_lb_vec.ipv4.sip = T.ipv4_addr(self.INPUT_PACKET_MULTI[IP].src).to_num()
        hw_lb_vec.ipv4.dip = T.ipv4_addr(self.INPUT_PACKET_MULTI[IP].dst).to_num()
        hw_lb_vec.ipv4.protocol = self.INPUT_PACKET_MULTI[IP].proto
        lb_vec_entry_list.append(hw_lb_vec)

        soft_lb_vec = sdk.la_lb_vector_t()
        soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP
        soft_lb_vec.ipv4.sip = self.SIP.to_num()
        soft_lb_vec.ipv4.dip = self.DIP1.to_num()
        soft_lb_vec.ipv4.protocol = 0
        lb_vec_entry_list.append(soft_lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(self.ecmp_group, lb_vec_entry_list)

        expected_mac = out_dest_chain[0].downcast().get_mac().flat
        expected_mac_str = T.mac_addr.mac_num_to_str(expected_mac)

        EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=expected_mac_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            self.EXPECTED_OUTPUT_PACKET_MULTI

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_MULTI, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.destroy_ip_over_ip_tunnel_port_over_ecmp()
