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

from leaba import sdk
import packet_test_utils as U
import topology as T
from sdk_test_case_base import *
from packet_test_utils import *
import mtu.mtu_test_utils as MTU
import scapy.all as S


class gue_base(sdk_test_case_base):
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    TUNNEL_TTL = 255
    TTL = 128
    MPLS_TTL = 136
    PREFIX1_GID = 0x691
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    def setUp(self):
        super().setUp()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)
        self.create_gue_ports()

    def create_gue_ports(self):
        # Overlay Prefix in 'vrf'
        self.overlay_prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(
            self.topology.vrf,
            self.overlay_prefix,
            self.l3_port_impl.reg_fec,
            gue_base.PRIVATE_DATA)
        # Overlay Prefix in 'vrf2'
        self.ip_impl.add_route(
            self.topology.vrf2,
            self.overlay_prefix,
            self.l3_port_impl.reg_fec,
            gue_base.PRIVATE_DATA)

        # VRF, Underlay Prefix 1
        self.tunnel_dest1 = self.ip_impl.build_prefix(self.LOCAL_IP1, length=16)

        self.gue_port = T.gue_port(self, self.device,
                                   self.TUNNEL_PORT_GID1,
                                   sdk.la_ip_tunnel_mode_e_DECAP_ONLY,
                                   self.topology.vrf,
                                   self.tunnel_dest1,
                                   self.REMOTE_IP,
                                   self.topology.vrf)

        self.ingress_counter = self.device.create_counter(1)
        self.gue_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.ingress_counter)
        self.gue_port.hld_obj.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)

        # VRF, Underlay Prefix 2
        self.tunnel_dest2 = self.ip_impl.build_prefix(self.LOCAL_IP2, length=16)

        self.gue_any_src_tunnel_port = T.gue_port(self, self.device,
                                                  self.TUNNEL_PORT_GID2,
                                                  sdk.la_ip_tunnel_mode_e_DECAP_ONLY,
                                                  self.topology.vrf,
                                                  self.tunnel_dest2,
                                                  self.ANY_IP,
                                                  self.topology.vrf)

        self.ingress_counter_any_src = self.device.create_counter(1)
        self.gue_any_src_tunnel_port.hld_obj.set_ingress_counter(
            sdk.la_counter_set.type_e_PORT, self.ingress_counter_any_src)
        self.gue_any_src_tunnel_port.hld_obj.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)

    def destroy_gue_ports(self):

        self.gue_any_src_tunnel_port.destroy()
        self.gue_port.destroy()
        self.ip_impl.delete_route(self.topology.vrf2, self.overlay_prefix)
        self.ip_impl.delete_route(self.topology.vrf, self.overlay_prefix)

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh, gue_base.PRIVATE_DATA_DEFAULT)
        self.has_default_route = True

    def destroy_default_route(self):
        if self.has_default_route:
            prefix = self.ip_impl.get_default_prefix()
            self.ip_impl.delete_route(self.topology.vrf, prefix)
            self.has_default_route = False

    def _test_gue_decap(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET, T.RX_SLICE)
        self.assertTrue(byte_count, expected_bytes)

        self.device.set_decap_ttl_decrement_enabled(sdk.la_ip_tunnel_type_e_GUE, False)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_NO_TTL_DECR, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.device.set_decap_ttl_decrement_enabled(sdk.la_ip_tunnel_type_e_GUE, True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.destroy_gue_ports()

    def _test_gue_decap_transit_counter_no_increment(self):
        transit_counter_size = sdk.la_ip_tunnel_type_e_LAST
        self.transit_counter = self.device.create_counter(transit_counter_size)
        self.device.set_ip_tunnel_transit_counter(self.transit_counter)
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET, T.RX_SLICE)
        self.assertTrue(byte_count, expected_bytes)

        packet_count, byte_count = self.transit_counter.read(sdk.la_ip_tunnel_type_e_GUE, True, True)
        self.assertEqual(packet_count, 0)

        self.device.set_decap_ttl_decrement_enabled(sdk.la_ip_tunnel_type_e_GUE, False)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_NO_TTL_DECR, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.transit_counter.read(sdk.la_ip_tunnel_type_e_GUE, True, True)
        self.assertEqual(packet_count, 0)

        self.device.set_decap_ttl_decrement_enabled(sdk.la_ip_tunnel_type_e_GUE, True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.transit_counter.read(sdk.la_ip_tunnel_type_e_GUE, True, True)
        self.assertEqual(packet_count, 0)

        self.destroy_gue_ports()

    def _test_gue_decap_v6(self):
        subnet = self.ip6_impl.build_prefix(self.DIPv6, length=16)
        self.ip6_impl.add_subnet(self.l3_port_impl.tx_port, subnet)
        self.ip6_impl.add_host(self.l3_port_impl.tx_port, self.DIPv6, self.l3_port_impl.reg_nh.mac_addr)
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_v6, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_v6, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET, T.RX_SLICE)
        self.assertTrue(byte_count, expected_bytes)

        self.device.set_decap_ttl_decrement_enabled(sdk.la_ip_tunnel_type_e_GUE, False)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_v6, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_NO_TTL_DECR_v6, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.device.set_decap_ttl_decrement_enabled(sdk.la_ip_tunnel_type_e_GUE, True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_v6, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_v6, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.destroy_gue_ports()

    def _test_gue_decap_mtu(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        MTU.run_mtu_test(self, self.device,
                         self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                         self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                         T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.device.set_decap_ttl_decrement_enabled(sdk.la_ip_tunnel_type_e_GUE, False)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_NO_TTL_DECR, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.device.set_decap_ttl_decrement_enabled(sdk.la_ip_tunnel_type_e_GUE, True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.destroy_gue_ports()

    def _test_gue_any_src_tunnel_decap(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        U.run_and_compare(self, self.device,
                          self.INPUT_ANY_IP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.ingress_counter_any_src.read(0, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_ANY_IP_PACKET, T.RX_SLICE)
        self.assertTrue(byte_count, expected_bytes)

        self.device.set_decap_ttl_decrement_enabled(sdk.la_ip_tunnel_type_e_GUE, False)
        U.run_and_compare(self, self.device,
                          self.INPUT_ANY_IP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_NO_TTL_DECR, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.device.set_decap_ttl_decrement_enabled(sdk.la_ip_tunnel_type_e_GUE, True)
        U.run_and_compare(self, self.device,
                          self.INPUT_ANY_IP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.destroy_gue_ports()

    def _test_gue_update_overlay_vrf(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        self.gue_port.hld_obj.set_overlay_vrf(self.topology.vrf2.hld_obj)
        vrf = self.gue_port.hld_obj.get_overlay_vrf()
        self.assertEqual(vrf.this, self.topology.vrf2.hld_obj.this)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET, T.RX_SLICE)
        self.assertTrue(byte_count, expected_bytes)

        self.destroy_gue_ports()

    def _test_gue_update_underlay_vrf(self):
        self.gue_port.hld_obj.set_underlay_vrf(self.topology.vrf2.hld_obj)
        vrf = self.gue_port.hld_obj.get_underlay_vrf()
        self.assertEqual(vrf.this, self.topology.vrf2.hld_obj.this)

        self.destroy_gue_ports()

    def _test_gue_update_remote_ip_addr(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        ip_addr = self.gue_port.hld_obj.get_remote_ip_addr()
        self.assertEqual(ip_addr.s_addr, self.REMOTE_IP.hld_obj.s_addr)

        self.gue_port.hld_obj.set_remote_ip_address(self.NEW_REMOTE_IP.hld_obj)

        ip_addr = self.gue_port.hld_obj.get_remote_ip_addr()
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
        self.gue_port.hld_obj.set_remote_ip_address(self.ANY_IP.hld_obj)

        ip_addr = self.gue_port.hld_obj.get_remote_ip_addr()
        self.assertEqual(ip_addr.s_addr, self.ANY_IP.hld_obj.s_addr)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_NEW_REMOTE_IP, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET_NEW_REMOTE_IP, T.RX_SLICE)
        self.assertTrue(byte_count, expected_bytes)

        self.destroy_gue_ports()

    def _test_gue_update_local_ip_addr(self):
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        prefix = self.gue_port.hld_obj.get_local_ip_prefix()
        self.assertEqual(prefix.addr.s_addr, self.tunnel_dest1.addr.s_addr)
        self.assertEqual(prefix.length, self.tunnel_dest1.length)

        tunnel_dest = self.ip_impl.build_prefix(self.NEW_LOCAL_IP, length=24)
        self.gue_port.hld_obj.set_local_ip_prefix(tunnel_dest)

        prefix = self.gue_port.hld_obj.get_local_ip_prefix()
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

        self.destroy_gue_ports()

    def _test_gue_ttl_qos_uniform(self):
        self.gue_port.hld_obj.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_TTL_QOS_UNIFORM, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_TTL_QOS_UNIFORM, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET, T.RX_SLICE)
        self.assertTrue(byte_count, expected_bytes)

        self.destroy_gue_ports()

    def _test_gue_ttl_qos_uniform_mtu(self):
        self.gue_port.hld_obj.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        self.topology.rx_l3_ac.hld_obj.set_qos_inheritance_mode(sdk.la_mpls_qos_inheritance_mode_e_UNIFORM)
        MTU.run_mtu_test(self, self.device,
                         self.INPUT_PACKET_TTL_QOS_UNIFORM, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                         self.EXPECTED_OUTPUT_PACKET_TTL_QOS_UNIFORM, T.TX_SLICE_REG,
                         T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.destroy_gue_ports()

    def _test_gue_decap_acl_outer_header(self):
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
        drop_action = sdk.la_acl_command_action()
        drop_action.type = sdk.la_acl_action_type_e_DROP
        drop_action.data.drop = True
        cmd_drop.append(drop_action)

        acl1.append(k, cmd_drop)
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        U.run_and_drop(self, self.device,
                       self.INPUT_PACKET, T.RX_SLICE,
                       T.RX_IFG, T.FIRST_SERDES)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.destroy_gue_ports()

    def _test_gue_duplicates(self):

        tunnel_dest = self.ip_impl.build_prefix(self.LOCAL_IP1, length=16)

        with self.assertRaises(sdk.ExistException):
            gue_port = T.gue_port(self, self.device,
                                  self.TUNNEL_PORT_GID4,
                                  sdk.la_ip_tunnel_mode_e_DECAP_ONLY,
                                  self.topology.vrf,
                                  tunnel_dest,
                                  self.REMOTE_IP,
                                  self.topology.vrf2)
        self.destroy_gue_ports()

    def _test_gue_decap_mpls_swap(self):
        nhlfe = self.device.create_mpls_swap_nhlfe(self.l3_port_impl.reg_nh.hld_obj, self.OUTPUT_LABEL)
        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_MPLS, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS_SWAP, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET_MPLS, T.RX_SLICE)
        self.assertTrue(byte_count, expected_bytes)
        self.destroy_gue_ports()
        lsr.delete_route(self.INPUT_LABEL)
        self.device.destroy(nhlfe)

    def _test_gue_decap_mpls_encap(self):
        prefix = self.ip_impl.build_prefix(self.DIP1, length=24)
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        lsp_labels = []
        lsp_labels.append(self.OUTPUT_LABEL)
        pfx_obj.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels,
                                              None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.topology.vrf.hld_obj.add_ipv4_route(prefix, pfx_obj.hld_obj, self.PRIVATE_DATA, False)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_MPLS_ENCAP, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS_ENCAP, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET_MPLS_ENCAP, T.RX_SLICE)
        self.assertTrue(byte_count, expected_bytes)
        self.destroy_gue_ports()
        self.topology.vrf.hld_obj.delete_ipv4_route(prefix)
        pfx_obj.destroy()

    def _test_gue_decap_mpls_decap(self):
        # enable ipv4 forwarding (no input vlans due to deep header stack)
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_def.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_ext.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        # also disable inner lb
        self.gue_port.hld_obj.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)

        lsr = self.device.get_lsr()
        decap = lsr.add_vpn_decap(self.INPUT_LABEL, self.topology.vrf.hld_obj)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_MPLS_NOVLAN, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3,
                          self.EXPECTED_OUTPUT_PACKET_MPLS_DECAP, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET_MPLS, T.RX_SLICE)
        self.assertTrue(byte_count, expected_bytes)
        self.destroy_gue_ports()
        lsr.delete_vpn_decap(decap)

    def _test_gue_decap_mpls_swap_v6(self):
        nhlfe = self.device.create_mpls_swap_nhlfe(self.l3_port_impl.reg_nh.hld_obj, self.OUTPUT_LABEL)
        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL, nhlfe, self.PRIVATE_DATA)

        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_MPLS_v6, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS_SWAP_v6, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET_MPLS_v6, T.RX_SLICE)
        self.assertTrue(byte_count, expected_bytes)
        self.destroy_gue_ports()
        lsr.delete_route(self.INPUT_LABEL)
        self.device.destroy(nhlfe)

    def _test_gue_decap_mpls_encap_v6(self):
        prefix = self.ip6_impl.build_prefix(self.DIPv6, length=64)
        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        lsp_labels = []
        lsp_labels.append(self.OUTPUT_LABEL)
        pfx_obj.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels,
                                              None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        self.topology.vrf.hld_obj.add_ipv6_route(prefix, pfx_obj.hld_obj, self.PRIVATE_DATA, False)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_MPLS_ENCAP_v6, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS_ENCAP_v6, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET_MPLS_ENCAP_v6, T.RX_SLICE)
        self.assertTrue(byte_count, expected_bytes)
        self.destroy_gue_ports()
        self.topology.vrf.hld_obj.delete_ipv6_route(prefix)
        pfx_obj.destroy()

    def _test_gue_decap_mpls_decap_v6(self):
        # enable ipv4 forwarding (no input vlans due to deep header stack)
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_def.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_ext.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        # also disable inner lb
        self.gue_port.hld_obj.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)

        lsr = self.device.get_lsr()
        decap = lsr.add_vpn_decap(self.INPUT_LABEL, self.topology.vrf.hld_obj)
        prefix = self.ip6_impl.build_prefix(self.DIPv6, length=64)
        self.ip6_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_MPLS_NOVLAN_v6, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3,
                          self.EXPECTED_OUTPUT_PACKET_MPLS_DECAP_v6, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        packet_count, byte_count = self.ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.INPUT_PACKET_MPLS_v6, T.RX_SLICE)
        self.assertTrue(byte_count, expected_bytes)
        self.destroy_gue_ports()
        self.ip6_impl.delete_route(self.topology.vrf, prefix)
        lsr.delete_vpn_decap(decap)

    def create_ecmp_group(self):
        NH_GID_BASE = 0x613
        NH_DST_MAC_BASE = T.mac_addr('11:11:11:11:11:00')

        l3_port_impl = T.ip_l3_ac_base(self.topology)

        self.ecmp_group = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.nh_list = []
        for nh_num in range(self.NUM_OF_NH):
            nh = T.next_hop(
                self,
                self.device,
                NH_GID_BASE + nh_num,
                NH_DST_MAC_BASE.create_offset_mac(nh_num),
                l3_port_impl.tx_port)
            self.ecmp_group.add_member(nh.hld_obj)
            self.nh_list.append(nh)

    def _test_gue_decap_ecmp(self):
        PAYLOAD_SIZE = 60
        self.create_ecmp_group()

        # enable ipv4 forwarding (no input vlans due to deep header stack)
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_def.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_ext.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)

        prefix = self.ip_impl.build_prefix(self.DIP_UNL, length=16)
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.ecmp_group, self.PRIVATE_DATA, False)
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)

        # ACL match on the Outer Header
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        k = []
        f = sdk.la_acl_field()
        f.type = sdk.la_acl_field_type_e_IPV4_DIP
        f.val.ipv4_dip.s_addr = self.LOCAL_IP1.to_num()
        f.mask.ipv4_dip.s_addr = 0xffffffff
        k.append(f)

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV4_DIP
        f1.val.ipv4_dip.s_addr = self.LOCAL_IP1.to_num()
        f1.mask.ipv4_dip.s_addr = 0x0
        k1.append(f1)

        cmd_nop = []
        nop_action = sdk.la_acl_command_action()
        nop_action.type = sdk.la_acl_action_type_e_DROP
        nop_action.data.drop = False
        cmd_nop.append(nop_action)

        acl1.append(k, cmd_nop)
        acl1.append(k1, cmd_nop)
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        INPUT_PACKET_MULTI = add_payload(self.INPUT_PACKET_MULTI_BASE, PAYLOAD_SIZE)

        lb_vec_entry_list = []
        hw_lb_vec = sdk.la_lb_vector_t()
        hw_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
        hw_lb_vec.ipv4.sip = T.ipv4_addr(INPUT_PACKET_MULTI[IP].src).to_num()
        hw_lb_vec.ipv4.dip = T.ipv4_addr(INPUT_PACKET_MULTI[IP].dst).to_num()
        hw_lb_vec.ipv4.protocol = INPUT_PACKET_MULTI[IP].proto
        hw_lb_vec.ipv4.src_port = INPUT_PACKET_MULTI[UDP].sport
        hw_lb_vec.ipv4.dest_port = INPUT_PACKET_MULTI[UDP].dport
        lb_vec_entry_list.append(hw_lb_vec)

        soft_lb_vec = sdk.la_lb_vector_t()
        soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
        soft_lb_vec.ipv4.sip = T.ipv4_addr(INPUT_PACKET_MULTI[UDP][IP].src).to_num()
        soft_lb_vec.ipv4.dip = T.ipv4_addr(INPUT_PACKET_MULTI[UDP][IP].dst).to_num()
        soft_lb_vec.ipv4.protocol = INPUT_PACKET_MULTI[UDP][IP].proto
        soft_lb_vec.ipv4.src_port = INPUT_PACKET_MULTI[TCP].sport
        soft_lb_vec.ipv4.dest_port = INPUT_PACKET_MULTI[TCP].dport

        lb_vec_entry_list.append(soft_lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(self.ecmp_group, lb_vec_entry_list)
        U.check_forwarding_load_balance_chain(self, out_dest_chain, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        expected_mac = out_dest_chain[0].downcast().get_mac().flat
        expected_mac_str = T.mac_addr.mac_num_to_str(expected_mac)

        EXPECTED_OUTPUT_PACKET_MULTI = \
            S.Ether(dst=expected_mac_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            self.EXPECTED_OUTPUT_PACKET_MULTI_BASE

        EXPECTED_OUTPUT_PACKET_MULTI_local = add_payload(EXPECTED_OUTPUT_PACKET_MULTI, PAYLOAD_SIZE)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_MULTI, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3,
                          EXPECTED_OUTPUT_PACKET_MULTI_local, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    def _test_gue_decap_mpls_ecmp(self):
        PAYLOAD_SIZE = 60
        self.create_ecmp_group()

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, self.ecmp_group)

        for nh_num in range(self.NUM_OF_NH):
            lsp_labels = []
            lsp_labels.append(self.OUTPUT_LABEL)
            pfx_obj.hld_obj.set_nh_lsp_properties(
                self.nh_list[nh_num].hld_obj,
                lsp_labels,
                None,
                sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsr = self.device.get_lsr()
        lsr.add_route(self.INPUT_LABEL, pfx_obj.hld_obj, self.PRIVATE_DATA)
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)

        # ACL match on the Outer Header
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        k = []
        f = sdk.la_acl_field()
        f.type = sdk.la_acl_field_type_e_IPV4_DIP
        f.val.ipv4_dip.s_addr = self.LOCAL_IP1.to_num()
        f.mask.ipv4_dip.s_addr = 0xffffffff
        k.append(f)

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV4_DIP
        f1.val.ipv4_dip.s_addr = self.LOCAL_IP1.to_num()
        f1.mask.ipv4_dip.s_addr = 0x0
        k1.append(f1)

        cmd_nop = []
        drop_action = sdk.la_acl_command_action()
        drop_action.type = sdk.la_acl_action_type_e_DROP
        drop_action.data.drop = False
        cmd_nop.append(drop_action)

        acl1.append(k, cmd_nop)
        acl1.append(k1, cmd_nop)
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        INPUT_PACKET_MPLS_MULTI = add_payload(self.INPUT_PACKET_MPLS_MULTI_BASE, PAYLOAD_SIZE)

        lb_vec_entry_list = []
        hw_lb_vec = sdk.la_lb_vector_t()
        hw_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
        hw_lb_vec.ipv4.sip = T.ipv4_addr(INPUT_PACKET_MPLS_MULTI[IP].src).to_num()
        hw_lb_vec.ipv4.dip = T.ipv4_addr(INPUT_PACKET_MPLS_MULTI[IP].dst).to_num()
        hw_lb_vec.ipv4.protocol = INPUT_PACKET_MPLS_MULTI[IP].proto
        hw_lb_vec.ipv4.src_port = INPUT_PACKET_MPLS_MULTI[UDP].sport
        hw_lb_vec.ipv4.dest_port = INPUT_PACKET_MPLS_MULTI[UDP].dport
        lb_vec_entry_list.append(hw_lb_vec)

        soft_lb_vec = sdk.la_lb_vector_t()
        soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
        soft_lb_vec.ipv4.sip = T.ipv4_addr(INPUT_PACKET_MPLS_MULTI[MPLS][IP].src).to_num()
        soft_lb_vec.ipv4.dip = T.ipv4_addr(INPUT_PACKET_MPLS_MULTI[MPLS][IP].dst).to_num()
        soft_lb_vec.ipv4.protocol = INPUT_PACKET_MPLS_MULTI[MPLS][IP].proto
        soft_lb_vec.ipv4.src_port = INPUT_PACKET_MPLS_MULTI[TCP].sport
        soft_lb_vec.ipv4.dest_port = INPUT_PACKET_MPLS_MULTI[TCP].dport

        lb_vec_entry_list.append(soft_lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(self.ecmp_group, lb_vec_entry_list)
        U.check_forwarding_load_balance_chain(self, out_dest_chain, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        expected_mac = out_dest_chain[0].downcast().get_mac().flat
        expected_mac_str = T.mac_addr.mac_num_to_str(expected_mac)

        EXPECTED_OUTPUT_PACKET_MPLS_MULTI = \
            S.Ether(dst=expected_mac_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            self.EXPECTED_OUTPUT_PACKET_MPLS_MULTI_BASE

        EXPECTED_OUTPUT_PACKET_MPLS_MULTI_local = add_payload(EXPECTED_OUTPUT_PACKET_MPLS_MULTI, PAYLOAD_SIZE)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_MPLS_MULTI, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          EXPECTED_OUTPUT_PACKET_MPLS_MULTI_local, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
