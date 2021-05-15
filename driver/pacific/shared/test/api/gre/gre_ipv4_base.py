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

import sys
import unittest
import ipaddress
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import sim_utils
import topology as T
import packet_test_defs as P
import ip_test_base
from sdk_test_case_base import *
import mtu.mtu_test_utils as MTU
from sdk_test_case_base import *
from gre.gre_base import *
import decor
import ipaddress

VRF_BASE_GID = 0x100 if not decor.is_gibraltar() else 0xF00


class gre_ipv4_base(gre_base):
    OVL_DIP_ROUTE = T.ipv4_addr('21.1.1.0')
    OVL_SIP_ROUTE = T.ipv4_addr('11.1.1.0')

    IP_TUNNEL_PORT_GID = 0x521
    REMOTE_IP = T.ipv4_addr('12.10.12.100')
    LOCAL_IP1 = T.ipv4_addr('192.168.95.250')
    TUNNEL_TTL = 255
    OVL_IP_PACKET_DIP = '21.1.1.1'
    OVL_IP_PACKET_SIP = '11.1.1.1'

    OVL_OSPF_DIP = '224.0.0.5'

    OVL_DIP_ROUTE_ABF = T.ipv4_addr('10.250.1.1')
    OVL_IP_PACKET_DIP_ABF = OVL_DIP_ROUTE_ABF.addr_str

    GRE_HEADER = S.GRE()
# next variables are by
# _test_gre_port_decap
# _test_gre_port_decap_mtu
    PORT_DECAP_OVL_INPUT_IP = S.IP(dst=OVL_IP_PACKET_SIP, src=OVL_IP_PACKET_DIP, ttl=63)
    PORT_DECAP_OVL_EXPECTED_IP = S.IP(dst=OVL_IP_PACKET_SIP, src=OVL_IP_PACKET_DIP, ttl=62)
    PORT_DECAP_OVL_TTL_EXPECTED_IP = S.IP(dst=OVL_IP_PACKET_SIP, src=OVL_IP_PACKET_DIP, ttl=254)
    PORT_DECAP_OVL_EXPECTED_IP_NO_TTL_DECR = PORT_DECAP_OVL_INPUT_IP

# next variables are used by
# _test_gre_port_decap_qos
    PORT_DECAP_QOS_OVL_INPUT_IP = S.IP(dst=OVL_IP_PACKET_SIP,
                                       src=OVL_IP_PACKET_DIP, ttl=63)
    PORT_DECAP_QOS_OVL_EXPECTED_IP = S.IP(dst=OVL_IP_PACKET_SIP,
                                          src=OVL_IP_PACKET_DIP, ttl=62,
                                          tos=gre_base.OUT_DSCP.value << 2)
    PORT_DECAP_QOS_OVL_EXPECTED_IP_NO_TTL_DECR = S.IP(dst=OVL_IP_PACKET_SIP,
                                                      src=OVL_IP_PACKET_DIP, ttl=63,
                                                      tos=gre_base.OUT_DSCP.value << 2)

    PORT_DECAP_QOS2_OVL_EXPECTED_IP = S.IP(dst=OVL_IP_PACKET_SIP,
                                           src=OVL_IP_PACKET_DIP, ttl=62,
                                           tos=gre_base.OUT_TOS.flat)
    PORT_DECAP_QOS2_TAG_OVL_EXPECTED_IP = S.IP(dst=OVL_IP_PACKET_SIP,
                                               src=OVL_IP_PACKET_DIP, ttl=62,
                                               tos=gre_base.TAG_IP_DSCP.value << 2)

# next variable(s) are used by
# _test_gre_port_decap_acl
    PORT_DECAP_ACL_OVL_INPUT_IP = S.IP(dst=OVL_IP_PACKET_SIP,
                                       src=OVL_IP_PACKET_DIP, ttl=63)

# next variable(s) are used by
# _test_gre_encap_qos
    ENCAP_QOS_OVL_INPUT_IP = S.IP(dst=OVL_IP_PACKET_DIP, src=OVL_IP_PACKET_SIP)
    ENCAP_QOS_OVL_INPUT_IP_ABF = S.IP(dst=OVL_IP_PACKET_DIP_ABF, src=OVL_IP_PACKET_SIP)
    ENCAP_QOS_OVL_EXPECTED_IP = S.IP(dst=OVL_IP_PACKET_DIP,
                                     src=OVL_IP_PACKET_SIP, ttl=63,
                                     tos=(gre_base.TAG_IP_DSCP.value << 2))
    ENCAP_QOS_OVL_EXPECTED_IP_2 = S.IP(dst=OVL_IP_PACKET_DIP,
                                       src=OVL_IP_PACKET_SIP, ttl=63)
    ENCAP_QOS_OVL_EXPECTED_IP_ABF = S.IP(dst=OVL_IP_PACKET_DIP_ABF,
                                         src=OVL_IP_PACKET_SIP, ttl=63)

# next variables are used by
# _test_gre_port_single_underlay_path
# _test_gre_port_single_underlay_path_verify_padding
# _test_gre_port_multi_underlay_path
# _test_gre_port_multi_underlay_path_mtu
    SINGLE_UNDERLAY_OVL_INPUT_IP = S.IP(dst=OVL_IP_PACKET_DIP, src=OVL_IP_PACKET_SIP)
    SINGLE_UNDERLAY_OVL_EXPECTED_IP = S.IP(dst=OVL_IP_PACKET_DIP,
                                           src=OVL_IP_PACKET_SIP, ttl=63)

# next variables are by
# _test_gre_port_decap_lpts
    PORT_DECAP_OVL_INPUT_OSPF = S.IP(dst=OVL_OSPF_DIP, src=OVL_IP_PACKET_DIP, ttl=1, proto=89)

# helper method for _test_gre_port_single_underlay_path
    def set_single_underlay_ovl_expected_inner_ttl(self, expected_packet, decrement=True):
        expected_packet[GRE][IP].ttl = self.SINGLE_UNDERLAY_OVL_EXPECTED_IP[IP].ttl if decrement else self.SINGLE_UNDERLAY_OVL_INPUT_IP[IP].ttl

    def gre_port_single_underlay_path(self, mode=sdk.la_ip_tunnel_mode_e_ENCAP_DECAP, per_proto_counter=False):
        self.gre_tunnel = self.gre_port_setup(self.GRE_PORT_GID, mode, self.topology.vrf,
                                              self.GRE_SIP, self.GRE_DIP, self.topology.vrf2, per_proto_counter)
        self.gre_destination = self.device.create_ip_tunnel_destination(
            self.GRE_TUNNEL_DESTINATION_GID,
            self.gre_tunnel,
            self.topology.nh_l3_ac_reg.hld_obj)
        self.ovl_dip_prefix = self.ip_impl.build_prefix(self.OVL_DIP_ROUTE, length=24)
        if self.source_based_forwarding == self.SBF_TEST_DISABLED:
            self.topology.vrf2.hld_obj.add_ipv4_route(self.ovl_dip_prefix, self.gre_destination, self.PRIVATE_DATA, False)
        self.ovl_sip_prefix = self.ip_impl.build_prefix(self.OVL_SIP_ROUTE, length=24)
        self.topology.vrf2.hld_obj.add_ipv4_route(self.ovl_sip_prefix, self.topology.nh_l3_ac_def.hld_obj, self.PRIVATE_DATA, False)
        self.setup_as_single_underlay_path = True

    def destroy_gre_port_single_underlay_path(self):
        if hasattr(self, 'setup_as_single_underlay_path') is False:
            return
        if self.setup_as_single_underlay_path is False:
            return
        if self.source_based_forwarding == self.SBF_TEST_DISABLED:
            self.topology.vrf2.hld_obj.delete_ipv4_route(self.ovl_dip_prefix)
        self.topology.vrf2.hld_obj.delete_ipv4_route(self.ovl_sip_prefix)
        self.device.destroy(self.gre_destination)
        self.device.destroy(self.gre_tunnel)
        self.device.destroy(self.l3_egress_counter)
        self.device.destroy(self.l3_ingress_counter)
        self.setup_as_single_underlay_path = False

    def ip_over_ip_tunnel_port_single_underlay_path(self, mode=sdk.la_ip_tunnel_mode_e_ENCAP_ONLY):
        self.ip_over_ip_tunnel = self.ip_over_ip_tunnel_port_setup(self.GRE_PORT_GID, mode, self.topology.vrf,
                                                                   self.GRE_SIP, self.GRE_DIP, self.topology.vrf2)
        self.ip_over_ip_tunnel_destination = self.device.create_ip_tunnel_destination(
            self.GRE_TUNNEL_DESTINATION_GID,
            self.ip_over_ip_tunnel.hld_obj,
            self.topology.nh_l3_ac_reg.hld_obj)
        self.ovl_dip_prefix = self.ip_impl.build_prefix(self.OVL_DIP_ROUTE, length=24)
        self.topology.vrf2.hld_obj.add_ipv4_route(self.ovl_dip_prefix, self.ip_over_ip_tunnel_destination, self.PRIVATE_DATA, False)
        self.ovl_sip_prefix = self.ip_impl.build_prefix(self.OVL_SIP_ROUTE, length=24)
        self.topology.vrf2.hld_obj.add_ipv4_route(self.ovl_sip_prefix, self.topology.nh_l3_ac_def.hld_obj, self.PRIVATE_DATA, False)
        self.setup_as_single_underlay_path = True

    def destroy_ip_over_ip_tunnel_port_single_underlay_path(self):
        if hasattr(self, 'setup_as_single_underlay_path') is False:
            return
        self.topology.vrf2.hld_obj.delete_ipv4_route(self.ovl_dip_prefix)
        self.topology.vrf2.hld_obj.delete_ipv4_route(self.ovl_sip_prefix)
        self.device.destroy(self.ip_over_ip_tunnel_destination)
        self.device.destroy(self.ip_over_ip_tunnel.hld_obj)
        self.setup_as_single_underlay_path = False

    def ip_over_ip_tunnel_port_create_ovl_ecmp(self):
        # create overlay ecmp group
        self.ovl_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.ovl_ecmp_attached_members = [self.ip_over_ip_tunnel_destination, self.ip_over_ip_tunnel_destination1]
        for member in self.ovl_ecmp_attached_members:
            self.ovl_ecmp.add_member(member)

        self.ovl_dip_prefix = self.ip_impl.build_prefix(self.OVL_DIP_ROUTE, length=24)
        self.topology.vrf2.hld_obj.add_ipv4_route(self.ovl_dip_prefix, self.ovl_ecmp, self.PRIVATE_DATA, False)

    def gre_port_create_ovl_ecmp(self):
        # create overlay ecmp group
        self.ovl_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        self.ovl_ecmp_attached_members = [self.gre_destination, self.gre_destination1]
        for member in self.ovl_ecmp_attached_members:
            self.ovl_ecmp.add_member(member)

        self.ovl_dip_prefix = self.ip_impl.build_prefix(self.OVL_DIP_ROUTE, length=24)
        if self.source_based_forwarding == self.SBF_TEST_DISABLED:
            self.topology.vrf2.hld_obj.add_ipv4_route(self.ovl_dip_prefix, self.ovl_ecmp, self.PRIVATE_DATA, False)

    def destroy_ip_over_ip_tunnel_port_multi_underlay_path(self):
        if hasattr(self, 'setup_as_multi_underlay_path') is False:
            return
        self.topology.vrf2.hld_obj.delete_ipv4_route(self.ovl_dip_prefix)
        self.device.destroy(self.ovl_ecmp)
        self.device.destroy(self.ip_over_ip_tunnel_destination)
        self.device.destroy(self.ip_over_ip_tunnel_destination1)
        self.device.destroy(self.unl_ecmp)
        self.device.destroy(self.ip_over_ip_tunnel.hld_obj)
        self.device.destroy(self.ip_over_ip_tunnel1.hld_obj)
        self.setup_as_multi_underlay_path = False

    def destroy_gre_port_multi_underlay_path(self):
        if hasattr(self, 'setup_as_multi_underlay_path') is False:
            return
        if self.source_based_forwarding == self.SBF_TEST_DISABLED:
            self.topology.vrf2.hld_obj.delete_ipv4_route(self.ovl_dip_prefix)
        self.device.destroy(self.ovl_ecmp)
        self.device.destroy(self.gre_destination)
        self.device.destroy(self.gre_destination1)
        self.device.destroy(self.unl_ecmp)
        self.device.destroy(self.gre_tunnel)
        self.device.destroy(self.gre_tunnel1)
        self.setup_as_multi_underlay_path = False

    def gre_test_overlay_full_mask(self):
        # change the overlay route to /32
        self.OVL_DIP_ROUTE32 = T.ipv4_addr(self.OVL_IP_PACKET_DIP)
        self.ovl_dip_prefix32 = self.ip_impl.build_prefix(self.OVL_DIP_ROUTE32, length=32)
        self.topology.vrf2.hld_obj.add_ipv4_route(self.ovl_dip_prefix32, self.gre_destination, self.PRIVATE_DATA, False)
        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, T.TX_SLICE_EXT,
                          T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT)

        packets, byte_count = self.l3_egress_counter.read(0, True, True)
        self.assertEqual(packets, 7)

        self.topology.vrf2.hld_obj.delete_ipv4_route(self.ovl_dip_prefix32)

    def _test_gre_port_multi_underlay_path_mtu(self):

        input_packet_base = \
            S.Ether(dst=self.OVL_IP_PACKET_DMAC,
                    src=self.OVL_IP_PACKET_SMAC) / \
            self.SINGLE_UNDERLAY_OVL_INPUT_IP / \
            S.TCP()
        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str,
                    src=T.TX_L3_AC_EXT_MAC.addr_str) / \
            S.IP(dst=self.GRE_DIP1.addr_str,
                 src=self.GRE_SIP1.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.GRE_HEADER / \
            self.SINGLE_UNDERLAY_OVL_EXPECTED_IP / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)
        (self.expected_packet, out_slice, out_ifg, out_pif) = self.calculate_ecmp_expected_output()

        MTU.run_mtu_test(self, self.device,
                         self.input_packet, T.TX_SLICE_DEF,
                         T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                         self.expected_packet, out_slice, out_ifg, out_pif)

        # change the overlay route to /32
        self.OVL_DIP_ROUTE32 = T.ipv4_addr(self.OVL_IP_PACKET_DIP)
        self.ovl_dip_prefix32 = self.ip_impl.build_prefix(self.OVL_DIP_ROUTE32, length=32)
        self.topology.vrf2.hld_obj.add_ipv4_route(self.ovl_dip_prefix32, self.gre_destination1, self.PRIVATE_DATA, False)

        MTU.run_mtu_test(self, self.device,
                         self.input_packet, T.TX_SLICE_DEF,
                         T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                         self.expected_packet, out_slice, out_ifg, out_pif)

        self.topology.vrf2.hld_obj.delete_ipv4_route(self.ovl_dip_prefix32)

    def calculate_ecmp_expected_output(self):
        # both members of ovl_ecmp use unl_ecmp as the destination
        # so it's enough to find the load-balancing result of unl_ecmp and fix the topmost eth header
        dip = T.ipv4_addr(self.input_packet[IP].dst)
        sip = T.ipv4_addr(self.input_packet[IP].src)

        lb_vec_entry_list = []

        lb_vec = sdk.la_lb_vector_t()
        lb_vec.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
        lb_vec.ipv4.sip = sip.hld_obj.s_addr
        lb_vec.ipv4.dip = dip.hld_obj.s_addr
        lb_vec.ipv4.protocol = self.input_packet[IP].proto
        lb_vec.ipv4.src_port = self.input_packet[TCP].sport
        lb_vec.ipv4.dest_port = self.input_packet[TCP].dport

        lb_vec_entry_list.append(lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(self.unl_ecmp, lb_vec_entry_list)

        ### For Debug purpose:########################################################
        #U.display_forwarding_load_balance_chain(self.unl_ecmp, out_dest_chain)
        #print('nh_reg=%d nh_ext=%d' % (self.topology.nh_l3_ac_reg.hld_obj.oid(),  self.topology.nh_l3_ac_ext.hld_obj.oid()))
        ##############################################################################

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

        dst = out_nh.get_mac()
        src = out_nh.get_router_port().downcast().get_mac()
        dst_str = T.mac_addr.mac_num_to_str(dst.flat)
        src_str = T.mac_addr.mac_num_to_str(src.flat)

        new_eth_hdr = S.Ether(dst=dst_str, src=src_str)
        expected_packet = new_eth_hdr / self.expected_packet[1]

        out_slice = out_dsp.get_slice()
        out_ifg = out_dsp.get_ifg()
        out_pif = out_dsp.get_base_serdes()

        return expected_packet, out_slice, out_ifg, out_pif

    def _test_gre_port_multi_underlay_path(self):

        input_packet_base = \
            S.Ether(dst=self.OVL_IP_PACKET_DMAC,
                    src=self.OVL_IP_PACKET_SMAC) / \
            self.SINGLE_UNDERLAY_OVL_INPUT_IP / \
            S.TCP()

        if self.source_based_forwarding == self.SBF_TEST_ENABLED_WITH_MPLS:
            expected_gre_encap = S.GRE(proto=0x8847) / \
                MPLS(label=self.SBF_MPLS_LABEL, ttl=255)
        else:
            expected_gre_encap = self.GRE_HEADER

        if decor.is_pacific():
            gre_dip = self.GRE_DIP1.addr_str
            gre_sip = self.GRE_SIP1.addr_str
        elif decor.is_gibraltar():
            gre_dip = self.GRE_DIP1.addr_str
            gre_sip = self.GRE_SIP1.addr_str

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str,
                    src=T.TX_L3_AC_EXT_MAC.addr_str) / \
            S.IP(dst=gre_dip,
                 src=gre_sip,
                 id=0,
                 flags=2,
                 ttl=255) / \
            expected_gre_encap / \
            self.SINGLE_UNDERLAY_OVL_EXPECTED_IP / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)
        (self.expected_packet, out_slice, out_ifg, out_pif) = self.calculate_ecmp_expected_output()

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, out_slice, out_ifg, out_pif)

        # change the overlay route to /32
        self.OVL_DIP_ROUTE32 = T.ipv4_addr(self.OVL_IP_PACKET_DIP)
        self.ovl_dip_prefix32 = self.ip_impl.build_prefix(self.OVL_DIP_ROUTE32, length=32)
        self.topology.vrf2.hld_obj.add_ipv4_route(self.ovl_dip_prefix32, self.gre_destination1, self.PRIVATE_DATA, False)

        gre_dip = self.GRE_DIP1.addr_str
        gre_sip = self.GRE_SIP1.addr_str

        self.expected_packet[S.IP].dst = gre_dip
        self.expected_packet[S.IP].src = gre_sip

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, out_slice, out_ifg, out_pif)

        self.topology.vrf2.hld_obj.delete_ipv4_route(self.ovl_dip_prefix32)

    def _test_gre_port_decap_acl_inner_header(self):
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)

        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        DIP = T.ipv4_addr(self.OVL_IP_PACKET_SIP)
        k = []
        f = sdk.la_acl_field()
        f.type = sdk.la_acl_field_type_e_IPV4_DIP
        f.val.ipv4_dip.s_addr = DIP.to_num()
        f.mask.ipv4_dip.s_addr = 0xffffffff
        k.append(f)

        commands = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = True
        commands.append(action1)

        acl1.append(k, commands)
        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.GRE_HEADER / \
            self.PORT_DECAP_ACL_OVL_INPUT_IP / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            self.PORT_DECAP_OVL_EXPECTED_IP / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        ipv4_acls = []
        ipv4_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.gre_tunnel.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        self.input_packet, __ = U.enlarge_packet_to_min_length(input_packet_base)

        U.run_and_drop(self, self.device,
                       self.input_packet, T.TX_SLICE_REG,
                       T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.gre_tunnel.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    def _test_ip_over_ip_tunnel_port_multi_underlay_path(self):

        input_packet_base = \
            S.Ether(dst=self.OVL_IP_PACKET_DMAC,
                    src=self.OVL_IP_PACKET_SMAC) / \
            self.SINGLE_UNDERLAY_OVL_INPUT_IP / \
            S.TCP()

        ip_tunnel_dip = self.GRE_DIP1.addr_str
        ip_tunnel_sip = self.GRE_SIP1.addr_str

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str,
                    src=T.TX_L3_AC_EXT_MAC.addr_str) / \
            S.IP(dst=ip_tunnel_dip,
                 src=ip_tunnel_sip,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.SINGLE_UNDERLAY_OVL_EXPECTED_IP / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)
        (self.expected_packet, out_slice, out_ifg, out_pif) = self.calculate_ecmp_expected_output()

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3,
                          self.expected_packet, out_slice, out_ifg, out_pif)

    def _test_gre_port_encap_abf(self):
        self.ovl_dip_prefix_abf = self.ip_impl.build_prefix(self.OVL_DIP_ROUTE_ABF, length=24)
        self.topology.vrf2.hld_obj.add_ipv4_route(self.ovl_dip_prefix_abf, self.ovl_ecmp, self.PRIVATE_DATA, False)
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)

        k = []
        f = sdk.la_acl_field()
        f.type = sdk.la_acl_field_type_e_IPV4_DIP
        f.val.ipv4_dip.s_addr = sdk.LA_IPV4_ANY_IP.s_addr
        f.mask.ipv4_dip.s_addr = 0xffffffff
        k.append(f)

        commands = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_L3_DESTINATION
        action1.data.l3_dest = self.ovl_ecmp
        commands.append(action1)

        acl1.append(k, commands)

        ipv4_acls = []
        ipv4_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        input_packet_base = \
            S.Ether(dst=self.OVL_IP_PACKET_DMAC,
                    src=self.OVL_IP_PACKET_SMAC) / \
            self.ENCAP_QOS_OVL_INPUT_IP_ABF / \
            S.TCP()

        gre_dip = self.GRE_DIP.addr_str
        gre_sip = self.GRE_SIP.addr_str

        if decor.is_pacific():
            gre_dip = self.GRE_DIP1.addr_str
            gre_sip = self.GRE_SIP1.addr_str

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                    src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(dst=gre_dip,
                 src=gre_sip,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.GRE_HEADER / \
            self.ENCAP_QOS_OVL_EXPECTED_IP_ABF / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)
        (self.expected_packet, out_slice, out_ifg, out_pif) = self.calculate_ecmp_expected_output()

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, out_slice,
                          out_ifg, out_pif)

        self.topology.tx_l3_ac_def.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.device.destroy(acl_group)
        self.device.destroy(acl1)
        self.topology.vrf2.hld_obj.delete_ipv4_route(self.ovl_dip_prefix_abf)

    # Function to generate a GRE DIP entropy prefix mask
    def gre_dip_entropy_prefix_mask(self, prefix_length):
        return ((0xffffffff << (32 - prefix_length)) & 0xffffffff)

    # Function to generate a GRE DIP entropy value mask
    def gre_dip_entropy_value_mask(self, prefix_length):
        return ((1 << (32 - prefix_length)) - 1)

    # Function to generate a GRE DIP entropy prefix
    def gre_dip_entropy_prefix(self, dip, prefix_length):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = (dip.hld_obj.s_addr &
                              self.gre_dip_entropy_prefix_mask(prefix_length))
        prefix.length = prefix_length
        return prefix

    # Valid GRE DIP entropy prefix lengths and their associated
    # GRE DIP entropy mode.
    gre_dip_entropy_valid_prefix_lengths = {
        24: sdk.la_gre_port.la_gre_dip_entropy_mode_e_GRE_DIP_ENTROPY_24,
        28: sdk.la_gre_port.la_gre_dip_entropy_mode_e_GRE_DIP_ENTROPY_28,
        32: sdk.la_gre_port.la_gre_dip_entropy_mode_e_GRE_DIP_ENTROPY_NONE
    }

    def _test_gre_encap_dip_entropy_prefix_lengths(self):
        # Validate all GRE DIP entropy prefix lengths from /0 to /32
        for prefix_length in range(33):
            try:
                self.gre_tunnel.set_remote_ip_prefix(
                    self.gre_dip_entropy_prefix(self.GRE_DIP, prefix_length))
                self.assertTrue(prefix_length in
                                self.gre_dip_entropy_valid_prefix_lengths)
                self.assertEqual(self.gre_tunnel.get_dip_entropy_mode(),
                                 self.gre_dip_entropy_valid_prefix_lengths[
                                     prefix_length])
            except BaseException as status:
                self.assertEqual(status.args[0], sdk.la_status_e_E_INVAL)
                self.assertTrue(prefix_length not in
                                self.gre_dip_entropy_valid_prefix_lengths)

    def _test_gre_encap_dip_entropy_forwarding(self):
        # Number of flows tested per GRE DIP entropy prefix length
        flows = 10

        # Minimum number of unique entropy values expected in the
        # egress packets generated per GRE DIP entropy prefix length.
        min_unique_entropy_values = 3

        # Prepare input packet
        input_packet_base = \
            S.Ether(dst=self.OVL_IP_PACKET_DMAC,
                    src=self.OVL_IP_PACKET_SMAC) / \
            S.IP(dst=self.OVL_IP_PACKET_DIP,
                 src=self.OVL_IP_PACKET_SIP) / \
            S.TCP()

        # Prepare base expected packet
        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                    src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(dst=self.GRE_DIP.addr_str,
                 src=self.GRE_SIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            S.GRE() / \
            S.IP(dst=self.OVL_IP_PACKET_DIP,
                 src=self.OVL_IP_PACKET_SIP,
                 ttl=63) / \
            S.TCP()

        # Pad and set input and expected packets
        self.input_packet, self.expected_packet = \
            U.pad_input_and_output_packets(input_packet_base,
                                           expected_packet_base)

        for prefix_length in self.gre_dip_entropy_valid_prefix_lengths:
            # Generate GRE DIP entropy prefix mask, value mask, and
            # prefix for the current prefix length.
            prefix_mask = self.gre_dip_entropy_prefix_mask(prefix_length)
            entropy_mask = self.gre_dip_entropy_value_mask(prefix_length)
            gre_dip_prefix = self.gre_dip_entropy_prefix(self.GRE_DIP,
                                                         prefix_length)

            # Set tunnel remote IP prefix to the GRE DIP prefix and
            # validate the DIP entropy mode.
            self.gre_tunnel.set_remote_ip_prefix(gre_dip_prefix)
            self.assertEqual(self.gre_tunnel.get_dip_entropy_mode(),
                             self.gre_dip_entropy_valid_prefix_lengths[
                                 prefix_length])

            # List of entropy values being collected for the current
            # prefix length.
            output_entropy_values = []

            for packet_index in range(flows):
                # Increment destination port to influence load-balancing
                self.input_packet[S.TCP].dport += 1
                self.expected_packet[S.TCP].dport += 1

                # Send input packet and get egress packet
                egress_packet = U.run_and_get(self, self.device,
                                              self.input_packet, T.TX_SLICE_DEF,
                                              T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)[0]
                scapy_egress_packet = U.hex_to_scapy(egress_packet.packet)

                # Get the output GRE DIP from the egress packet and add the
                # entropy value in the output GRE DIP to the list of entropy
                # values being collected for the current prefix length.
                output_gre_dip = int(ipaddress.ip_address(
                                     scapy_egress_packet[S.IP].dst))
                output_entropy_values += [output_gre_dip & entropy_mask]

                # Verify that the input and output GRE DIP prefixes match
                self.assertEqual(output_gre_dip & prefix_mask,
                                 gre_dip_prefix.addr.s_addr)

                # Change the output GRE DIP in the expected packet to the actual
                # output GRE DIP and verify that the actual and expected packets
                # are identical.
                self.expected_packet[S.IP].dst = scapy_egress_packet[S.IP].dst
                U.assertEqualPackets(self, egress_packet.packet,
                                     U.scapy_to_hex(self.expected_packet))

            # Ideally, the output GRE DIP would be predicted by passing the
            # appropriate flow parameters from the ingress packet directly
            # to the load-balancing algorithm within the testcase, as done
            # on other platforms. Until this can be done in the SDK, verify
            # that there are a reasonable number of unique entropy values
            # among the egress packets for each prefix length.
            if (prefix_length < 32):
                self.assertGreaterEqual(len(set(output_entropy_values)),
                                        min_unique_entropy_values)
            else:
                self.assertEqual(len(set(output_entropy_values)), 1)

    def gre_port_multi_underlay_path_ecmp(self, mode=sdk.la_ip_tunnel_mode_e_ENCAP_DECAP):
        self.gre_tunnel = self.gre_port_setup(self.GRE_PORT_GID, mode, self.topology.vrf,
                                              self.GRE_SIP, self.GRE_DIP, self.topology.vrf2)
        self.gre_destination = self.device.create_ip_tunnel_destination(
            self.GRE_TUNNEL_DESTINATION_GID,
            self.gre_tunnel,
            self.topology.nh_l3_ac_reg.hld_obj)

        l3_port_impl = T.ip_l3_ac_base(self.topology)

        self.ecmp_group = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        for nh_num in range(self.NUM_OF_NH):
            nh = T.next_hop(
                self,
                self.device,
                self.NH_GID_BASE + nh_num,
                self.NH_DST_MAC_BASE.create_offset_mac(nh_num),
                l3_port_impl.tx_port)
            self.ecmp_group.add_member(nh.hld_obj)

        self.ovl_dip_prefix = self.ip_impl.build_prefix(self.OVL_DIP_ROUTE, length=24)
        if self.source_based_forwarding == self.SBF_TEST_DISABLED:
            self.topology.vrf2.hld_obj.add_ipv4_route(self.ovl_dip_prefix, self.gre_destination, self.PRIVATE_DATA, False)
        self.ovl_sip_prefix = self.ip_impl.build_prefix(self.OVL_SIP_ROUTE, length=24)
        self.topology.vrf2.hld_obj.add_ipv4_route(self.ovl_sip_prefix, self.ecmp_group, self.PRIVATE_DATA, False)
        self.setup_as_single_underlay_path = True

    def _test_gre_source_base_forwarding_encap_per_proto_counter(self):
        self.gre_port_single_underlay_path_SBF(True)
        self._test_gre_port_encap_per_proto_counter()

    def _test_gre_decap_scale(self, mode = sdk.la_ip_tunnel_mode_e_DECAP_ONLY):

        index = 1
        for vrf_idx in range(4):
            vrf_gid = VRF_BASE_GID + vrf_idx
            vrf = T.vrf(self, self.device, vrf_gid)
            for idx in range(16):
                SIP = '12.10.12.%s' % (idx)
                GRE_SIP = T.ipv4_addr(SIP)
                gre_port = T.gre_port(self, self.device,
                                      self.GRE_PORT_GID + index,
                                      mode,
                                      vrf,
                                      GRE_SIP,
                                      self.GRE_DIP,
                                      self.topology.vrf)

                gre_port.hld_obj.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)
                index += 1

        rd_def_my_ipv4 = sdk.la_resource_descriptor()
        rd_def_my_ipv4.m_index.slice_id = T.RX_SLICE
        rd_def_my_ipv4.m_resource_type = sdk.la_resource_descriptor.type_e_MY_IPV4_TABLE
        rd_def_my_ipv4_out = self.device.get_resource_usage(rd_def_my_ipv4)
        assert(rd_def_my_ipv4_out.used == 64)

        with self.assertRaises(sdk.ResourceException):
            vrf = T.vrf(self, self.device, 333)
            GRE_SIP = T.ipv4_addr('11.11.11.111')
            gre_port = T.gre_port(self, self.device,
                                  self.GRE_PORT_GID,
                                  mode,
                                  vrf,
                                  GRE_SIP,
                                  self.GRE_DIP,
                                  self.topology.vrf)
