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
from packet_test_utils import *
from collections import namedtuple
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import ip_test_base
import topology as T
from sdk_test_case_base import *

load_contrib('mpls')

# This test assumes that MPLS bottom-of-stack label is followed by Ether
bind_layers(MPLS, Ether, s=1)


class pwe_flood_base(sdk_test_case_base):

    PREFIX1_GID = 0x691
    PREFIX2_GID = 0x692
    PREFIX3_GID = 0x693
    PREFIX_RCY_GID = 0x698

    DA = T.mac_addr('be:ef:5d:35:8b:46')
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    RECYCLE_PORT_MAC = T.mac_addr('00:11:22:33:44:55')
    RCY_DST_MAC = T.mac_addr('07:66:77:88:99:aa')
    VLAN = 0xAB9

    PWE_TTL = 0xff  # Set by the SDK

    SYS_PORT_GID_BASE = 50
    AC_PORT_GID_BASE = 0x292

    LDP_LABEL1 = sdk.la_mpls_label()
    LDP_LABEL1.label = 0x64
    LDP_LABEL2 = sdk.la_mpls_label()
    LDP_LABEL2.label = 0x65
    LDP_LABEL3 = sdk.la_mpls_label()
    LDP_LABEL3.label = 0x66

    PWE_LOCAL_LABEL = sdk.la_mpls_label()
    PWE_LOCAL_LABEL.label = 0x62
    PWE_REMOTE_LABEL = sdk.la_mpls_label()
    PWE_REMOTE_LABEL.label = 0x63

    PWE_LOCAL_LABEL2 = sdk.la_mpls_label()
    PWE_LOCAL_LABEL2.label = 0x70
    PWE_REMOTE_LABEL2 = sdk.la_mpls_label()
    PWE_REMOTE_LABEL2.label = 0x71

    PWE_LOCAL_LABEL3 = sdk.la_mpls_label()
    PWE_LOCAL_LABEL3.label = 0x72
    PWE_REMOTE_LABEL3 = sdk.la_mpls_label()
    PWE_REMOTE_LABEL3.label = 0x73

    PWE_FLOW_LABEL = sdk.la_mpls_label()
    if (decor.is_pacific()):
        PWE_FLOW_LABEL.label = 0xce2b0
    else:
        PWE_FLOW_LABEL.label = 0xed0

    PWE_FLOW_LABEL_TTL = 0xff

    CW = sdk.la_mpls_label()
    CW.label = 0x0
    CW_TTL = 0x0

    RCY_LABEL = sdk.la_mpls_label()
    RCY_LABEL.label = 0xf0065

    RCY_LABEL2 = sdk.la_mpls_label()
    RCY_LABEL2.label = 0xf0066

    TE_TUNNEL1_GID = 0x391
    PRIMARY_TE_LABEL = sdk.la_mpls_label()
    PRIMARY_TE_LABEL.label = 0x76

    #DPE_GID = 0x1008
    #GP_LABEL = sdk.la_mpls_label()
    #BGP_LABEL.label = 0x77
    #VPN_LABEL = sdk.la_mpls_label()
    #VPN_LABEL.label = 0x78

    DIP = T.ipv4_addr('82.81.95.250')
    SIP = T.ipv4_addr('12.10.12.10')

    PWE_PORT_GID = 16385
    PWE_GID = 0x89

    ip_impl_class = ip_test_base.ipv4_test_base
    l3_port_impl_class = T.ip_l3_ac_base
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    SWITCH_BASE_GID = 0x10

    phy_port = namedtuple('phy_port', 'slice ifg first_serdes last_serdes sys_port_gid ac_port_gid')
    ports = [phy_port(0, 0, 4, 5, SYS_PORT_GID_BASE, AC_PORT_GID_BASE),
             phy_port(3, 1, 8, 9, SYS_PORT_GID_BASE + 1, AC_PORT_GID_BASE + 1)]

    def setUp(self):
        super().setUp()

        self.ac_profile = T.ac_profile(self, self.device)

        self.ip_impl = self.ip_impl_class()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)

        self.vrf = T.vrf(self, self.device, 0x3ee)

        # create recycle port and next hop.
        self.create_recycle_ac_port()

        self.add_default_route()

        # Create lsr path
        self.lsr = self.device.get_lsr()

        # Create l2 ac
        self.create_ac_ports()

        # create SW
        self.sw1 = T.switch(self, self.device, self.SWITCH_BASE_GID)
        self.ac_ports[0].hld_obj.attach_to_switch(self.sw1.hld_obj)

        # create l2_mc_Group
        self.mc_group = self.device.create_l2_multicast_group(0x13, sdk.la_replication_paradigm_e_EGRESS)
        self.assertIsNotNone(self.mc_group)
        self.l2_dest = None

    def create_pwe_port(self, port_id, pwe_local_label, pwe_remote_label, pwe_gid, l3_destination, rcy_label):

        self.lsr.add_route(rcy_label, self.topology.vrf.hld_obj, l3_destination, self.PRIVATE_DATA)

        pwe_port = T.l2_pwe_port(self, self.device, port_id, pwe_local_label, pwe_remote_label, pwe_gid, l3_destination)
        pwe_port.hld_obj.set_ac_profile_for_pwe(self.ac_profile.hld_obj)

        pwe_port.hld_obj.set_pwe_multicast_recycle_lsp_properties(rcy_label, self.recycle_nh)
        pwe_port.hld_obj.attach_to_switch(self.sw1.hld_obj)

        return pwe_port

    def create_ldp_mpls_nh(self):
        self.pfx_obj_vpls = T.prefix_object(self, self.device, self.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)
        self.assertNotEqual(self.pfx_obj_vpls.hld_obj, None)

        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL1)

        self.pfx_obj_vpls.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj,
                                                        lsp_labels,
                                                        None,
                                                        sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsp_labels = []
        lsp_labels.append(self.RCY_LABEL)

        self.pfx_obj_vpls.hld_obj.set_nh_lsp_properties(self.recycle_nh,
                                                        lsp_labels,
                                                        None,
                                                        sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

    def create_ldp_mpls_nh2(self):
        # Second prefix object
        self.pfx_obj_vpls2 = T.prefix_object(self, self.device, self.PREFIX2_GID, self.l3_port_impl.def_nh.hld_obj)
        self.assertNotEqual(self.pfx_obj_vpls2.hld_obj, None)

        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL2)

        self.pfx_obj_vpls2.hld_obj.set_nh_lsp_properties(self.l3_port_impl.def_nh.hld_obj,
                                                         lsp_labels,
                                                         None,
                                                         sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsp_labels = []
        lsp_labels.append(self.RCY_LABEL2)

        self.pfx_obj_vpls2.hld_obj.set_nh_lsp_properties(self.recycle_nh,
                                                         lsp_labels,
                                                         None,
                                                         sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

    def create_ldp_mpls_nh3(self):
        self.pfx_obj_vpls3 = T.prefix_object(self, self.device, self.PREFIX3_GID, self.l3_port_impl.ext_nh.hld_obj)
        self.assertNotEqual(self.pfx_obj_vpls3.hld_obj, None)

        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL3)

        self.pfx_obj_vpls3.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj,
                                                         lsp_labels,
                                                         None,
                                                         sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsp_labels = []
        lsp_labels.append(self.RCY_LABEL)

        self.pfx_obj_vpls3.hld_obj.set_nh_lsp_properties(self.recycle_nh,
                                                         lsp_labels,
                                                         None,
                                                         sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

    def create_ldp_tenh_to_mpls(self, implicit_null=False):
        self.te_tunnel = T.ldp_over_te_tunnel(self, self.device, self.TE_TUNNEL1_GID, self.l3_port_impl.reg_nh.hld_obj)

        self.te_counter = None
        te_labels = []
        if not implicit_null:
            te_labels.append(self.PRIMARY_TE_LABEL)
        self.te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, te_labels, self.te_counter)
        self.te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        self.pfx_obj_vpls = T.prefix_object(self, self.device, self.PREFIX1_GID, self.te_tunnel.hld_obj)

        lsp_counter = None
        lsp_labels = []
        if not implicit_null:
            lsp_labels.append(self.LDP_LABEL1)

        self.pfx_obj_vpls.hld_obj.set_te_tunnel_lsp_properties(self.te_tunnel.hld_obj, lsp_labels, lsp_counter)

        lsp_labels = []
        lsp_labels.append(self.RCY_LABEL)

        self.pfx_obj_vpls.hld_obj.set_nh_lsp_properties(self.recycle_nh,
                                                        lsp_labels,
                                                        None,
                                                        sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

    def create_ac_port(self, num):
        self.eth_ports.insert(
            num,
            T.ethernet_port(
                self,
                self.device,
                self.ports[num].slice,
                self.ports[num].ifg,
                self.ports[num].sys_port_gid,
                self.ports[num].first_serdes,
                self.ports[num].last_serdes))
        self.eth_ports[num].set_ac_profile(self.ac_profile)
        self.ac_ports.insert(num,
                             T.l2_ac_port(self, self.device,
                                          self.ports[num].ac_port_gid,
                                          self.topology.filter_group_def,
                                          None,
                                          self.eth_ports[num],
                                          None, self.VLAN, 0x0))

        counter_set_size = 1
        l2_ingress_counter = self.device.create_counter(counter_set_size)
        self.ac_ports[num].hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, l2_ingress_counter)

        l2_egress_counter = self.device.create_counter(counter_set_size)
        self.ac_ports[num].hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, l2_egress_counter)

    def create_ac_ports(self):
        self.eth_ports = []
        self.ac_ports = []

        for i in range(1):
            self.create_ac_port(i)

    def create_recycle_ac_port(self):
        # MATILDA_SAVE -- need review
        # if non of the odd slices are active, than crush.
        default_slice = T.get_device_slice(1)
        slice_for_recycle = T.choose_active_slices(self.device, default_slice, [1, 3, 5])
        self.recycle_sys_port = self.topology.recycle_ports[slice_for_recycle].sys_port.hld_obj

        self.recycle_eth_port = self.device.create_ethernet_port(
            self.recycle_sys_port,
            sdk.la_ethernet_port.port_type_e_AC)
        self.recycle_eth_port.set_ac_profile(self.topology.ac_profile_def.hld_obj)

        self.recycle_l3_ac_port = self.device.create_l3_ac_port(
            T.RX_L3_AC_GID + 0x200,
            self.recycle_eth_port,
            0x567,
            0,
            self.RECYCLE_PORT_MAC.hld_obj,
            self.topology.vrf.hld_obj,
            self.topology.ingress_qos_profile_def.hld_obj,
            self.topology.egress_qos_profile_def.hld_obj)

        self.recycle_l3_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.recycle_l3_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)

        self.recycle_nh = self.device.create_next_hop(
            T.NH_L3_AC_REG_GID + 0x100,
            self.RECYCLE_PORT_MAC.hld_obj,
            self.recycle_l3_ac_port,
            sdk.la_next_hop.nh_type_e_NORMAL)
        # self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)

        # Set the vlan for the tx side for l3 ac
        tag = sdk.la_vlan_tag_t()
        tag.tpid = 0x8100
        tag.tci.fields.pcp = 0
        tag.tci.fields.dei = 0
        tag.tci.fields.vid = 0x567

        self.recycle_l3_ac_port.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh, self.PRIVATE_DATA_DEFAULT)

    def set_flood_destination(self, destinations):
        for index, destination in enumerate(destinations):
            self.mc_group.add(destination[0], destination[1])
        self.sw1.hld_obj.set_flood_destination(self.mc_group)

    def remove_mc_group(self, destinations):
        for index, destination in enumerate(destinations):
            self.mc_group.remove(destination[0])

    def tearDown(self):
        self.remove_mc_group(self.l2_dest)
        self.destroy_ports()
        self.ac_profile.destroy()
        self.sw1.destroy()
        super().tearDown()

    def destroy_ports(self):
        for pwe_port in self.pwe_ports:
            pwe_port.hld_obj.detach()

        for ac_port in self.ac_ports:
            ac_port.hld_obj.detach()

        for ac_port in self.ac_ports:
            ac_port.destroy()

        for eth_port in self.eth_ports:
            eth_port.destroy()

        for pwe_port in self.pwe_ports:
            pwe_port.destroy()

    def _test_pwe_encap_flood(self):
        INPUT_PACKET_BASE = \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN, type=Ethertype.IPv4.value) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=Ethertype.MPLS.value) / \
            MPLS(label=self.LDP_LABEL1.label, ttl=self.PWE_TTL - 1) / \
            MPLS(label=self.PWE_REMOTE_LABEL.label, ttl=self.PWE_TTL, s=1) / \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN, type=U.Ethertype.IPv4.value) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
        EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

        self.create_ldp_mpls_nh()

        self.pwe_ports = []
        self.pwe_ports.append(self.create_pwe_port(self.PWE_PORT_GID, self.PWE_LOCAL_LABEL,
                                                   self.PWE_REMOTE_LABEL, self.PWE_GID, self.pfx_obj_vpls.hld_obj,
                                                   self.RCY_LABEL))

        self.l2_dest = [[self.pwe_ports[0].hld_obj, self.recycle_sys_port],
                        [self.ac_ports[0].hld_obj, self.eth_ports[0].sys_port.hld_obj]]
        self.set_flood_destination(self.l2_dest)

        self.mc_group.remove(self.pwe_ports[0].hld_obj)
        self.mc_group.add(self.pwe_ports[0].hld_obj, self.recycle_sys_port)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, self.ports[0].slice, self.ports[0].ifg, self.ports[0].first_serdes,
                          EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3)

    def _test_pwe_decap_flood(self):
        INPUT_PACKET_BASE = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.SA.addr_str, type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
            MPLS(label=self.PWE_LOCAL_LABEL.label, ttl=self.PWE_TTL) / \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN) / \
            IP()

        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN) / \
            IP()

        INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
        EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

        self.create_ldp_mpls_nh()

        self.pwe_ports = []
        self.pwe_ports.append(self.create_pwe_port(self.PWE_PORT_GID, self.PWE_LOCAL_LABEL,
                                                   self.PWE_REMOTE_LABEL, self.PWE_GID, self.pfx_obj_vpls.hld_obj,
                                                   self.RCY_LABEL))

        self.l2_dest = [[self.ac_ports[0].hld_obj, self.eth_ports[0].sys_port.hld_obj],
                        [self.pwe_ports[0].hld_obj, self.eth_ports[0].sys_port.hld_obj]]
        self.set_flood_destination(self.l2_dest)
        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          EXPECTED_OUTPUT_PACKET, self.ports[0].slice, self.ports[0].ifg, self.ports[0].first_serdes)

    def _test_pwe_encap_flood_multiple_pwe(self):
        INPUT_PACKET_BASE = \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN, type=Ethertype.IPv4.value) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=Ethertype.MPLS.value) / \
            MPLS(label=self.LDP_LABEL1.label, ttl=self.PWE_TTL - 1) / \
            MPLS(label=self.PWE_REMOTE_LABEL.label, ttl=self.PWE_TTL, s=1) / \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN, type=U.Ethertype.IPv4.value) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        EXPECTED_OUTPUT_PACKET_BASE2 = \
            Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str, type=Ethertype.MPLS.value) / \
            MPLS(label=self.LDP_LABEL2.label, ttl=self.PWE_TTL - 1) / \
            MPLS(label=self.PWE_REMOTE_LABEL2.label, ttl=self.PWE_TTL, s=1) / \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN, type=U.Ethertype.IPv4.value) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
        EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
        EXPECTED_OUTPUT_PACKET2 = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE2, BASE_INPUT_PACKET_PAYLOAD_SIZE)

        self.create_ldp_mpls_nh()
        self.create_ldp_mpls_nh2()

        self.pwe_ports = []
        self.pwe_ports.append(self.create_pwe_port(self.PWE_PORT_GID, self.PWE_LOCAL_LABEL,
                                                   self.PWE_REMOTE_LABEL, self.PWE_GID, self.pfx_obj_vpls.hld_obj,
                                                   self.RCY_LABEL))

        self.pwe_ports.append(self.create_pwe_port(self.PWE_PORT_GID + 1, self.PWE_LOCAL_LABEL2,
                                                   self.PWE_REMOTE_LABEL2, self.PWE_GID + 1, self.pfx_obj_vpls2.hld_obj,
                                                   self.RCY_LABEL2))

        self.l2_dest = [[self.pwe_ports[0].hld_obj, self.recycle_sys_port],
                        [self.pwe_ports[1].hld_obj, self.recycle_sys_port],
                        [self.ac_ports[0].hld_obj, self.eth_ports[0].sys_port.hld_obj]]
        self.set_flood_destination(self.l2_dest)

        ingress_packets = []
        expected_packets = []

        ingress_packets.append({
            'data': INPUT_PACKET,
            'slice': self.ports[0].slice,
            'ifg': self.ports[0].ifg,
            'pif': self.ports[0].first_serdes})
        expected_packets.append({
            'data': EXPECTED_OUTPUT_PACKET,
            'slice': T.TX_SLICE_REG,
            'ifg': T.TX_IFG_REG,
            'pif': T.FIRST_SERDES_L3})
        expected_packets.append({
            'data': EXPECTED_OUTPUT_PACKET2,
            'slice': T.TX_SLICE_DEF,
            'ifg': T.TX_IFG_DEF,
            'pif': T.FIRST_SERDES_L3})

        U.run_and_compare_list(self, self.device, ingress_packets[0], expected_packets)

    def _test_flood_to_ac_pwe(self):
        INPUT_PACKET_BASE = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.SA.addr_str, type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
            MPLS(label=self.PWE_LOCAL_LABEL.label, ttl=self.PWE_TTL) / \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        EXPECTED_OUTPUT_PACKET_BASE2 = \
            Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str, type=Ethertype.MPLS.value) / \
            MPLS(label=self.LDP_LABEL2.label, ttl=self.PWE_TTL - 1) / \
            MPLS(label=self.PWE_REMOTE_LABEL2.label, ttl=self.PWE_TTL, s=1) / \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN, type=U.Ethertype.IPv4.value) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
        EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
        EXPECTED_OUTPUT_PACKET2 = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE2, BASE_INPUT_PACKET_PAYLOAD_SIZE)

        ingress_packets = []
        expected_packets = []

        ingress_packets.append({
            'data': INPUT_PACKET,
            'slice': T.RX_SLICE,
            'ifg': T.RX_IFG,
            'pif': T.FIRST_SERDES})
        expected_packets.append({
            'data': EXPECTED_OUTPUT_PACKET,
            'slice': self.ports[0].slice,
            'ifg': self.ports[0].ifg,
            'pif': self.ports[0].first_serdes})
        expected_packets.append({
            'data': EXPECTED_OUTPUT_PACKET2,
            'slice': T.TX_SLICE_DEF,
            'ifg': T.TX_IFG_DEF,
            'pif': T.FIRST_SERDES_L3})

        self.create_ldp_mpls_nh()
        self.create_ldp_mpls_nh2()

        self.pwe_ports = []
        self.pwe_ports.append(self.create_pwe_port(self.PWE_PORT_GID, self.PWE_LOCAL_LABEL,
                                                   self.PWE_REMOTE_LABEL, self.PWE_GID, self.pfx_obj_vpls.hld_obj,
                                                   self.RCY_LABEL))

        self.pwe_ports.append(self.create_pwe_port(self.PWE_PORT_GID + 1, self.PWE_LOCAL_LABEL2,
                                                   self.PWE_REMOTE_LABEL2, self.PWE_GID + 1, self.pfx_obj_vpls2.hld_obj,
                                                   self.RCY_LABEL2))

        self.l2_dest = [[self.pwe_ports[0].hld_obj, self.recycle_sys_port],
                        [self.pwe_ports[1].hld_obj, self.recycle_sys_port],
                        [self.ac_ports[0].hld_obj, self.eth_ports[0].sys_port.hld_obj]]
        self.set_flood_destination(self.l2_dest)
        U.run_and_compare_list(self, self.device, ingress_packets[0], expected_packets)

    def _test_pwe_encap_flood_multiple_pwe_flow_label_cw(self):
        INPUT_PACKET_BASE = \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN, type=Ethertype.IPv4.value) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=Ethertype.MPLS.value) / \
            MPLS(label=self.LDP_LABEL1.label, ttl=self.PWE_TTL - 1) / \
            MPLS(label=self.PWE_REMOTE_LABEL.label, ttl=self.PWE_TTL, s=1) / \
            PseudowireControlWord() / \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN, type=U.Ethertype.IPv4.value) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        EXPECTED_OUTPUT_PACKET_BASE2 = \
            Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str, type=Ethertype.MPLS.value) / \
            MPLS(label=self.LDP_LABEL2.label, ttl=self.PWE_TTL - 1) / \
            MPLS(label=self.PWE_REMOTE_LABEL2.label, ttl=self.PWE_TTL) / \
            MPLS(label=self.PWE_FLOW_LABEL.label, ttl=self.PWE_FLOW_LABEL_TTL, s=1) / \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN, type=U.Ethertype.IPv4.value) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
        EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
        EXPECTED_OUTPUT_PACKET2 = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE2, BASE_INPUT_PACKET_PAYLOAD_SIZE)

        self.create_ldp_mpls_nh()
        self.create_ldp_mpls_nh2()

        self.pwe_ports = []
        self.pwe_ports.append(self.create_pwe_port(self.PWE_PORT_GID, self.PWE_LOCAL_LABEL,
                                                   self.PWE_REMOTE_LABEL, self.PWE_GID, self.pfx_obj_vpls.hld_obj,
                                                   self.RCY_LABEL))

        self.pwe_ports.append(self.create_pwe_port(self.PWE_PORT_GID + 1, self.PWE_LOCAL_LABEL2,
                                                   self.PWE_REMOTE_LABEL2, self.PWE_GID + 1, self.pfx_obj_vpls2.hld_obj,
                                                   self.RCY_LABEL2))

        self.pwe_ports[0].hld_obj.set_control_word_enabled(True)
        self.pwe_ports[1].hld_obj.set_flow_label_enabled(True)

        self.l2_dest = [[self.pwe_ports[0].hld_obj, self.recycle_sys_port],
                        [self.pwe_ports[1].hld_obj, self.recycle_sys_port],
                        [self.ac_ports[0].hld_obj, self.eth_ports[0].sys_port.hld_obj]]

        self.set_flood_destination(self.l2_dest)

        ingress_packets = []
        expected_packets = []

        ingress_packets.append({
            'data': INPUT_PACKET,
            'slice': self.ports[0].slice,
            'ifg': self.ports[0].ifg,
            'pif': self.ports[0].first_serdes})
        expected_packets.append({
            'data': EXPECTED_OUTPUT_PACKET,
            'slice': T.TX_SLICE_REG,
            'ifg': T.TX_IFG_REG,
            'pif': T.FIRST_SERDES_L3})
        expected_packets.append({
            'data': EXPECTED_OUTPUT_PACKET2,
            'slice': T.TX_SLICE_DEF,
            'ifg': T.TX_IFG_DEF,
            'pif': T.FIRST_SERDES_L3})

        U.run_and_compare_list(self, self.device, ingress_packets[0], expected_packets)

    def _test_pwe_flood_change_l3_dest(self):
        INPUT_PACKET_BASE = \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN, type=Ethertype.IPv4.value) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=Ethertype.MPLS.value) / \
            MPLS(label=self.LDP_LABEL1.label, ttl=self.PWE_TTL - 1) / \
            MPLS(label=self.PWE_REMOTE_LABEL.label, ttl=self.PWE_TTL, s=1) / \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN, type=U.Ethertype.IPv4.value) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        EXPECTED_OUTPUT_PACKET_BASE2 = \
            Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str, type=Ethertype.MPLS.value) / \
            MPLS(label=self.LDP_LABEL3.label, ttl=self.PWE_TTL - 1) / \
            MPLS(label=self.PWE_REMOTE_LABEL.label, ttl=self.PWE_TTL, s=1) / \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN, type=U.Ethertype.IPv4.value) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
        EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
        EXPECTED_OUTPUT_PACKET2 = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE2, BASE_INPUT_PACKET_PAYLOAD_SIZE)

        self.create_ldp_mpls_nh()

        self.pwe_ports = []
        self.pwe_ports.append(self.create_pwe_port(self.PWE_PORT_GID, self.PWE_LOCAL_LABEL,
                                                   self.PWE_REMOTE_LABEL, self.PWE_GID, self.pfx_obj_vpls.hld_obj,
                                                   self.RCY_LABEL))
        self.create_ldp_mpls_nh3()

        self.l2_dest = [[self.pwe_ports[0].hld_obj, self.recycle_sys_port],
                        [self.ac_ports[0].hld_obj, self.eth_ports[0].sys_port.hld_obj]]

        self.set_flood_destination(self.l2_dest)
        U.run_and_compare(self, self.device,
                          INPUT_PACKET, self.ports[0].slice, self.ports[0].ifg, self.ports[0].first_serdes,
                          EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3)

        self.pwe_ports[0].hld_obj.set_l3_destination(self.pfx_obj_vpls3.hld_obj)
        self.lsr.modify_route(self.RCY_LABEL, self.pfx_obj_vpls3.hld_obj)
        self.mc_group.remove(self.pwe_ports[0].hld_obj)
        self.mc_group.add(self.pwe_ports[0].hld_obj, self.recycle_sys_port)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, self.ports[0].slice, self.ports[0].ifg, self.ports[0].first_serdes,
                          EXPECTED_OUTPUT_PACKET2, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3)

    def _test_pwe_force_flood_enable(self):
        INPUT_PACKET_BASE = \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN, type=Ethertype.IPv4.value) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=Ethertype.MPLS.value) / \
            MPLS(label=self.LDP_LABEL1.label, ttl=self.PWE_TTL) / \
            MPLS(label=self.PWE_REMOTE_LABEL.label, ttl=self.PWE_TTL, s=1) / \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN, type=U.Ethertype.IPv4.value) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        EXPECTED_OUTPUT_PACKET_BASE2 = \
            Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str, type=Ethertype.MPLS.value) / \
            MPLS(label=self.LDP_LABEL2.label, ttl=self.PWE_TTL - 1) / \
            MPLS(label=self.PWE_REMOTE_LABEL2.label, ttl=self.PWE_TTL, s=1) / \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN, type=U.Ethertype.IPv4.value) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
        EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
        EXPECTED_OUTPUT_PACKET2 = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE2, BASE_INPUT_PACKET_PAYLOAD_SIZE)

        self.create_ldp_mpls_nh()
        self.create_ldp_mpls_nh2()

        self.pwe_ports = []
        self.pwe_ports.append(self.create_pwe_port(self.PWE_PORT_GID, self.PWE_LOCAL_LABEL,
                                                   self.PWE_REMOTE_LABEL, self.PWE_GID, self.pfx_obj_vpls.hld_obj,
                                                   self.RCY_LABEL))

        self.pwe_ports.append(self.create_pwe_port(self.PWE_PORT_GID + 1, self.PWE_LOCAL_LABEL2,
                                                   self.PWE_REMOTE_LABEL2, self.PWE_GID + 1, self.pfx_obj_vpls2.hld_obj,
                                                   self.RCY_LABEL2))

        self.l2_dest = [[self.pwe_ports[0].hld_obj, self.recycle_sys_port],
                        [self.pwe_ports[1].hld_obj, self.recycle_sys_port],
                        [self.ac_ports[0].hld_obj, self.eth_ports[0].sys_port.hld_obj]]
        self.set_flood_destination(self.l2_dest)

        self.sw1.hld_obj.set_mac_entry(self.DA.hld_obj, self.pwe_ports[0].hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, self.ports[0].slice, self.ports[0].ifg, self.ports[0].first_serdes,
                          EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3)

        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=Ethertype.MPLS.value) / \
            MPLS(label=self.LDP_LABEL1.label, ttl=self.PWE_TTL - 1) / \
            MPLS(label=self.PWE_REMOTE_LABEL.label, ttl=self.PWE_TTL, s=1) / \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN, type=U.Ethertype.IPv4.value) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)
        EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

        self.sw1.hld_obj.set_force_flood_mode(True)

        ingress_packets = []
        expected_packets = []

        ingress_packets.append({
            'data': INPUT_PACKET,
            'slice': self.ports[0].slice,
            'ifg': self.ports[0].ifg,
            'pif': self.ports[0].first_serdes})
        expected_packets.append({
            'data': EXPECTED_OUTPUT_PACKET,
            'slice': T.TX_SLICE_REG,
            'ifg': T.TX_IFG_REG,
            'pif': T.FIRST_SERDES_L3})
        expected_packets.append({
            'data': EXPECTED_OUTPUT_PACKET2,
            'slice': T.TX_SLICE_DEF,
            'ifg': T.TX_IFG_DEF,
            'pif': T.FIRST_SERDES_L3})

        U.run_and_compare_list(self, self.device, ingress_packets[0], expected_packets)

    def _test_pw_flood_ldp_tenh(self):
        INPUT_PACKET_BASE = \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN, type=Ethertype.IPv4.value) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=Ethertype.MPLS.value) / \
            MPLS(label=self.PRIMARY_TE_LABEL.label, ttl=self.PWE_TTL - 1) / \
            MPLS(label=self.LDP_LABEL1.label, ttl=self.PWE_TTL - 1) / \
            MPLS(label=self.PWE_REMOTE_LABEL.label, ttl=self.PWE_TTL, s=1) / \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN, type=U.Ethertype.IPv4.value) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
        EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

        self.create_ldp_tenh_to_mpls()

        self.pwe_ports = []
        self.pwe_ports.append(self.create_pwe_port(self.PWE_PORT_GID, self.PWE_LOCAL_LABEL,
                                                   self.PWE_REMOTE_LABEL, self.PWE_GID, self.pfx_obj_vpls.hld_obj,
                                                   self.RCY_LABEL))

        self.l2_dest = [[self.pwe_ports[0].hld_obj, self.recycle_sys_port],
                        [self.ac_ports[0].hld_obj, self.eth_ports[0].sys_port.hld_obj]]
        self.set_flood_destination(self.l2_dest)
        U.run_and_compare(self, self.device,
                          INPUT_PACKET, self.ports[0].slice, self.ports[0].ifg, self.ports[0].first_serdes,
                          EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3)

    def _test_pw_flood_ldp_tenh_implicit_null(self):
        INPUT_PACKET_BASE = \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN, type=Ethertype.IPv4.value) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=Ethertype.MPLS.value) / \
            MPLS(label=self.PWE_REMOTE_LABEL.label, ttl=self.PWE_TTL, s=1) / \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN, type=U.Ethertype.IPv4.value) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
        EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

        self.create_ldp_tenh_to_mpls(True)

        self.pwe_ports = []
        self.pwe_ports.append(self.create_pwe_port(self.PWE_PORT_GID, self.PWE_LOCAL_LABEL,
                                                   self.PWE_REMOTE_LABEL, self.PWE_GID, self.pfx_obj_vpls.hld_obj,
                                                   self.RCY_LABEL))

        self.l2_dest = [[self.pwe_ports[0].hld_obj, self.recycle_sys_port],
                        [self.ac_ports[0].hld_obj, self.eth_ports[0].sys_port.hld_obj]]
        self.set_flood_destination(self.l2_dest)
        U.run_and_compare(self, self.device,
                          INPUT_PACKET, self.ports[0].slice, self.ports[0].ifg, self.ports[0].first_serdes,
                          EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3)

    def _test_pew_flood_pwe_shg_drop(self):
        INPUT_PACKET_BASE = \
            Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.SA.addr_str, type=U.Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
            MPLS(label=self.PWE_LOCAL_LABEL.label, ttl=self.PWE_TTL) / \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str, type=Ethertype.MPLS.value) / \
            MPLS(label=self.LDP_LABEL2.label, ttl=self.PWE_TTL - 1) / \
            MPLS(label=self.PWE_REMOTE_LABEL2.label, ttl=self.PWE_TTL, s=1) / \
            Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN, type=U.Ethertype.IPv4.value) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.PWE_TTL)

        INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
        EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

        self.create_ldp_mpls_nh()
        self.create_ldp_mpls_nh2()

        self.pwe_ports = []
        self.pwe_ports.append(self.create_pwe_port(self.PWE_PORT_GID, self.PWE_LOCAL_LABEL,
                                                   self.PWE_REMOTE_LABEL, self.PWE_GID, self.pfx_obj_vpls.hld_obj,
                                                   self.RCY_LABEL))

        self.pwe_ports.append(self.create_pwe_port(self.PWE_PORT_GID + 1, self.PWE_LOCAL_LABEL2,
                                                   self.PWE_REMOTE_LABEL2, self.PWE_GID + 1, self.pfx_obj_vpls2.hld_obj,
                                                   self.RCY_LABEL2))

        self.grp1 = T.filter_group(self, self.device)
        # Deny traffic
        self.grp1.hld_obj.set_filtering_mode(self.grp1.hld_obj, True)
        self.pwe_ports[0].hld_obj.set_filter_group(self.grp1.hld_obj)
        self.pwe_ports[1].hld_obj.set_filter_group(self.grp1.hld_obj)

        self.l2_dest = [[self.pwe_ports[0].hld_obj, self.recycle_sys_port],
                        [self.pwe_ports[1].hld_obj, self.recycle_sys_port]]
        self.set_flood_destination(self.l2_dest)
        U.run_and_drop(self, self.device, INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Allow traffic
        self.grp1.hld_obj.set_filtering_mode(self.grp1.hld_obj, False)
        U.run_and_compare(self, self.device, INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          EXPECTED_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3)
