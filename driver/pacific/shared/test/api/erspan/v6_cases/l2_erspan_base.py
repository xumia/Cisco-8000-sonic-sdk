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

import nplapicli
import ip_test_base
import packet_test_utils as U
import packet_test_defs as P
import uut_provider as UUT_P
import scapy.all as S
import topology as T
from erspan_base import *

IN_SLICE = T.get_device_slice(2)
IN_IFG = 0
IN_SERDES_FIRST = T.get_device_first_serdes(4)
IN_SERDES_LAST = IN_SERDES_FIRST + 1

OUT_SLICE = T.get_device_slice(4)
OUT_IFG = T.get_device_ifg(1)
OUT_SERDES_FIRST = T.get_device_out_first_serdes(8)
OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

OUT_SLICE1 = T.get_device_slice(1)
OUT_IFG1 = 0
OUT_SERDES_FIRST1 = T.get_device_out_next_first_serdes(12)
OUT_SERDES_LAST1 = OUT_SERDES_FIRST1 + 1

SYS_PORT_GID_BASE = 23
AC_PORT_GID_BASE = 10

SWITCH_GID = 100

DST_MAC = "ca:fe:ca:fe:ca:fe"
SRC_MAC = "de:ad:de:ad:de:ad"
VLAN = 0xAB9

MC_GROUP_GID = 0x13

MC_GROUP_ADDR = T.ipv4_addr('225.1.2.3')


class l2_erspan_base(erspan_base):

    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl = ip_test_base.ipv4_test_base

    def setUp(self):
        super().setUp()
        # MATILDA_SAVE -- need review
        global IN_SLICE, OUT_SLICE, OUT_SLICE1
        IN_SLICE = T.choose_active_slices(self.device, IN_SLICE, [2, 3])
        OUT_SLICE = T.choose_active_slices(self.device, OUT_SLICE, [4, 1])
        OUT_SLICE1 = T.choose_active_slices(self.device, OUT_SLICE, [1, 5])
        # recall create_packets() after changing the slices
        self.create_packets()

    def create_l2_topology(self):
        self.sw1 = T.switch(self, self.device, SWITCH_GID)
        self.ac_profile = T.ac_profile(self, self.device)

        # Add 'cafecafecafe' to the MAC table, going to AC port 2
        self.dest_mac = T.mac_addr(DST_MAC)

        self.eth_port1 = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, SYS_PORT_GID_BASE, IN_SERDES_FIRST, IN_SERDES_LAST)
        self.eth_port1.set_ac_profile(self.ac_profile)
        self.ac_port1 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port1,
            None,
            VLAN,
            0x0)

        self.eth_port2 = T.ethernet_port(
            self,
            self.device,
            OUT_SLICE,
            OUT_IFG,
            SYS_PORT_GID_BASE + 1,
            OUT_SERDES_FIRST,
            OUT_SERDES_LAST)
        self.eth_port2.set_ac_profile(self.ac_profile)
        self.ac_port2 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 1,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port2,
            self.dest_mac,
            VLAN,
            0x0)

    def create_packets(self):
        self.in_packet, pad_len = \
            U.enlarge_packet_to_min_length(S.Ether(dst=DST_MAC, src=SRC_MAC, type=U.Ethertype.Dot1Q.value) /
                                           S.Dot1Q(vlan=VLAN) /
                                           S.IP() / TCP())

        self.out_packet = \
            U.add_payload(S.Ether(dst=DST_MAC, src=SRC_MAC, type=U.Ethertype.Dot1Q.value) /
                          S.Dot1Q(vlan=VLAN) /
                          S.IP() / TCP(), pad_len)

        punt_egr_packets = self.device.get_bool_property(sdk.la_device_property_e_TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST)

        self.set_rx_slice_and_inject_header(IN_SLICE, IN_IFG)
        self.INJECT_UP_STD_HEADER[UUT_P.INJECT_UP_STD_LAYER_INDEX].pif_id = IN_SERDES_FIRST

        if (punt_egr_packets is False):
            span_packet_base = \
                S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str,
                        type=U.Ethertype.IPv6.value) / \
                S.IPv6(src=TUNNEL_SOURCE.addr_str,
                       dst=TUNNEL_DEST.addr_str,
                       hlim=TUNNEL_TTL,
                       tc=TUNNEL_DSCP << 2,
                       nh=sdk.la_l4_protocol_e_GRE, plen=76) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II, seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=3) / \
                S.Ether(dst=DST_MAC, src=SRC_MAC, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=VLAN) / S.IP() / S.TCP()

            new_span_packet_base = \
                S.Ether(dst=NEW_DEST_MAC.addr_str, src=NEW_SOURCE_MAC.addr_str,
                        type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=EGRESS_VLAN) / \
                S.IPv6(src=NEW_TUNNEL_SOURCE.addr_str,
                       dst=NEW_TUNNEL_DEST.addr_str,
                       hlim=NEW_TUNNEL_TTL,
                       tc=NEW_TUNNEL_DSCP << 2,
                       nh=sdk.la_l4_protocol_e_GRE, plen=76) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II, seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=3) / \
                S.Ether(dst=DST_MAC, src=SRC_MAC, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=VLAN) / S.IP() / S.TCP()

        else:
            span_packet_base = \
                S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str,
                        type=U.Ethertype.IPv6.value) / \
                S.IPv6(src=TUNNEL_SOURCE.addr_str,
                       dst=TUNNEL_DEST.addr_str,
                       hlim=TUNNEL_TTL,
                       tc=TUNNEL_DSCP << 2,
                       nh=sdk.la_l4_protocol_e_GRE, plen=111) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II, seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=3) / \
                self.INJECT_UP_STD_HEADER / \
                S.Ether(dst=DST_MAC, src=SRC_MAC, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=VLAN) / S.IP() / TCP()

            new_span_packet_base = \
                S.Ether(dst=NEW_DEST_MAC.addr_str, src=NEW_SOURCE_MAC.addr_str,
                        type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=EGRESS_VLAN) / \
                S.IPv6(src=NEW_TUNNEL_SOURCE.addr_str,
                       dst=NEW_TUNNEL_DEST.addr_str,
                       hlim=NEW_TUNNEL_TTL,
                       tc=NEW_TUNNEL_DSCP << 2,
                       nh=sdk.la_l4_protocol_e_GRE, plen=111) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II, seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=3) / \
                self.INJECT_UP_STD_HEADER / \
                S.Ether(dst=DST_MAC, src=SRC_MAC, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=VLAN) / S.IP() / TCP()

        self.span_packet = U.add_payload(span_packet_base, pad_len)
        self.new_span_packet = U.add_payload(new_span_packet_base, pad_len)

        self.in_packet_data = {'data': self.in_packet, 'slice': self.RX_slice, 'ifg': self.RX_ifg, 'pif': IN_SERDES_FIRST}
        self.out_packet_data = {
            'data': self.out_packet,
            'slice': OUT_SLICE,
            'ifg': OUT_IFG,
            'pif': OUT_SERDES_FIRST}
        self.span_packet_data = {
            'data': self.span_packet,
            'slice': T.TX_SLICE_REG,
            'ifg': T.TX_IFG_REG,
            'pif': self.l3_port_impl.serdes_reg}
        self.new_span_packet_data = {
            'data': self.new_span_packet,
            'slice': T.TX_SLICE_EXT,
            'ifg': T.TX_IFG_EXT,
            'pif': self.l3_port_impl.serdes_ext}

    def create_l2_muticast_topology(self):

        # Create multicast group
        self.mc_group = self.device.create_l2_multicast_group(MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.assertIsNotNone(self.mc_group)

        # Create switch
        self.sw1 = T.switch(self, self.device, 100)
        self.sw1.hld_obj.set_flood_destination(self.mc_group)

        # Create input AC port
        self.in_eth_port = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, SYS_PORT_GID_BASE, IN_SERDES_FIRST, IN_SERDES_LAST)
        self.in_ac_port = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            None,
            self.in_eth_port,
            None,
            VLAN,
            0x0)

        # Create 2 output system-ports
        self.out_mac_port1 = T.mac_port(self, self.device, OUT_SLICE, OUT_IFG, OUT_SERDES_FIRST, OUT_SERDES_LAST)
        self.out_sys_port1 = T.system_port(self, self.device, SYS_PORT_GID_BASE + 1, self.out_mac_port1)

        self.out_mac_port2 = T.mac_port(self, self.device, OUT_SLICE1, OUT_IFG1, OUT_SERDES_FIRST1, OUT_SERDES_LAST1)
        self.out_sys_port2 = T.system_port(self, self.device, SYS_PORT_GID_BASE + 2, self.out_mac_port2)

        self.out_mac_port1.activate()
        self.out_mac_port2.activate()

        # Create packets
        self.create_multicast_packets()

    def create_multicast_packets(self):
        self.in_packet, pad_len = \
            U.enlarge_packet_to_min_length(Ether(dst=DST_MAC, src=SRC_MAC, type=U.Ethertype.Dot1Q.value) /
                                           Dot1Q(vlan=VLAN) /
                                           IP() / TCP())

        self.out_packet = \
            U.add_payload(Ether(dst=DST_MAC, src=SRC_MAC, type=U.Ethertype.Dot1Q.value) /
                          Dot1Q(vlan=VLAN) /
                          IP() / TCP(), pad_len)

        # self.in_packet, self.out_packet = U.pad_input_and_output_packets(in_packet_base, out_packet_base)

        punt_egr_packets = self.device.get_bool_property(sdk.la_device_property_e_TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST)

        self.set_rx_slice_and_inject_header(IN_SLICE, IN_IFG)
        self.INJECT_UP_STD_HEADER[UUT_P.INJECT_UP_STD_LAYER_INDEX].pif_id = IN_SERDES_FIRST

        if (punt_egr_packets is False):
            span_packet_base = \
                S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str,
                        type=U.Ethertype.IPv6.value) / \
                S.IPv6(src=TUNNEL_SOURCE.addr_str,
                       dst=TUNNEL_DEST.addr_str,
                       hlim=TUNNEL_TTL,
                       tc=TUNNEL_DSCP << 2,
                       nh=sdk.la_l4_protocol_e_GRE, plen=76) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II, seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=3) / \
                S.Ether(dst=DST_MAC, src=SRC_MAC, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=VLAN) / S.IP() / S.TCP()

            new_span_packet_base = \
                S.Ether(dst=NEW_DEST_MAC.addr_str, src=NEW_SOURCE_MAC.addr_str,
                        type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=EGRESS_VLAN) / \
                S.IPv6(src=NEW_TUNNEL_SOURCE.addr_str,
                       dst=NEW_TUNNEL_DEST.addr_str,
                       hlim=NEW_TUNNEL_TTL,
                       tc=NEW_TUNNEL_DSCP << 2,
                       nh=sdk.la_l4_protocol_e_GRE, plen=76) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II, seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=3) / \
                S.Ether(dst=DST_MAC, src=SRC_MAC, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=VLAN) / S.IP() / S.TCP()

        else:
            span_packet_base = \
                S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str,
                        type=U.Ethertype.IPv6.value) / \
                S.IPv6(src=TUNNEL_SOURCE.addr_str,
                       dst=TUNNEL_DEST.addr_str,
                       hlim=TUNNEL_TTL,
                       tc=TUNNEL_DSCP << 2,
                       nh=sdk.la_l4_protocol_e_GRE, plen=111) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II, seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=3) / \
                self.INJECT_UP_STD_HEADER / \
                S.Ether(dst=DST_MAC, src=SRC_MAC, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=VLAN) / S.IP() / TCP()

            new_span_packet_base = \
                S.Ether(dst=NEW_DEST_MAC.addr_str, src=NEW_SOURCE_MAC.addr_str,
                        type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=EGRESS_VLAN) / \
                S.IPv6(src=NEW_TUNNEL_SOURCE.addr_str,
                       dst=NEW_TUNNEL_DEST.addr_str,
                       hlim=NEW_TUNNEL_TTL,
                       tc=NEW_TUNNEL_DSCP << 2,
                       nh=sdk.la_l4_protocol_e_GRE, plen=111) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II, seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=3) / \
                self.INJECT_UP_STD_HEADER / \
                S.Ether(dst=DST_MAC, src=SRC_MAC, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=VLAN) / S.IP() / TCP()

        self.span_packet = U.add_payload(span_packet_base, pad_len)
        self.new_span_packet = U.add_payload(new_span_packet_base, pad_len)

    def _test_l2_multicast_erspan(self):
        dest_mac = T.mac_addr(DST_MAC)
        self.in_ac_port.hld_obj.attach_to_switch(self.sw1.hld_obj)
        self.sw1.hld_obj.set_mac_entry(dest_mac.hld_obj, self.mc_group, sdk.LA_MAC_AGING_TIME_NEVER)

        # Create 2 output AC ports
        eth_port1 = T.sa_ethernet_port(self, self.device, self.out_sys_port1)
        ac_port1 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 1,
            self.topology.filter_group_def,
            self.sw1,
            eth_port1,
            None,
            VLAN,
            0x0)

        eth_port2 = T.sa_ethernet_port(self, self.device, self.out_sys_port2)
        ac_port2 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 2,
            self.topology.filter_group_def,
            self.sw1,
            eth_port2,
            None,
            VLAN,
            0x0)

        # Add the output AC ports to the MC group
        self.mc_group.add(ac_port1.hld_obj, self.out_sys_port1.hld_obj)
        self.mc_group.add(ac_port2.hld_obj, self.out_sys_port2.hld_obj)

        # Run the packet and check results
        ingress_packet = {'data': self.in_packet, 'slice': self.RX_slice, 'ifg': self.RX_ifg, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE1, 'ifg': OUT_IFG1, 'pif': OUT_SERDES_FIRST1})
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST})
        multicast_out_packets = copy.deepcopy(expected_packets)
        expected_packets.append({'data': self.span_packet,
                                 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG,
                                 'pif': self.l3_port_impl.serdes_reg})
        self.in_ac_port.hld_obj.set_ingress_mirror_command(self.mirror_cmd.hld_obj, is_acl_conditioned=False)

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        mirror_cmd, is_acl_conditioned = self.in_ac_port.hld_obj.get_ingress_mirror_command()
        self.assertEqual(mirror_cmd.get_gid(), self.mirror_cmd.hld_obj.get_gid())
        self.assertFalse(is_acl_conditioned)

        packet_count, byte_count = self.erspan_counter.read(0, True, True)
        self.mirror_cmd.hld_obj.set_counter(None)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.span_packet, byte_count)

        self.in_ac_port.hld_obj.set_ingress_mirror_command(None, is_acl_conditioned=False)
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets[0:2])

        self.in_ac_port.hld_obj.set_ingress_mirror_command(None, is_acl_conditioned=True)
        U.run_and_compare_list(self, self.device, self.in_packet_data, expected_packets[0:2])


class vxlan_l2_single_port(l2_erspan_base):
    NEW_TX_L3_AC_DEF_MAC = T.mac_addr('50:52:53:54:55:56')
    VXLAN_L2_PORT_GID = 0x251
    VXLAN_SIP = T.ipv4_addr('12.10.12.11')
    VXLAN_DIP = T.ipv4_addr('12.1.95.250')
    VXLAN_SRC_MAC = T.mac_addr('06:12:34:56:78:9a')
    VXLAN_DST_MAC = T.mac_addr('08:bc:de:23:45:67')
    L2_SRC_MAC = T.mac_addr('02:11:22:33:44:55')
    L2_DST_MAC = T.mac_addr('04:66:77:88:99:aa')
    OUTER_SRC_MAC = '00:11:22:33:44:55'
    TTL = 255

    def single_port_setup(self):

        self.topology.tx_l3_ac_eth_port_def.hld_obj.set_service_mapping_type(sdk.la_ethernet_port.service_mapping_type_e_SMALL)

        self.underlay_ip_impl = ip_test_base.ipv4_test_base
        self.l3_port_impl = T.ip_l3_ac_base(self.topology)

        # make the l3 port address unicast mac address
        self.topology.tx_l3_ac_def.hld_obj.set_mac(
            vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.hld_obj)

        self.topology.tx_l3_ac_def.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_def.hld_obj.set_ingress_mirror_command(self.mirror_cmd.hld_obj, is_acl_conditioned=False)

        # mac forwarding entry for l2 payload
        self.topology.tx_switch.hld_obj.set_mac_entry(
            vxlan_l2_single_port.L2_DST_MAC.hld_obj,
            self.topology.tx_l2_ac_port_def.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)
        self.topology.rx_switch.hld_obj.set_mac_entry(
            vxlan_l2_single_port.L2_DST_MAC.hld_obj,
            self.topology.rx_l2_ac_port.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        # create L2 VXLAN port
        self.vxlan_l2_port = self.device.create_vxlan_l2_service_port(
            vxlan_l2_single_port.VXLAN_L2_PORT_GID,
            vxlan_l2_single_port.VXLAN_SIP.hld_obj,
            vxlan_l2_single_port.VXLAN_DIP.hld_obj,
            self.topology.vrf.hld_obj)
        self.vxlan_l2_port.set_l3_destination(self.l3_port_impl.def_nh.hld_obj)

        # set VNI the on the switch/BD
        self.vxlan_l2_port.set_encap_vni(self.topology.rx_switch.hld_obj, 9999)
        self.topology.rx_switch.hld_obj.set_decap_vni(9999)
        self.vxlan_l2_port.set_encap_vni(self.topology.tx_switch.hld_obj, 10000)
        self.topology.tx_switch.hld_obj.set_decap_vni(10000)

        # set vxlan mac to forwarding table
        self.topology.rx_switch.hld_obj.set_mac_entry(
            vxlan_l2_single_port.VXLAN_DST_MAC.hld_obj,
            self.vxlan_l2_port,
            sdk.LA_MAC_AGING_TIME_NEVER)

        self.topology.tx_switch.hld_obj.set_mac_entry(
            vxlan_l2_single_port.VXLAN_DST_MAC.hld_obj,
            self.vxlan_l2_port,
            sdk.LA_MAC_AGING_TIME_NEVER)

    def add_default_route(self):
        prefix = self.underlay_ip_impl.get_default_prefix()
        self.underlay_ip_impl.add_route(self.topology.vrf, prefix,
                                        self.l3_port_impl.def_nh,
                                        vxlan_base.PRIVATE_DATA_DEFAULT)
        self.has_default_route = True

    def destroy_default_route(self):
        if self.has_default_route:
            prefix = self.underlay_ip_impl.get_default_prefix()
            self.underlay_ip_impl.delete_route(self.topology.vrf, prefix)
            self.has_default_route = False

    def single_port_destroy(self):
        self.topology.rx_switch.hld_obj.remove_mac_entry(
            vxlan_l2_single_port.VXLAN_DST_MAC.hld_obj)
        self.topology.tx_switch.hld_obj.remove_mac_entry(
            vxlan_l2_single_port.VXLAN_DST_MAC.hld_obj)
        self.vxlan_l2_port.clear_encap_vni(self.topology.rx_switch.hld_obj)
        self.topology.rx_switch.hld_obj.clear_decap_vni()
        self.vxlan_l2_port.clear_encap_vni(self.topology.tx_switch.hld_obj)
        self.topology.tx_switch.hld_obj.clear_decap_vni()
        self.device.destroy(self.vxlan_l2_port)

    def create_vxlan_packets(self):
        # packet comes in at tx_l3_ac_def and goes out at tx_l2_ac_port_def
        VXLAN_DECAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=vxlan_l2_single_port.L2_DST_MAC.addr_str,
                    src=vxlan_l2_single_port.L2_SRC_MAC.addr_str) / \
            S.IP() / \
            S.TCP()

        self.VXLAN_DECAP_EXPECTED_OUTPUT_PACKET, pad_len = U.enlarge_packet_to_min_length(VXLAN_DECAP_EXPECTED_OUTPUT_PACKET, 68)

        VXLAN_DECAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(dst=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 src=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=TTL) / \
            S.UDP(sport=6522,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10000) / \
            VXLAN_DECAP_EXPECTED_OUTPUT_PACKET

        self.VXLAN_DECAP_INPUT_PACKET = U.add_payload(VXLAN_DECAP_INPUT_PACKET, pad_len)

        punt_egr_packets = self.device.get_bool_property(sdk.la_device_property_e_TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST)

        UUT_P.INJECT_UP_STD_HEADER[UUT_P.INJECT_UP_STD_LAYER_INDEX].pif_id = T.FIRST_SERDES_L3
        UUT_P.INJECT_UP_STD_HEADER[UUT_P.INJECT_UP_STD_LAYER_INDEX].ifg_id = T.TX_IFG_DEF

        if (punt_egr_packets is False):
            span_packet_base = \
                S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str,
                        type=U.Ethertype.IPv6.value) / \
                S.IPv6(src=TUNNEL_SOURCE.addr_str,
                       dst=TUNNEL_DEST.addr_str,
                       hlim=TUNNEL_TTL,
                       tc=TUNNEL_DSCP << 2,
                       nh=sdk.la_l4_protocol_e_GRE, plen=134) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II, seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=0) / \
                VXLAN_DECAP_INPUT_PACKET

            new_span_packet_base = \
                S.Ether(dst=NEW_DEST_MAC.addr_str, src=NEW_SOURCE_MAC.addr_str,
                        type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=EGRESS_VLAN) / \
                S.IPv6(src=NEW_TUNNEL_SOURCE.addr_str,
                       dst=NEW_TUNNEL_DEST.addr_str,
                       hlim=NEW_TUNNEL_TTL,
                       tc=NEW_TUNNEL_DSCP << 2,
                       nh=sdk.la_l4_protocol_e_GRE, plen=134) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II, seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=0) / \
                VXLAN_DECAP_INPUT_PACKET

        else:
            span_packet_base = \
                S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str,
                        type=U.Ethertype.IPv6.value) / \
                S.IPv6(src=TUNNEL_SOURCE.addr_str,
                       dst=TUNNEL_DEST.addr_str,
                       hlim=TUNNEL_TTL,
                       tc=TUNNEL_DSCP << 2,
                       nh=sdk.la_l4_protocol_e_GRE, plen=169) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II, seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=3) / \
                UUT_P.INJECT_UP_STD_HEADER / \
                VXLAN_DECAP_INPUT_PACKET

            new_span_packet_base = \
                S.Ether(dst=NEW_DEST_MAC.addr_str, src=NEW_SOURCE_MAC.addr_str,
                        type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=EGRESS_VLAN) / \
                S.IPv6(src=NEW_TUNNEL_SOURCE.addr_str,
                       dst=NEW_TUNNEL_DEST.addr_str,
                       hlim=NEW_TUNNEL_TTL,
                       tc=NEW_TUNNEL_DSCP << 2,
                       nh=sdk.la_l4_protocol_e_GRE, plen=169) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II, seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=3) / \
                UUT_P.INJECT_UP_STD_HEADER / \
                VXLAN_DECAP_INPUT_PACKET

        self.span_packet = U.add_payload(span_packet_base, pad_len)
        self.new_span_packet = U.add_payload(new_span_packet_base, pad_len)

        self.in_packet_data = {
            'data': self.VXLAN_DECAP_INPUT_PACKET,
            'slice': T.TX_SLICE_DEF,
            'ifg': T.TX_IFG_DEF,
            'pif': T.FIRST_SERDES_L3}
        self.out_packet_data = {
            'data': self.VXLAN_DECAP_EXPECTED_OUTPUT_PACKET,
            'slice': T.TX_SLICE_DEF,
            'ifg': T.TX_IFG_DEF,
            'pif': T.FIRST_SERDES_SVI}
        self.span_packet_data = {
            'data': self.span_packet,
            'slice': T.TX_SLICE_REG,
            'ifg': T.TX_IFG_REG,
            'pif': self.l3_port_impl.serdes_reg}
        self.new_span_packet_data = {
            'data': self.new_span_packet,
            'slice': T.TX_SLICE_EXT,
            'ifg': T.TX_IFG_EXT,
            'pif': self.l3_port_impl.serdes_ext}
