#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
#from sdk_test_case_base import *
from collections import namedtuple
import decor

from traps.traps_base import *

SYS_PORT_GID_BASE = 50
AC_PORT_GID_BASE = 10
SPA_PORT_GID_BASE = 15

L2_SLICE_1 = T.get_device_slice(0)
L2_SLICE_2 = T.get_device_slice(2)
L2_SLICE_3 = T.get_device_slice(3)

L2_IFG_1 = T.get_device_ifg(0)
L2_IFG_2 = T.get_device_ifg(1)

L2_FIRST_SERDES = T.get_device_first_serdes(4)
L2_LAST_SERDES = T.get_device_last_serdes(5)

VLAN = 0xAB9
TTL = 128

SIP = T.ipv4_addr('12.10.12.10')
DIP = T.ipv4_addr('82.81.95.250')

SIP6 = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
DIP6 = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

SRC_MAC = "00:01:02:03:04:06"
DEST_MAC = '02:02:02:02:02:02'


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class trap_dhcp_unicast_l2_CSCvw75304(sdk_test_case_base):
    # Static members
    phy_port = namedtuple('phy_port', 'slice ifg first_serdes last_serdes sys_port_gid ac_port_gid')

    def setUp(self):
        super().setUp(create_default_topology=False)

        self.ports = [0, 0]
        # MATILDA_SAVE -- need review
        slice = T.choose_active_slices(self.device, 0, [0, 2, 5])
        self.ports[0] = self.phy_port(slice,
                                      T.get_device_ifg(0),
                                      T.get_device_first_serdes(4),
                                      T.get_device_last_serdes(5),
                                      SYS_PORT_GID_BASE,
                                      AC_PORT_GID_BASE)
        slice = T.choose_active_slices(self.device, 3, [1, 3, 4])
        self.ports[1] = self.phy_port(slice,
                                      T.get_device_ifg(1),
                                      T.get_device_next_first_serdes(8),
                                      T.get_device_next_last_serdes(9),
                                      SYS_PORT_GID_BASE + 1,
                                      AC_PORT_GID_BASE + 1)

        if not any(self.topology.inject_ports):
            self.topology.create_inject_ports()
            self._add_objects_to_keep()
        self.create_network_topology()
        self.copc_ipv4 = self.device.create_copc(sdk.la_control_plane_classifier.type_e_IPV4)
        self.copc_ipv6 = self.device.create_copc(sdk.la_control_plane_classifier.type_e_IPV6)

    def install_an_entry_in_copc_ipv4_table(
            self,
            protocol_value,
            protocol_mask,
            l4_dst_port_value,
            l4_dst_port_mask,
            ethernet_profile_id_value,
            ethernet_profile_id_mask,
            lp_type_value,
            lp_type_mask,
            is_svi_value,
            is_svi_mask,
            event,
            dest_ip_value = T.ipv4_addr('0.0.0.0'),
            dest_ip_mask = T.ipv4_addr('0.0.0.0'),
            my_mac_value = False,
            my_mac_mask = False):

        key1 = []
        f1 = sdk.field()
        f1.type.ipv4 = sdk.la_control_plane_classifier.ipv4_field_type_e_ETHERNET_PROFILE_ID
        f1.val.ipv4.ethernet_profile_id = ethernet_profile_id_value
        f1.mask.ipv4.ethernet_profile_id = ethernet_profile_id_mask
        key1.append(f1)

        f2 = sdk.field()
        f2.type.ipv4 = sdk.la_control_plane_classifier.ipv4_field_type_e_LP_TYPE
        f2.val.ipv4.lp_type = lp_type_value
        f2.mask.ipv4.lp_type = lp_type_mask
        key1.append(f2)

        f3 = sdk.field()
        f3.type.ipv4 = sdk.la_control_plane_classifier.ipv4_field_type_e_PROTOCOL
        f3.val.ipv4.protocol = protocol_value
        f3.mask.ipv4.protocol = protocol_mask
        key1.append(f3)

        f4 = sdk.field()
        f4.type.ipv4 = sdk.la_control_plane_classifier.ipv4_field_type_e_DPORT
        f4.val.ipv4.dport = l4_dst_port_value
        f4.mask.ipv4.dport = l4_dst_port_mask
        key1.append(f4)

        f5 = sdk.field()
        f5.type.ipv4 = sdk.la_control_plane_classifier.ipv4_field_type_e_IS_SVI
        f5.val.ipv4.is_svi = is_svi_value
        f5.mask.ipv4.is_svi = is_svi_mask
        key1.append(f5)

        f6 = sdk.field()
        f6.type.ipv4 = sdk.la_control_plane_classifier.ipv4_field_type_e_IPV4_DIP
        f6.val.ipv4.ipv4_dip.s_addr = dest_ip_value.to_num()
        f6.mask.ipv4.ipv4_dip.s_addr = dest_ip_mask.to_num()
        key1.append(f6)

        f7 = sdk.field()
        f7.type.ipv4 = sdk.la_control_plane_classifier.ipv4_field_type_e_MY_MAC
        f7.val.ipv4.my_mac = my_mac_value
        f7.mask.ipv4.my_mac = my_mac_mask
        key1.append(f7)

        result1 = sdk.result()
        result1.event = event

        self.copc_ipv4.append(key1, result1)

    def clear_entries_from_copc_ipv4_table(self):
        self.copc_ipv4.clear()

    def install_an_entry_in_copc_ipv6_table(
            self,
            next_header_value,
            next_header_mask,
            l4_dst_port_value,
            l4_dst_port_mask,
            ethernet_profile_id_value,
            ethernet_profile_id_mask,
            lp_type_value,
            lp_type_mask,
            is_svi_value,
            is_svi_mask,
            event,
            dest_ip_value = T.ipv6_addr('0::0'),
            dest_ip_mask = T.ipv6_addr('0::0'),
            my_mac_value = False,
            my_mac_mask = False):

        key1 = []
        f1 = sdk.field()
        f1.type.ipv6 = sdk.la_control_plane_classifier.ipv6_field_type_e_ETHERNET_PROFILE_ID
        f1.val.ipv6.ethernet_profile_id = ethernet_profile_id_value
        f1.mask.ipv6.ethernet_profile_id = ethernet_profile_id_mask
        key1.append(f1)

        f2 = sdk.field()
        f2.type.ipv6 = sdk.la_control_plane_classifier.ipv6_field_type_e_LP_TYPE
        f2.val.ipv6.lp_type = lp_type_value
        f2.mask.ipv6.lp_type = lp_type_mask
        key1.append(f2)

        f3 = sdk.field()
        f3.type.ipv6 = sdk.la_control_plane_classifier.ipv6_field_type_e_NEXT_HEADER
        f3.val.ipv6.next_header = next_header_value
        f3.mask.ipv6.next_header = next_header_mask
        key1.append(f3)

        f4 = sdk.field()
        f4.type.ipv6 = sdk.la_control_plane_classifier.ipv6_field_type_e_DPORT
        f4.val.ipv6.dport = l4_dst_port_value
        f4.mask.ipv6.dport = l4_dst_port_mask
        key1.append(f4)

        f5 = sdk.field()
        f5.type.ipv6 = sdk.la_control_plane_classifier.ipv6_field_type_e_IS_SVI
        f5.val.ipv6.is_svi = is_svi_value
        f5.mask.ipv6.is_svi = is_svi_mask
        key1.append(f5)

        f6 = sdk.field()
        f6.type.ipv6 = sdk.la_control_plane_classifier.ipv6_field_type_e_IPV6_DIP
        q0 = sdk.get_ipv6_addr_q0(dest_ip_value.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(dest_ip_value.hld_obj)
        sdk.set_ipv6_addr(f6.val.ipv6.ipv6_dip, q0, q1)
        q0 = sdk.get_ipv6_addr_q0(dest_ip_mask.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(dest_ip_mask.hld_obj)
        sdk.set_ipv6_addr(f6.mask.ipv6.ipv6_dip, q0, q1)
        key1.append(f6)

        f7 = sdk.field()
        f7.type.ipv6 = sdk.la_control_plane_classifier.ipv6_field_type_e_MY_MAC
        f7.val.ipv6.my_mac = my_mac_value
        f7.mask.ipv6.my_mac = my_mac_mask
        key1.append(f7)

        result1 = sdk.result()
        result1.event = event

        self.copc_ipv6.append(key1, result1)

    def clear_entries_from_copc_ipv6_table(self):
        self.copc_ipv6.clear()

    def tearDown(self):
        self.destroy_ports()
        super().tearDown()

    def create_network_topology(self):
        self.create_ports()
        self.create_packets()

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
                                          self.sw1,
                                          self.eth_ports[num],
                                          None, VLAN, 0x0))

        counter_set_size = 1
        l2_ingress_counter = self.device.create_counter(counter_set_size)
        self.ac_ports[num].hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, l2_ingress_counter)

        l2_egress_counter = self.device.create_counter(counter_set_size)
        self.ac_ports[num].hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, l2_egress_counter)

    def create_ports(self):
        self.eth_ports = []
        self.ac_ports = []

        self.sw1 = T.switch(self, self.device, VLAN)
        self.ac_profile = T.ac_profile(self, self.device)
        for i in range(2):
            self.create_ac_port(i)

        self.mc_group = self.device.create_l2_multicast_group(0x20, sdk.la_replication_paradigm_e_EGRESS)
        self.assertIsNotNone(self.mc_group)

        sys_port1 = self.eth_ports[0].hld_obj.get_system_port()
        self.mc_group.add(self.ac_ports[0].hld_obj, sys_port1)

        sys_port2 = self.eth_ports[1].hld_obj.get_system_port()
        self.mc_group.add(self.ac_ports[1].hld_obj, sys_port2)

        self.sw1.hld_obj.set_flood_destination(self.mc_group)

    def destroy_ports(self):
        self.mc_group.remove(self.ac_ports[0].hld_obj)
        self.mc_group.remove(self.ac_ports[1].hld_obj)
        self.sw1.hld_obj.set_flood_destination(None)
        self.device.destroy(self.mc_group)

        for ac_port in self.ac_ports:
            l2_ingress_counter = ac_port.hld_obj.get_ingress_counter(sdk.la_counter_set.type_e_PORT)
            ac_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, None)
            self.device.destroy(l2_ingress_counter)

            l2_egress_counter = ac_port.hld_obj.get_egress_counter(sdk.la_counter_set.type_e_PORT)
            ac_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, None)
            self.device.destroy(l2_egress_counter)

            ac_port.hld_obj.detach()

        for ac_port in self.ac_ports:
            ac_port.destroy()

        for eth_port in self.eth_ports:
            eth_port.destroy()

        self.ac_profile.destroy()

    def create_packets(self):
        self.in_packet = {}
        self.out_packet = {}

        in_packet_base = Ether(dst=DEST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            UDP(sport=0x44, dport=0x43) / \
            BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
            DHCP(options=[("message-type", "discover"), "end"])

        out_packet_base = Ether(dst=DEST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            UDP(sport=0x44, dport=0x43) / \
            BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
            DHCP(options=[("message-type", "discover"), "end"])
        self.in_packet['DHCPV4SERVER'], self.out_packet['DHCPV4SERVER'] = pad_input_and_output_packets(
            in_packet_base, out_packet_base)

        in_packet_base = Ether(dst=DEST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            UDP(sport=0x43, dport=0x44) / \
            BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
            DHCP(options=[("message-type", "discover"), "end"])

        out_packet_base = Ether(dst=DEST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            UDP(sport=0x43, dport=0x44) / \
            BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
            DHCP(options=[("message-type", "discover"), "end"])
        self.in_packet['DHCPV4CLIENT'], self.out_packet['DHCPV4CLIENT'] = pad_input_and_output_packets(
            in_packet_base, out_packet_base)

        in_packet_base = Ether(dst=DEST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IPv6(src=SIP6.addr_str, dst=DIP6.addr_str, hlim=TTL) / \
            UDP(sport=0x222, dport=0x223) / \
            BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
            DHCP(options=[("message-type", "discover"), "end"])

        out_packet_base = Ether(dst=DEST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IPv6(src=SIP6.addr_str, dst=DIP6.addr_str, hlim=TTL) / \
            UDP(sport=0x222, dport=0x223) / \
            BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
            DHCP(options=[("message-type", "discover"), "end"])
        self.in_packet['DHCPV6SERVER'], self.out_packet['DHCPV6SERVER'] = pad_input_and_output_packets(
            in_packet_base, out_packet_base)

        in_packet_base = Ether(dst=DEST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IPv6(src=SIP6.addr_str, dst=DIP6.addr_str, hlim=TTL) / \
            UDP(sport=0x223, dport=0x222) / \
            BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
            DHCP(options=[("message-type", "discover"), "end"])

        out_packet_base = Ether(dst=DEST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IPv6(src=SIP6.addr_str, dst=DIP6.addr_str, hlim=TTL) / \
            UDP(sport=0x223, dport=0x222) / \
            BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
            DHCP(options=[("message-type", "discover"), "end"])
        self.in_packet['DHCPV6CLIENT'], self.out_packet['DHCPV6CLIENT'] = pad_input_and_output_packets(
            in_packet_base, out_packet_base)

    def run_and_compare_packets(self, ingress_port_num, egress_port_num, type):
        run_and_compare(
            self,
            self.device,
            self.in_packet[type],
            self.ports[ingress_port_num].slice,
            self.ports[ingress_port_num].ifg,
            self.ports[ingress_port_num].first_serdes,
            self.out_packet[type],
            self.ports[egress_port_num].slice,
            self.ports[egress_port_num].ifg,
            self.ports[egress_port_num].first_serdes)

    def _test_traffic(self, ingress_port_num, egress_port_num, type):
        l2_ingress_counter = self.ac_ports[ingress_port_num].hld_obj.get_ingress_counter(sdk.la_counter_set.type_e_PORT)

        l2_egress_counter = self.ac_ports[egress_port_num].hld_obj.get_egress_counter(sdk.la_counter_set.type_e_PORT)
        # clear counters
        packet_count, byte_count = l2_ingress_counter.read(0, True, True)
        packet_count, byte_count = l2_egress_counter.read(0, True, True)

        self.run_and_compare_packets(ingress_port_num, egress_port_num, type)
        packet_count, byte_count = l2_ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = l2_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

    def dhcp_setup(self):
        # set ethernet profile id on ethernet port
        udp_protocol = 0x11
        ethernet_profile_id = 2
        ipv4_l4_dhcp_server_dst_port = 0x43
        ipv4_l4_dhcp_client_dst_port = 0x44
        ipv6_l4_dhcp_server_dst_port = 0x223
        ipv6_l4_dhcp_client_dst_port = 0x222

        self.install_an_entry_in_copc_ipv4_table(
            udp_protocol,
            0xff,
            ipv4_l4_dhcp_server_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L3,
            0xff,
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER)
        self.install_an_entry_in_copc_ipv4_table(
            udp_protocol,
            0xff,
            ipv4_l4_dhcp_server_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            True,
            True,
            sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER)
        self.install_an_entry_in_copc_ipv4_table(
            udp_protocol,
            0xff,
            ipv4_l4_dhcp_server_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER,
            T.ipv4_addr('0.0.0.0'),
            T.ipv4_addr('0.0.0.0'),
            True,
            True)
        self.install_an_entry_in_copc_ipv4_table(
            udp_protocol,
            0xff,
            ipv4_l4_dhcp_client_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L3,
            0xff,
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV4_CLIENT)
        self.install_an_entry_in_copc_ipv4_table(
            udp_protocol,
            0xff,
            ipv4_l4_dhcp_client_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            True,
            True,
            sdk.LA_EVENT_ETHERNET_DHCPV4_CLIENT)
        self.install_an_entry_in_copc_ipv4_table(
            udp_protocol,
            0xff,
            ipv4_l4_dhcp_client_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER,
            T.ipv4_addr('0.0.0.0'),
            T.ipv4_addr('0.0.0.0'),
            True,
            True)
        self.install_an_entry_in_copc_ipv6_table(
            udp_protocol,
            0xff,
            ipv6_l4_dhcp_server_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L3,
            0xff,
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER)
        self.install_an_entry_in_copc_ipv6_table(
            udp_protocol,
            0xff,
            ipv6_l4_dhcp_server_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            True,
            True,
            sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER)
        self.install_an_entry_in_copc_ipv6_table(
            udp_protocol,
            0xff,
            ipv6_l4_dhcp_server_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER,
            T.ipv6_addr('0::0'),
            T.ipv6_addr('0::0'),
            True,
            True)
        self.install_an_entry_in_copc_ipv6_table(
            udp_protocol,
            0xff,
            ipv6_l4_dhcp_client_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L3,
            0xff,
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV6_CLIENT)
        self.install_an_entry_in_copc_ipv6_table(
            udp_protocol,
            0xff,
            ipv6_l4_dhcp_client_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            True,
            True,
            sdk.LA_EVENT_ETHERNET_DHCPV6_CLIENT)
        self.install_an_entry_in_copc_ipv6_table(
            udp_protocol,
            0xff,
            ipv6_l4_dhcp_client_dst_port,
            0xffff,
            ethernet_profile_id,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER,
            T.ipv6_addr('0::0'),
            T.ipv6_addr('0::0'),
            True,
            True)

    def dhcp_teardown(self):
        self.clear_entries_from_copc_ipv4_table()
        self.clear_entries_from_copc_ipv6_table()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_l2_dhcpv4_server_trap_skip(self):
        self.dhcp_setup()
        self.eth_ports[0].hld_obj.set_copc_profile(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER, 0,
                                           None, None, False, False, True, 0)
        self._test_traffic(0, 1, 'DHCPV4SERVER')
        self.eth_ports[0].hld_obj.set_copc_profile(0)
        self.dhcp_teardown()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_l2_dhcpv4_client_trap_skip(self):
        self.dhcp_setup()
        self.eth_ports[0].hld_obj.set_copc_profile(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_CLIENT, 0,
                                           None, None, False, False, True, 0)
        self._test_traffic(0, 1, 'DHCPV4CLIENT')
        self.eth_ports[0].hld_obj.set_copc_profile(0)
        self.dhcp_teardown()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_l2_dhcpv6_server_trap_skip(self):
        self.dhcp_setup()
        self.eth_ports[0].hld_obj.set_copc_profile(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER, 0,
                                           None, None, False, False, True, 0)
        self._test_traffic(0, 1, 'DHCPV6SERVER')
        self.eth_ports[0].hld_obj.set_copc_profile(0)
        self.dhcp_teardown()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_l2_dhcpv6_client_trap_skip(self):
        self.dhcp_setup()
        self.eth_ports[0].hld_obj.set_copc_profile(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV6_CLIENT, 0,
                                           None, None, False, False, True, 0)
        self._test_traffic(0, 1, 'DHCPV6CLIENT')
        self.eth_ports[0].hld_obj.set_copc_profile(0)
        self.dhcp_teardown()


if __name__ == '__main__':
    unittest.main()
