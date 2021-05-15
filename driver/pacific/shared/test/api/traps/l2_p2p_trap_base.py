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
from sdk_test_case_base import *
from collections import namedtuple

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

STD_MACSEC_ETHERTYPE = 0x888E
WAN_MACSEC_ETHERTYPE = 0x876F
CFM_ETHERTYPE = 0x8902

DEST_MAC = '02:02:02:02:02:02'
L2CP_LLDP_DMAC = '01:80:c2:00:00:50'
L2CP_LLDP_DMAC_MASK = 'ff:ff:ff:ff:ff:f8'
L2CP_CFM_DMAC = '01:80:c2:00:00:31'
L2CP_CFM_DMAC_MASK = 'ff:ff:ff:ff:ff:ff'

TEST_L2CP_INDEX = 0
TEST_CFM_INDEX = 1

CFM_MD_lvl1_ascii = '\x20'
CFM_OPCODE_ascii = '\x01'
CFM_PDU_ascii = '\x00\x00'


class l2_p2p_trap_base(sdk_test_case_base):
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

        self.copc_mac = self.device.create_copc(sdk.la_control_plane_classifier.type_e_MAC)
        self.copc_ipv4 = self.device.create_copc(sdk.la_control_plane_classifier.type_e_IPV4)
        self.copc_ipv6 = self.device.create_copc(sdk.la_control_plane_classifier.type_e_IPV6)

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
                                          None,
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

        self.ac_profile = T.ac_profile(self, self.device)
        for i in range(2):
            self.create_ac_port(i)

        self._l2_p2p_attach(0, 1)

    def create_p2p_destination(self, first_port, second_port):
        self.ac_ports[first_port].hld_obj.set_destination(self.ac_ports[second_port].hld_obj)
        self.ac_ports[second_port].hld_obj.set_destination(self.ac_ports[first_port].hld_obj)

    def destroy_ports(self):
        for ac_port in self.ac_ports:
            ac_port.hld_obj.detach()

        for ac_port in self.ac_ports:
            ac_port.destroy()

        for eth_port in self.eth_ports:
            eth_port.destroy()

        self.ac_profile.destroy()

    def create_packets(self):
        SRC_MAC = "00:01:02:03:04:06"
        cdp_da = '01:00:0C:CC:CC:CC'
        in_packet_base = Ether(dst=cdp_da, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()
        self.in_packet = {}
        self.out_packet = {}

        out_packet_base = Ether(dst=cdp_da, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()
        self.in_packet['CDP'], self.out_packet['CDP'] = pad_input_and_output_packets(in_packet_base, out_packet_base)

        DST_MAC = "01:00:5E:00:00:01"
        DST_IP = T.ipv4_addr('239.0.0.1')
        SRC_IP = T.ipv4_addr('1.2.3.1')
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP(src=SRC_IP.addr_str, dst=DST_IP.addr_str, ttl=128) / UDP()

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP(src=SRC_IP.addr_str, dst=DST_IP.addr_str, ttl=128) / UDP()
        self.in_packet['BCAST'], self.out_packet['BCAST'] = pad_input_and_output_packets(in_packet_base, out_packet_base)

        in_packet_base = Ether(dst=DEST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=STD_MACSEC_ETHERTYPE) / \
            EAPOL(type = 1)

        out_packet_base = Ether(dst=DEST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=STD_MACSEC_ETHERTYPE) / \
            EAPOL(type = 1)
        self.in_packet['MACSEC'], self.out_packet['MACSEC'] = pad_input_and_output_packets(in_packet_base, out_packet_base)

        in_packet_base = Ether(dst=DEST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=WAN_MACSEC_ETHERTYPE) / \
            EAPOL(type = 1)

        out_packet_base = Ether(dst=DEST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=WAN_MACSEC_ETHERTYPE) / \
            EAPOL(type = 1)
        self.in_packet['WANMACSEC'], self.out_packet['WANMACSEC'] = pad_input_and_output_packets(in_packet_base, out_packet_base)

        in_packet_base = Ether(dst=DEST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            ARP(op='is-at')

        out_packet_base = Ether(dst=DEST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            ARP(op='is-at')
        self.in_packet['ARP'], self.out_packet['ARP'] = pad_input_and_output_packets(in_packet_base, out_packet_base)

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

        in_packet_base = Ether(dst=L2CP_LLDP_DMAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=U.Ethertype.LLDP.value)

        out_packet_base = Ether(dst=L2CP_LLDP_DMAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=U.Ethertype.LLDP.value)
        self.in_packet['LLDP'], self.out_packet['LLDP'] = pad_input_and_output_packets(in_packet_base, out_packet_base)

        cfm_raw_lvl1 = Raw()
        cfm_raw_lvl1.load = CFM_MD_lvl1_ascii + CFM_OPCODE_ascii + CFM_PDU_ascii
        in_packet_base = Ether(dst=L2CP_CFM_DMAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=CFM_ETHERTYPE) / cfm_raw_lvl1

        out_packet_base = Ether(dst=L2CP_CFM_DMAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=CFM_ETHERTYPE) / cfm_raw_lvl1
        self.in_packet['CFM'], self.out_packet['CFM'] = pad_input_and_output_packets(in_packet_base, out_packet_base)

    def _l2_p2p_attach(self, ingress_port_num, egress_port_num):
        self.create_p2p_destination(ingress_port_num, egress_port_num)

    def run_and_compare_p2p(self, ingress_port_num, egress_port_num, type):
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

    def run_and_drop_p2p(self, ingress_port_num, egress_port_num, type):
        run_and_drop(
            self,
            self.device,
            self.in_packet[type],
            self.ports[ingress_port_num].slice,
            self.ports[ingress_port_num].ifg,
            self.ports[ingress_port_num].first_serdes)

    def _test_traffic(self, ingress_port_num, egress_port_num, type):
        l2_ingress_counter = self.ac_ports[ingress_port_num].hld_obj.get_ingress_counter(sdk.la_counter_set.type_e_PORT)

        l2_egress_counter = self.ac_ports[egress_port_num].hld_obj.get_egress_counter(sdk.la_counter_set.type_e_PORT)
        # clear counters
        packet_count, byte_count = l2_ingress_counter.read(0, True, True)
        packet_count, byte_count = l2_egress_counter.read(0, True, True)

        self.run_and_compare_p2p(ingress_port_num, egress_port_num, type)
        packet_count, byte_count = l2_ingress_counter.read(0, True, True)
        #self.assertEqual(packet_count, 1)
        packet_count, byte_count = l2_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

    def _test_drop_traffic(self, ingress_port_num, egress_port_num, type):
        self.run_and_drop_p2p(ingress_port_num, egress_port_num, type)
