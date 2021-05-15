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

import unittest
from leaba import sdk
from sdk_test_case_base import *
import packet_test_utils as U
import scapy.all as S
import topology as T
import sim_utils
import ip_test_base
import sys


class ip_routing_svi_flood_base(sdk_test_case_base):

    rx_slice = T.RX_SLICE  # slice-5
    tx_slice = T.TX_SLICE_REG  # slice-1
    tx2_slice = T.TX_SLICE_EXT  # slice-3
    slice0 = 0
    rcy_slice = 3

    ifg0 = T.RX_IFG
    ifg1 = 1
    serdes4 = 4
    serdes5 = 5
    serdes6 = 6
    serdes7 = 7
    serdes8 = 8
    serdes9 = 9

    vlan0 = 0x0
    rx_vlan1 = 0xa
    tx_vlan1 = 0xb
    tx2_vlan1 = 0xc

    sys_port_gid_base = 0x10
    ac_port_gid_base = 0x100

    rx_sys_trunk_port_gid = sys_port_gid_base  # 0x10
    rx_ac_trunk_port_gid = ac_port_gid_base  # 0x100
    rx_sys_access_port_gid = sys_port_gid_base + 1  # 0x11
    rx_ac_access_port_gid = ac_port_gid_base + 1  # 0x101

    tx_sys_trunk_port_gid = sys_port_gid_base + 2  # 0x12
    tx_ac_trunk_port_gid = ac_port_gid_base + 2  # 0x102
    tx_sys_access_port_gid = sys_port_gid_base + 3  # 0x13
    tx_ac_access_port_gid = ac_port_gid_base + 3  # 0x103

    tx2_sys_trunk_port_gid = sys_port_gid_base + 4  # 0x14
    tx2_ac_trunk_port_gid = ac_port_gid_base + 4  # 0x104
    tx2_sys_access_port_gid = sys_port_gid_base + 5  # 0x15
    tx2_ac_access_port_gid = ac_port_gid_base + 5  # 0x105

    tx_inject_up_l2ac_port_gid = ac_port_gid_base + 6  # 0x106
    tx2_inject_up_l2ac_port_gid = ac_port_gid_base + 7  # 0x107

    tx_sys_spa_port_gid = sys_port_gid_base + 6  # 0x16
    tx2_sys_spa_port_gid = sys_port_gid_base + 7  # 0x17
    tx_spa_port_gid = 0x120
    tx2_spa_port_gid = 0x121
    tx_l2ac_spa_port_gid = ac_port_gid_base + 8  # 0x108
    tx2_l2ac_spa_port_gid = ac_port_gid_base + 9  # 0x109

    tx_sw_mc_group_id = 0x20
    tx2_sw_mc_group_id = 0x21
    nh_gid = 0x300
    zero_mac = T.mac_addr('00:00:00:00:00:00')
    rx_svi_mac = T.RX_SVI_MAC  # 10:12:13:14:15:16
    tx_svi_mac = T.RX_SVI_MAC1  # 10:17:18:19:1a:1b
    tx2_svi_mac = T.TX_SVI_EXT_MAC  # 28:29:2a:2b:2c:2d
    tx_svi_host_mac = T.mac_addr('00:27:28:29:00:02')
    nh_mac = T.mac_addr('40:42:43:44:45:46')
    private_data = 0x1234567890abcdef

    def setUp(self):
        super().setUp()

        self.rx_slice = T.choose_active_slices(self.device, self.rx_slice, [5, 2])    # slice-5
        self.tx_slice = T.choose_active_slices(self.device, self.tx_slice, [1, 4])  # slice-1
        self.tx2_slice = T.choose_active_slices(self.device, self.tx2_slice, [3, 2])  # slice-3
        self.slice0 = T.choose_active_slices(self.device, self.slice0, [0, 4])
        self.rcy_slice = T.choose_active_slices(self.device, self.rcy_slice, [3, 1, 5])
        self.tx2_ifg = self.ifg0
        if self.rx_slice == self.tx2_slice:
            self.tx2_ifg = self.ifg1

        self.create_l2()
        self.create_l3()

    def create_l2(self):
        # create rx and tx switches
        self.rx_sw = self.topology.rx_switch   # T.RX_SWITCH_GID  = 0xa0a
        self.tx_sw = self.topology.rx_switch1  # T.RX_SWITCH_GID1 = 0xa0b
        self.tx2_sw = self.topology.tx_switch1  # T.TX_SWITCH_GID1 = 0xa0d

        # create ports on rx_sw (one access port and one trunk port). These ports are incoming ports.
        # rx - trunk port
        self.rx_mac_port1 = T.mac_port(self, self.device, self.rx_slice, self.ifg0, self.serdes4, self.serdes5)
        self.rx_sys_port1 = T.system_port(self, self.device, self.rx_sys_trunk_port_gid, self.rx_mac_port1)
        self.rx_eth_port1 = T.sa_ethernet_port(self, self.device, self.rx_sys_port1)
        self.rx_ac_trunk_port = T.l2_ac_port(self, self.device, self.rx_ac_trunk_port_gid, None,
                                             self.rx_sw, self.rx_eth_port1, self.zero_mac, self.rx_vlan1, self.vlan0)
        self.rx_mac_port1.activate()

        # rx - access port
        self.rx_mac_port2 = T.mac_port(self, self.device, self.rx_slice, self.ifg0, self.serdes6, self.serdes7)
        self.rx_sys_port2 = T.system_port(self, self.device, self.rx_sys_access_port_gid, self.rx_mac_port2)
        self.rx_eth_port2 = T.sa_ethernet_port(self, self.device, self.rx_sys_port2)
        self.rx_ac_access_port = T.l2_ac_port(self, self.device, self.rx_ac_access_port_gid, None,
                                              self.rx_sw, self.rx_eth_port2, self.zero_mac)
        self.rx_mac_port2.activate()

        # create ports on tx_sw (one acccess port and one trunk port). These are outgoing ports for host directly attached case.
        # tx_sw trunk port
        self.tx_mac_port1 = T.mac_port(self, self.device, self.tx_slice, self.ifg0, self.serdes4, self.serdes5)
        self.tx_sys_port1 = T.system_port(self, self.device, self.tx_sys_trunk_port_gid, self.tx_mac_port1)
        self.tx_eth_port1 = T.sa_ethernet_port(self, self.device, self.tx_sys_port1)
        self.tx_ac_trunk_port = T.l2_ac_port(self, self.device, self.tx_ac_trunk_port_gid, None,
                                             self.tx_sw, self.tx_eth_port1, self.zero_mac, self.tx_vlan1, self.vlan0)
        self.tx_mac_port1.activate()
        self.set_l2_ac_vlan_tag(self.tx_ac_trunk_port, self.tx_vlan1)
        self.tx_sw_ec1 = self.device.create_counter(1)
        self.tx_ac_trunk_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.tx_sw_ec1)

        # tx_sw access port
        self.tx_mac_port2 = T.mac_port(self, self.device, self.tx_slice, self.ifg0, self.serdes6, self.serdes7)
        self.tx_sys_port2 = T.system_port(self, self.device, self.tx_sys_access_port_gid, self.tx_mac_port2)
        self.tx_eth_port2 = T.sa_ethernet_port(self, self.device, self.tx_sys_port2)
        self.tx_ac_access_port = T.l2_ac_port(self, self.device, self.tx_ac_access_port_gid, None,
                                              self.tx_sw, self.tx_eth_port2, self.zero_mac)
        self.tx_mac_port2.activate()
        self.tx_sw_ec2 = self.device.create_counter(1)
        self.tx_ac_access_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.tx_sw_ec2)

        # tx_sw spa port
        self.tx_mac_port3 = T.mac_port(self, self.device, self.tx_slice, self.ifg0, self.serdes8, self.serdes9)
        self.tx_mac_port3.activate()
        self.tx_sys_port3 = T.system_port(self, self.device, self.tx_sys_spa_port_gid, self.tx_mac_port3)

        self.tx_spa_port = T.spa_port(self, self.device, self.tx_spa_port_gid)
        self.tx_spa_port.add(self.tx_sys_port3)
        self.tx_spa_port.hld_obj.set_member_transmit_enabled(self.tx_sys_port3.hld_obj, True)

        self.tx_spa_eth_port = T.sa_ethernet_port(self, self.device, self.tx_spa_port)
        self.tx_spa_l2_ac_port = T.l2_ac_port(self, self.device, self.tx_l2ac_spa_port_gid, None,
                                              self.tx_sw, self.tx_spa_eth_port, self.zero_mac)
        self.tx_sw_ec3 = self.device.create_counter(1)
        self.tx_spa_l2_ac_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.tx_sw_ec3)

        # create ports on tx2_sw (one access port and one trunk port). These are outgoing ports for host behind route case.
        # tw2_sw trunk port
        self.tx2_mac_port1 = T.mac_port(self, self.device, self.tx2_slice, self.tx2_ifg, self.serdes4, self.serdes5)
        self.tx2_sys_port1 = T.system_port(self, self.device, self.tx2_sys_trunk_port_gid, self.tx2_mac_port1)
        self.tx2_eth_port1 = T.sa_ethernet_port(self, self.device, self.tx2_sys_port1)
        self.tx2_ac_trunk_port = T.l2_ac_port(self, self.device, self.tx2_ac_trunk_port_gid, None,
                                              self.tx2_sw, self.tx2_eth_port1, self.zero_mac, self.tx2_vlan1, self.vlan0)
        self.tx2_mac_port1.activate()
        self.set_l2_ac_vlan_tag(self.tx2_ac_trunk_port, self.tx2_vlan1)
        self.tx2_sw_ec1 = self.device.create_counter(1)
        self.tx2_ac_trunk_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.tx2_sw_ec1)

        # tw2_sw access port
        self.tx2_mac_port2 = T.mac_port(self, self.device, self.tx2_slice, self.tx2_ifg, self.serdes6, self.serdes7)
        self.tx2_sys_port2 = T.system_port(self, self.device, self.tx2_sys_access_port_gid, self.tx2_mac_port2)
        self.tx2_eth_port2 = T.sa_ethernet_port(self, self.device, self.tx2_sys_port2)
        self.tx2_ac_access_port = T.l2_ac_port(self, self.device, self.tx2_ac_access_port_gid, None,
                                               self.tx2_sw, self.tx2_eth_port2, self.zero_mac)
        self.tx2_mac_port2.activate()
        self.tx2_sw_ec2 = self.device.create_counter(1)
        self.tx2_ac_access_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.tx2_sw_ec2)

        # tx2_sw spa port
        self.tx2_mac_port3 = T.mac_port(self, self.device, self.tx2_slice, self.ifg1, self.serdes8, self.serdes9)
        self.tx2_sys_port3 = T.system_port(self, self.device, self.tx2_sys_spa_port_gid, self.tx2_mac_port3)
        self.tx2_mac_port3.activate()

        self.tx2_spa_port = T.spa_port(self, self.device, self.tx2_spa_port_gid)
        self.tx2_spa_port.add(self.tx2_sys_port3)
        self.tx2_spa_port.hld_obj.set_member_transmit_enabled(self.tx2_sys_port3.hld_obj, True)

        self.tx2_spa_eth_port = T.sa_ethernet_port(self, self.device, self.tx2_spa_port)
        self.tx2_spa_l2_ac_port = T.l2_ac_port(self, self.device, self.tx2_l2ac_spa_port_gid, None,
                                               self.tx2_sw, self.tx2_spa_eth_port, self.zero_mac)
        self.tx2_sw_ec3 = self.device.create_counter(1)
        self.tx2_spa_l2_ac_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.tx2_sw_ec3)

        # create and set flood destination for tx_sw and tx2_sw
        self.tx_sw_mc_group = self.device.create_l2_multicast_group(self.tx_sw_mc_group_id, sdk.la_replication_paradigm_e_EGRESS)
        self.assertIsNotNone(self.tx_sw_mc_group)
        self.tx_sw_mc_group.add(self.tx_ac_trunk_port.hld_obj, self.tx_sys_port1.hld_obj)
        self.tx_sw_mc_group.add(self.tx_ac_access_port.hld_obj, self.tx_sys_port2.hld_obj)
        self.tx_sw_mc_group.add(self.tx_spa_l2_ac_port.hld_obj, self.tx_sys_port3.hld_obj)
        self.tx_sw.hld_obj.set_flood_destination(self.tx_sw_mc_group)

        self.tx2_sw_mc_group = self.device.create_l2_multicast_group(self.tx2_sw_mc_group_id, sdk.la_replication_paradigm_e_EGRESS)
        self.assertIsNotNone(self.tx2_sw_mc_group)
        self.tx2_sw_mc_group.add(self.tx2_ac_trunk_port.hld_obj, self.tx2_sys_port1.hld_obj)
        self.tx2_sw_mc_group.add(self.tx2_ac_access_port.hld_obj, self.tx2_sys_port2.hld_obj)
        self.tx2_sw_mc_group.add(self.tx2_spa_l2_ac_port.hld_obj, self.tx2_sys_port3.hld_obj)
        self.tx2_sw.hld_obj.set_flood_destination(self.tx2_sw_mc_group)

    def create_l3(self):
        # vrf
        self.vrf = self.topology.vrf

        # svi's
        # rx_svi
        self.rx_svi = self.topology.rx_svi  # T.RX_SVI_GID: 0x711
        self.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        self.rx_svi_subnet = self.ip_impl.build_prefix(self.rx_svi_ip, length=16)
        self.ip_impl.add_subnet(self.rx_svi, self.rx_svi_subnet)

        # tx_svi
        self.tx_svi = self.topology.rx_svi1  # T.RX_SVI_GID1: 0x712
        self.tx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.tx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        self.tx_svi_subnet = self.ip_impl.build_prefix(self.tx_svi_host_ip, length=16)
        self.ip_impl.add_subnet(self.tx_svi, self.tx_svi_subnet)
        self.set_svi_tag(self.tx_svi, self.tx_vlan1)
        self.tx_svi_ec = self.device.create_counter(sdk.la_l3_protocol_e_LAST)
        self.tx_svi.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.tx_svi_ec)

        # tx2_svi
        self.tx2_svi = self.topology.tx_svi_ext  # T.TX_SVI_EXT_GID: 0x731
        self.tx2_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.tx2_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        self.tx2_svi_subnet = self.ip_impl.build_prefix(self.tx2_svi_ip, length=16)
        self.set_svi_tag(self.tx2_svi, self.tx2_vlan1)
        self.tx2_svi_ec = self.device.create_counter(sdk.la_l3_protocol_e_LAST)
        self.tx2_svi.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.tx2_svi_ec)

    def add_host(self):
        self.ip_impl.add_host(self.tx_svi, self.tx_svi_host_ip, self.tx_svi_host_mac)

    def delete_host(self):
        self.ip_impl.delete_host(self.tx_svi, self.tx_svi_host_ip)

    def add_route(self):
        # create next_hop
        self.next_hop = T.next_hop(self, self.device, self.nh_gid, self.nh_mac, self.tx2_svi)
        self.ip_impl.add_route(self.vrf, self.tx2_svi_subnet, self.next_hop, self.private_data)

    def delete_route(self):
        self.ip_impl.delete_route(self.vrf, self.tx2_svi_subnet)
        self.next_hop.destroy()

    def set_svi_tag(self, svi_port, vlan):
        tag = sdk.la_vlan_tag_t()
        tag.tpid = 0x8100
        tag.tci.fields.pcp = 0
        tag.tci.fields.dei = 0
        tag.tci.fields.vid = vlan
        svi_port.hld_obj.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)

    def set_l2_ac_vlan_tag(self, ac_port, vlan):
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = 0x8100
        eve.tag0.tci.fields.vid = vlan
        ac_port.hld_obj.set_egress_vlan_edit_command(eve)

    def create_inject_up_mac_eth_port(self):
        self.inject_up_mac_port = T.mac_port(self, self.device, self.slice0, self.ifg0, 10, 11)
        self.inject_up_mac_port.activate()
        self.inject_up_sys_port = T.system_port(self, self.device, self.sys_port_gid_base + 8, self.inject_up_mac_port)
        self.inject_up_mac_eth_port = T.sa_ethernet_port(self, self.device, self.inject_up_sys_port)

    def create_inject_up_rcy_eth_port(self):
        print("rcy system port gid is ", self.topology.recycle_ports[1].sys_port.hld_obj.get_gid())
        self.inject_up_rcy_eth_port = T.sa_ethernet_port(self, self.device, self.topology.recycle_ports[self.rcy_slice].sys_port)

    def create_inject_up_l2_ac_port(self, eth_port):
        # inject-up port for tx_sw
        self.tx_inject_up_l2ac_port = T.l2_ac_port(self, self.device, self.tx_inject_up_l2ac_port_gid, None,
                                                   self.tx_sw, eth_port, self.zero_mac, self.tx_vlan1,
                                                   0xDEF)
        self.tx_svi.hld_obj.set_inject_up_source_port(self.tx_inject_up_l2ac_port.hld_obj)

        # inject-up port for tx2_sw
        self.tx2_inject_up_l2ac_port = T.l2_ac_port(self, self.device, self.tx2_inject_up_l2ac_port_gid, None,
                                                    self.tx2_sw, eth_port, self.zero_mac,
                                                    self.tx2_vlan1, 0xABC)
        self.tx2_svi.hld_obj.set_inject_up_source_port(self.tx2_inject_up_l2ac_port.hld_obj)

    def set_inject_up_ive_data(self):
        # pop the two vlan tags in packet meant for recovering relay_id
        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 0
        ive.num_tags_to_pop = 2
        self.tx_inject_up_l2ac_port.hld_obj.set_ingress_vlan_edit_command(ive)
        self.tx2_inject_up_l2ac_port.hld_obj.set_ingress_vlan_edit_command(ive)

    def create_inject_up_on_mac_port(self):
        self.create_inject_up_mac_eth_port()
        self.create_inject_up_l2_ac_port(self.inject_up_mac_eth_port)
        self.set_inject_up_ive_data()

    def create_inject_up_on_rcy_port(self):
        self.create_inject_up_rcy_eth_port()
        self.create_inject_up_l2_ac_port(self.inject_up_rcy_eth_port)
        self.set_inject_up_ive_data()

    def delete_inject_up_port(self):
        self.tx_inject_up_l2ac_port.destroy()
        self.tx2_inject_up_l2ac_port.destroy()

    def install_mac(self):
        self.tx2_sw.hld_obj.set_mac_entry(self.nh_mac.hld_obj, self.tx2_ac_access_port.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

    def install_mac2(self):
        self.tx2_sw.hld_obj.set_mac_entry(self.nh_mac.hld_obj, self.tx2_ac_trunk_port.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

    def delete_mac(self):
        self.tx2_sw.hld_obj.remove_mac_entry(self.nh_mac.hld_obj)

    def install_host_mac(self):
        self.tx_sw.hld_obj.set_mac_entry(self.tx_svi_host_mac.hld_obj, self.tx_ac_access_port.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

    def install_host_mac2(self):
        self.tx_sw.hld_obj.set_mac_entry(self.tx_svi_host_mac.hld_obj, self.tx_ac_trunk_port.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

    def delete_host_mac(self):
        self.tx_sw.hld_obj.remove_mac_entry(self.tx_svi_host_mac.hld_obj)

    def do_test_counters(self, svi, port1, port2=None, port3=None, output_packet1=None, output_packet2=None):
        packet_count, byte_count = svi.read(self.protocol, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = port1.read(0, True, True)
        self.assertEqual(packet_count, 1)
        if (output_packet1 is not None):
            U.assertPacketLengthEgress(self, output_packet1, byte_count)
        if (port2 is not None):
            packet_count, byte_count = port2.read(0, True, True)
            self.assertEqual(packet_count, 1)
        if (port3 is not None):
            packet_count, byte_count = port3.read(0, True, True)
            self.assertEqual(packet_count, 1)
        if(output_packet2 is not None):
            U.assertPacketLengthEgress(self, output_packet2, byte_count)

    def do_test_svi_flood(self):
        # Host directly attached cases
        self.add_host()

        # ingress packet without vlan tag (from access port)
        ingress_packet = {'data': self.input_packet, 'slice': self.rx_slice, 'ifg': self.ifg0, 'pif': self.serdes6}
        egress_packets = []
        egress_packets.append({'data': self.output_packet, 'slice': self.tx_slice,
                               'ifg': self.ifg0, 'pif': self.serdes6})
        egress_packets.append({'data': self.output_packet, 'slice': self.tx_slice,
                               'ifg': self.ifg0, 'pif': self.serdes8})
        egress_packets.append({'data': self.output_packet_with_vlan, 'slice': self.tx_slice,
                               'ifg': self.ifg0, 'pif': self.serdes4})
        U.run_and_compare_list(self, self.device, ingress_packet, egress_packets)
        self.do_test_counters(self.tx_svi_ec, self.tx_sw_ec1, self.tx_sw_ec2, self.tx_sw_ec3,
                              self.output_packet_with_vlan, self.output_packet)

        # ingress packet with vlan tag (from trunk port)
        ingress_packet = {'data': self.input_packet_with_vlan, 'slice': self.rx_slice, 'ifg': self.ifg0, 'pif': self.serdes4}
        egress_packets = []
        egress_packets.append({'data': self.output_packet, 'slice': self.tx_slice,
                               'ifg': self.ifg0, 'pif': self.serdes6})
        egress_packets.append({'data': self.output_packet, 'slice': self.tx_slice,
                               'ifg': self.ifg0, 'pif': self.serdes8})
        egress_packets.append({'data': self.output_packet_with_vlan, 'slice': self.tx_slice,
                               'ifg': self.ifg0, 'pif': self.serdes4})
        U.run_and_compare_list(self, self.device, ingress_packet, egress_packets)
        self.do_test_counters(self.tx_svi_ec, self.tx_sw_ec1, self.tx_sw_ec2, self.tx_sw_ec3,
                              self.output_packet_with_vlan, self.output_packet)

        # install mac and check packet get unicast
        self.install_host_mac()
        U.run_and_compare(self, self.device,
                          self.input_packet, self.rx_slice, self.ifg0, self.serdes6,
                          self.output_packet, self.tx_slice, self.ifg0, self.serdes6)
        self.do_test_counters(self.tx_svi_ec, self.tx_sw_ec2)

        # delete mac and check flood again
        self.delete_host_mac()

        ingress_packet = {'data': self.input_packet_with_vlan, 'slice': self.rx_slice, 'ifg': self.ifg0, 'pif': self.serdes4}
        egress_packets = []
        egress_packets.append({'data': self.output_packet, 'slice': self.tx_slice,
                               'ifg': self.ifg0, 'pif': self.serdes6})
        egress_packets.append({'data': self.output_packet, 'slice': self.tx_slice,
                               'ifg': self.ifg0, 'pif': self.serdes8})
        egress_packets.append({'data': self.output_packet_with_vlan, 'slice': self.tx_slice,
                               'ifg': self.ifg0, 'pif': self.serdes4})
        U.run_and_compare_list(self, self.device, ingress_packet, egress_packets)
        self.do_test_counters(self.tx_svi_ec, self.tx_sw_ec1, self.tx_sw_ec2, self.tx_sw_ec3,
                              self.output_packet_with_vlan, self.output_packet)

        # add mac to different port and check unicast
        self.install_host_mac2()
        U.run_and_compare(self, self.device,
                          self.input_packet, self.rx_slice, self.ifg0, self.serdes6,
                          self.output_packet_with_vlan, self.tx_slice, self.ifg0, self.serdes4)
        self.do_test_counters(self.tx_svi_ec, self.tx_sw_ec1)

        self.delete_host()

        # Host behind route cases
        self.add_route()

        # ingress packet without vlan tag (from access port)
        ingress_packet = {'data': self.input_packet_nh, 'slice': self.rx_slice, 'ifg': self.ifg0, 'pif': self.serdes6}
        egress_packets = []
        egress_packets.append({'data': self.output_packet_nh, 'slice': self.tx2_slice,
                               'ifg': self.tx2_ifg, 'pif': self.serdes6})
        egress_packets.append({'data': self.output_packet_nh, 'slice': self.tx2_slice,
                               'ifg': self.ifg1, 'pif': self.serdes8})
        egress_packets.append({'data': self.output_packet_with_vlan_nh, 'slice': self.tx2_slice,
                               'ifg': self.tx2_ifg, 'pif': self.serdes4})
        U.run_and_compare_list(self, self.device, ingress_packet, egress_packets)
        self.do_test_counters(self.tx2_svi_ec, self.tx2_sw_ec1, self.tx2_sw_ec2, self.tx2_sw_ec3,
                              self.output_packet_with_vlan_nh, self.output_packet_nh)

        # ingress packet without vlan tag (from trunk port)
        ingress_packet = {'data': self.input_packet_with_vlan_nh, 'slice': self.rx_slice, 'ifg': self.ifg0, 'pif': self.serdes4}
        egress_packets = []
        egress_packets.append({'data': self.output_packet_nh, 'slice': self.tx2_slice,
                               'ifg': self.tx2_ifg, 'pif': self.serdes6})
        egress_packets.append({'data': self.output_packet_nh, 'slice': self.tx2_slice,
                               'ifg': self.ifg1, 'pif': self.serdes8})
        egress_packets.append({'data': self.output_packet_with_vlan_nh, 'slice': self.tx2_slice,
                               'ifg': self.tx2_ifg, 'pif': self.serdes4})
        U.run_and_compare_list(self, self.device, ingress_packet, egress_packets)
        self.do_test_counters(self.tx2_svi_ec, self.tx2_sw_ec1, self.tx2_sw_ec2, self.tx2_sw_ec3,
                              self.output_packet_with_vlan_nh, self.output_packet_nh)

        # add nh_mac to l2_port and check if packet is getting unicast (not flood)
        self.install_mac2()
        U.run_and_compare(self, self.device,
                          self.input_packet_nh, self.rx_slice, self.ifg0, self.serdes6,
                          self.output_packet_with_vlan_nh, self.tx2_slice, self.tx2_ifg, self.serdes4)
        self.do_test_counters(self.tx2_svi_ec, self.tx2_sw_ec1)

        # delete_mac and check if packet gets flooded again
        self.delete_mac()
        ingress_packet = {'data': self.input_packet_with_vlan_nh, 'slice': self.rx_slice, 'ifg': self.ifg0, 'pif': self.serdes4}
        egress_packets = []
        egress_packets.append({'data': self.output_packet_nh, 'slice': self.tx2_slice,
                               'ifg': self.tx2_ifg, 'pif': self.serdes6})
        egress_packets.append({'data': self.output_packet_nh, 'slice': self.tx2_slice,
                               'ifg': self.ifg1, 'pif': self.serdes8})
        egress_packets.append({'data': self.output_packet_with_vlan_nh, 'slice': self.tx2_slice,
                               'ifg': self.tx2_ifg, 'pif': self.serdes4})
        U.run_and_compare_list(self, self.device, ingress_packet, egress_packets)
        self.do_test_counters(self.tx2_svi_ec, self.tx2_sw_ec1, self.tx2_sw_ec2, self.tx2_sw_ec3,
                              self.output_packet_with_vlan_nh, self.output_packet_nh)

        # install nh_mac on different l2_port and check if packet is getting unicast
        self.install_mac()
        U.run_and_compare(self, self.device,
                          self.input_packet_nh, self.rx_slice, self.ifg0, self.serdes6,
                          self.output_packet_nh, self.tx2_slice, self.tx2_ifg, self.serdes6)
        self.do_test_counters(self.tx2_svi_ec, self.tx2_sw_ec2)

        self.delete_route()
