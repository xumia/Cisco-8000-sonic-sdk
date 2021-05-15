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
from scapy.all import *
from scapy.config import conf
conf.ipv6_enabled = False
import unittest
from leaba import sdk
import sim_utils
import topology as T
from sdk_test_case_base import *
import sim_utils
import nplapicli
import mtu.mtu_test_utils as MTU

IN_SLICE = T.get_device_slice(2)
IN_IFG = 0
IN_SERDES_FIRST = T.get_device_first_serdes(4)
IN_SERDES_LAST = IN_SERDES_FIRST + 1

OUT_SLICE = T.get_device_slice(4)
OUT_IFG = T.get_device_ifg(1)
OUT_SERDES_FIRST = T.get_device_next_first_serdes(8)
OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

OUT_SLICE1 = T.get_device_slice(1)
OUT_IFG1 = 0
OUT_SERDES_FIRST1 = T.get_device_out_first_serdes(12)
OUT_SERDES_LAST1 = OUT_SERDES_FIRST1 + 1

OUT_SLICE2 = OUT_SLICE
OUT_IFG2 = OUT_IFG
OUT_SERDES_FIRST2 = T.get_device_out_next_first_serdes(12)
OUT_SERDES_LAST2 = OUT_SERDES_FIRST2 + 1

SYS_PORT_GID_BASE = 23
AC_PORT_GID_BASE = 10

SWITCH_GID = 100

DST_MAC = 'ca:fe:ca:fe:ca:fe'
SRC_MAC = 'de:ad:de:ad:de:ad'
VLAN = 0xAB9

MC_GROUP_GID = 0x13

MC_GROUP_ADDR = T.ipv4_addr('225.1.2.3')
SRC_ADDR = T.ipv4_addr('1.1.1.1')

MC_GROUP_ADDR_V6 = T.ipv6_addr('ff01:0:0:0:0:1:ffe8:658f')
SIP_V6 = T.ipv6_addr('1111:0db8:0a0b:12f0:1234:5678:9abc:def1')


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class test_l2_multicast(sdk_test_case_base):

    def setUp(self):
        super().setUp()
        # MATILDA_SAVE -- need review
        global IN_SLICE, OUT_SLICE, OUT_SLICE2, OUT_SLICE1
        if (IN_SLICE not in self.device.get_used_slices()):
            IN_SLICE = T.choose_active_slices(self.device, IN_SLICE, [2, 3])
        if (OUT_SLICE not in self.device.get_used_slices()):
            OUT_SLICE = T.choose_active_slices(self.device, OUT_SLICE, [4, 0])
        if (OUT_SLICE1 not in self.device.get_used_slices()):
            OUT_SLICE1 = T.choose_active_slices(self.device, OUT_SLICE1, [1, 5])
        OUT_SLICE2 = OUT_SLICE

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
        self.create_packets()
        self.create_ipv6_mc_packets()
        self.create_ipv4_mc_packets()

    def get_mc_sa_addr_str(self, ip_addr):
        octets = ip_addr.addr_str.split('.')
        assert(len(octets) == 4)
        sa_addr_str = '01:00:5e'
        sa_addr_str += ':%02x' % (0x7f & int(octets[1]))
        for o in octets[2:]:
            sa_addr_str += ':%02x' % (int(o))
        return sa_addr_str

    def v6_get_mc_sa_addr_str(self, ip_addr):
        # https://tools.ietf.org/html/rfc2464#section-7
        shorts = ip_addr.addr_str.split(':')
        assert(len(shorts) == T.ipv6_addr.NUM_OF_SHORTS)
        sa_addr_str = '33:33'
        for s in shorts[-2:]:
            sl = int(s, 16) & 0xff
            sh = (int(s, 16) >> 8) & 0xff
            sa_addr_str += ':%02x:%02x' % (sh, sl)
        return sa_addr_str

    def create_ipv4_mc_packets(self):

        in_v4_packet_base = Ether(dst=self.get_mc_sa_addr_str(MC_GROUP_ADDR), src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP(dst=MC_GROUP_ADDR.addr_str,
               src=SRC_ADDR.addr_str,
               ttl=225) / \
            TCP()

        out_v4_packet_base = Ether(dst=self.get_mc_sa_addr_str(MC_GROUP_ADDR), src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP(dst=MC_GROUP_ADDR.addr_str,
               src=SRC_ADDR.addr_str,
               ttl=225) / \
            TCP()

        out_v4_packet_with_vlan_base = Ether(dst=self.get_mc_sa_addr_str(MC_GROUP_ADDR),
                                             src=SRC_MAC,
                                             type=Ethertype.Dot1Q.value) / Dot1Q(prio=2,
                                                                                 id=1,
                                                                                 vlan=VLAN + 2,
                                                                                 type=Ethertype.Dot1Q.value) / Dot1Q(prio=2,
                                                                                                                     id=1,
                                                                                                                     vlan=VLAN) / IP(dst=MC_GROUP_ADDR.addr_str,
                                                                                                                                     src=SRC_ADDR.addr_str,
                                                                                                                                     ttl=225) / TCP()

        self.in_v4_packet, self.out_v4_packet = pad_input_and_output_packets(in_v4_packet_base, out_v4_packet_base)
        __, self.out_v4_packet_with_vlan = pad_input_and_output_packets(in_v4_packet_base, out_v4_packet_with_vlan_base)

    def create_ipv6_mc_packets(self):
        in_v6_packet_base = \
            Ether(dst=self.v6_get_mc_sa_addr_str(MC_GROUP_ADDR_V6), src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IPv6(src=SIP_V6.addr_str, dst=MC_GROUP_ADDR_V6.addr_str, hlim=225) / \
            TCP()

        out_v6_packet_base = \
            Ether(dst=self.v6_get_mc_sa_addr_str(MC_GROUP_ADDR_V6), src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IPv6(src=SIP_V6.addr_str, dst=MC_GROUP_ADDR_V6.addr_str, hlim=225) / \
            TCP()

        out_v6_packet_with_vlan_base = \
            Ether(dst=self.v6_get_mc_sa_addr_str(MC_GROUP_ADDR_V6), src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN + 2, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IPv6(src=SIP_V6.addr_str, dst=MC_GROUP_ADDR_V6.addr_str, hlim=225) / \
            TCP()

        self.in_v6_packet, self.out_v6_packet = pad_input_and_output_packets(in_v6_packet_base, out_v6_packet_base)
        __, self.out_v6_packet_with_vlan = pad_input_and_output_packets(in_v6_packet_base, out_v6_packet_with_vlan_base)

    def create_packets(self):
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        out_packet_with_vlan_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN + 2, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        self.in_packet, self.out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)
        __, self.out_packet_with_vlan = pad_input_and_output_packets(in_packet_base, out_packet_with_vlan_base)

    def create_port_setup_disable(self):
        dest_mac = T.mac_addr(DST_MAC)
        self.in_ac_port.hld_obj.attach_to_switch(self.sw1.hld_obj)
        self.sw1.hld_obj.set_mac_entry(dest_mac.hld_obj, self.mc_group, sdk.LA_MAC_AGING_TIME_NEVER)

        # Create 2 output AC ports
        eth_port1 = T.sa_ethernet_port(self, self.device, self.out_sys_port1)
        self.ac_port1 = T.l2_ac_port(
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
        self.ac_port2 = T.l2_ac_port(
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
        self.mc_group.add(self.ac_port1.hld_obj, self.out_sys_port1.hld_obj)
        self.mc_group.add(self.ac_port2.hld_obj, self.out_sys_port2.hld_obj)

    def test_empty_mcg(self):
        run_and_drop(self, self.device, self.in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    def test_l2_forwarding(self):
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
        ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE1, 'ifg': OUT_IFG1, 'pif': OUT_SERDES_FIRST1})
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    def test_l2_members_same_sys_port(self):
        self.in_ac_port.hld_obj.set_destination(self.mc_group)

        # Create 2 output AC ports over the same ethernet port
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
        ac_port2 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 2,
            self.topology.filter_group_def,
            self.sw1,
            eth_port1,
            None,
            VLAN + 1,
            0x0)

        # Push extra tag to 2nd member to distinguish between the packets
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = VLAN + 2

        ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        # Add the output AC ports to the MC group
        self.mc_group.add(ac_port1.hld_obj, self.out_sys_port1.hld_obj)
        self.mc_group.add(ac_port2.hld_obj, self.out_sys_port1.hld_obj)

        # Run the packet and check results
        ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST})
        expected_packets.append({'data': self.out_packet_with_vlan, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # Remove the first member
        self.mc_group.remove(ac_port1.hld_obj)

        # Run after removal
        run_and_compare_list(self, self.device, ingress_packet, expected_packets[1:])

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    def test_l2_p2p(self):
        self.in_ac_port.hld_obj.set_destination(self.mc_group)
        # Create 2 output AC ports
        eth_port1 = T.sa_ethernet_port(self, self.device, self.out_sys_port1)
        ac_port1 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 1,
            self.topology.filter_group_def,
            None,
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
            None,
            eth_port2,
            None,
            VLAN,
            0x0)

        # Add the output AC ports to the MC group
        self.mc_group.add(ac_port1.hld_obj, self.out_sys_port1.hld_obj)
        self.mc_group.add(ac_port2.hld_obj, self.out_sys_port2.hld_obj)

        # Run the packet and check results
        ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE1, 'ifg': OUT_IFG1, 'pif': OUT_SERDES_FIRST1})
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    def test_l2_switch_flooding(self):
        self.in_ac_port.hld_obj.attach_to_switch(self.sw1.hld_obj)
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

        self.mc_group.add(ac_port1.hld_obj, self.out_sys_port1.hld_obj)
        self.mc_group.add(ac_port2.hld_obj, self.out_sys_port2.hld_obj)

        input_p_counter = self.device.create_counter(1)
        self.in_ac_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, input_p_counter)

        output_p_counter = self.device.create_counter(1)
        ac_port1.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, output_p_counter)

        # Run the packet and check results
        ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE1, 'ifg': OUT_IFG1, 'pif': OUT_SERDES_FIRST1})
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        packet_count, byte_count = input_p_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        packet_count, byte_count = output_p_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv6_l2_multicat_with_snooping(self):

        mrouter_group = self.device.create_l2_multicast_group(MC_GROUP_GID + 1, sdk.la_replication_paradigm_e_EGRESS)
        self.assertIsNotNone(mrouter_group)

        l2_mc_group = self.device.create_l2_multicast_group(MC_GROUP_GID + 12, sdk.la_replication_paradigm_e_EGRESS)
        self.assertIsNotNone(l2_mc_group)

        self.in_ac_port.hld_obj.attach_to_switch(self.sw1.hld_obj)
        # Create 3 output AC ports
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
        out_mac_port3 = T.mac_port(self, self.device, OUT_SLICE2, OUT_IFG2, OUT_SERDES_FIRST2, OUT_SERDES_LAST2)
        out_sys_port3 = T.system_port(self, self.device, SYS_PORT_GID_BASE + 3, out_mac_port3)
        out_mac_port3.activate()
        eth_port3 = T.sa_ethernet_port(self, self.device, out_sys_port3)
        ac_port3 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 3,
            self.topology.filter_group_def,
            self.sw1,
            eth_port3,
            None,
            VLAN,
            0x0)

        ingress_packet = {'data': self.in_v6_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}

        # Case1: Packet going out of flood port.
        self.mc_group.add(ac_port1.hld_obj, self.out_sys_port1.hld_obj)
        self.mc_group.add(ac_port2.hld_obj, self.out_sys_port2.hld_obj)
        self.mc_group.add(ac_port3.hld_obj, out_sys_port3.hld_obj)
        expected_packets = []
        expected_packets.append({'data': self.out_v6_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST})
        expected_packets.append({'data': self.out_v6_packet, 'slice': OUT_SLICE1, 'ifg': OUT_IFG1, 'pif': OUT_SERDES_FIRST1})
        expected_packets.append({'data': self.out_v6_packet, 'slice': OUT_SLICE2, 'ifg': OUT_IFG2, 'pif': OUT_SERDES_FIRST2})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # Case2: Packet going out of mrouter port but not on flood port when the snooping is enabled.
        mrouter_group.add(ac_port2.hld_obj, self.out_sys_port2.hld_obj)
        self.sw1.hld_obj.set_ipv6_multicast_enabled(True)
        ipv6_multicast_enabled = self.sw1.hld_obj.get_ipv6_multicast_enabled()
        self.assertTrue(ipv6_multicast_enabled)
        expected_packets = []
        expected_packets.append({'data': self.out_v6_packet, 'slice': OUT_SLICE1, 'ifg': OUT_IFG1, 'pif': OUT_SERDES_FIRST1})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # Case3: Packet going out of listner ports on l2 mc group.
        l2_mc_group.add(ac_port2.hld_obj, self.out_sys_port2.hld_obj)
        l2_mc_group.add(ac_port3.hld_obj, out_sys_port3.hld_obj)
        self.sw1.hld_obj.add_ipv6_multicast_route(MC_GROUP_ADDR_V6.hld_obj, l2_mc_group)
        expected_packets = []
        expected_packets.append({'data': self.out_v6_packet, 'slice': OUT_SLICE1, 'ifg': OUT_IFG1, 'pif': OUT_SERDES_FIRST1})
        expected_packets.append({'data': self.out_v6_packet, 'slice': OUT_SLICE2, 'ifg': OUT_IFG2, 'pif': OUT_SERDES_FIRST2})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)
        self.sw1.hld_obj.delete_ipv6_multicast_route(MC_GROUP_ADDR_V6.hld_obj)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_l2_multicat_with_snooping(self):

        mrouter_group = self.device.create_l2_multicast_group(MC_GROUP_GID + 1, sdk.la_replication_paradigm_e_EGRESS)
        self.assertIsNotNone(mrouter_group)

        l2_mc_group = self.device.create_l2_multicast_group(MC_GROUP_GID + 12, sdk.la_replication_paradigm_e_EGRESS)
        self.assertIsNotNone(l2_mc_group)

        self.in_ac_port.hld_obj.attach_to_switch(self.sw1.hld_obj)
        # Create 3 output AC ports
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
        out_mac_port3 = T.mac_port(self, self.device, OUT_SLICE2, OUT_IFG2, OUT_SERDES_FIRST2, OUT_SERDES_LAST2)
        out_sys_port3 = T.system_port(self, self.device, SYS_PORT_GID_BASE + 3, out_mac_port3)
        out_mac_port3.activate()
        eth_port3 = T.sa_ethernet_port(self, self.device, out_sys_port3)
        ac_port3 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 3,
            self.topology.filter_group_def,
            self.sw1,
            eth_port3,
            None,
            VLAN,
            0x0)

        ingress_packet = {'data': self.in_v4_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}

        # Case1: Packet going out of flood port.
        self.mc_group.add(ac_port1.hld_obj, self.out_sys_port1.hld_obj)
        self.mc_group.add(ac_port2.hld_obj, self.out_sys_port2.hld_obj)
        self.mc_group.add(ac_port3.hld_obj, out_sys_port3.hld_obj)
        expected_packets = []
        expected_packets.append({'data': self.out_v4_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST})
        expected_packets.append({'data': self.out_v4_packet, 'slice': OUT_SLICE1, 'ifg': OUT_IFG1, 'pif': OUT_SERDES_FIRST1})
        expected_packets.append({'data': self.out_v4_packet, 'slice': OUT_SLICE2, 'ifg': OUT_IFG2, 'pif': OUT_SERDES_FIRST2})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # Case2: Packet going out of mrouter port but not on flood port when the snooping is enabled.
        mrouter_group.add(ac_port2.hld_obj, self.out_sys_port2.hld_obj)
        self.sw1.hld_obj.set_ipv4_multicast_enabled(True)
        ipv4_multicast_enabled = self.sw1.hld_obj.get_ipv4_multicast_enabled()
        self.assertTrue(ipv4_multicast_enabled)
        expected_packets = []
        expected_packets.append({'data': self.out_v4_packet, 'slice': OUT_SLICE1, 'ifg': OUT_IFG1, 'pif': OUT_SERDES_FIRST1})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # Case3: Packet going out of listner ports on l2 mc group.
        l2_mc_group.add(ac_port2.hld_obj, self.out_sys_port2.hld_obj)
        l2_mc_group.add(ac_port3.hld_obj, out_sys_port3.hld_obj)
        self.sw1.hld_obj.add_ipv4_multicast_route(MC_GROUP_ADDR.hld_obj, l2_mc_group)
        expected_packets = []
        expected_packets.append({'data': self.out_v4_packet, 'slice': OUT_SLICE1, 'ifg': OUT_IFG1, 'pif': OUT_SERDES_FIRST1})
        expected_packets.append({'data': self.out_v4_packet, 'slice': OUT_SLICE2, 'ifg': OUT_IFG2, 'pif': OUT_SERDES_FIRST2})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)
        self.sw1.hld_obj.delete_ipv4_multicast_route(MC_GROUP_ADDR.hld_obj)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    def test_l2_switch_flooding_dest_on_same_slice(self):
        self.in_ac_port.hld_obj.attach_to_switch(self.sw1.hld_obj)
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

        eth_port2_serdes_first = T.get_device_next2_first_serdes(OUT_SERDES_FIRST + 4)
        eth_port2_serdes_last = T.get_device_next2_last_serdes(OUT_SERDES_LAST + 4)
        eth_port2 = T.ethernet_port(
            self,
            self.device,
            OUT_SLICE,
            OUT_IFG,
            SYS_PORT_GID_BASE + 3,
            eth_port2_serdes_first,
            eth_port2_serdes_last)
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
        self.mc_group.add(ac_port2.hld_obj, eth_port2.sys_port.hld_obj)

        # Run the packet and check results
        ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST})
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST + 4})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    def test_l2_switch_flooding_dest_remove_first_member(self):
        self.in_ac_port.hld_obj.attach_to_switch(self.sw1.hld_obj)
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

        eth_port2_serdes_first = T.get_device_next2_first_serdes(OUT_SERDES_FIRST + 4)
        eth_port2_serdes_last = T.get_device_next2_last_serdes(OUT_SERDES_LAST + 4)
        eth_port2 = T.ethernet_port(
            self,
            self.device,
            OUT_SLICE,
            OUT_IFG,
            SYS_PORT_GID_BASE + 3,
            eth_port2_serdes_first,
            eth_port2_serdes_last)
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

        self.mc_group.add(ac_port1.hld_obj, self.out_sys_port1.hld_obj)
        self.mc_group.add(ac_port2.hld_obj, eth_port2.sys_port.hld_obj)

        # Run the packet and check results
        ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST})
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST + 4})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # Remove a member
        self.mc_group.remove(ac_port1.hld_obj)

        # Re-run
        run_and_compare_list(self, self.device, ingress_packet, expected_packets[1:])

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    def test_l2_switch_flooding_dest_remove_last_member(self):
        self.in_ac_port.hld_obj.attach_to_switch(self.sw1.hld_obj)
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

        eth_port2_serdes_first = T.get_device_next2_first_serdes(OUT_SERDES_FIRST + 4)
        eth_port2_serdes_last = T.get_device_next2_last_serdes(OUT_SERDES_LAST + 4)
        eth_port2 = T.ethernet_port(
            self,
            self.device,
            OUT_SLICE,
            OUT_IFG,
            SYS_PORT_GID_BASE + 3,
            eth_port2_serdes_first,
            eth_port2_serdes_last)
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

        self.mc_group.add(ac_port1.hld_obj, self.out_sys_port1.hld_obj)
        self.mc_group.add(ac_port2.hld_obj, eth_port2.sys_port.hld_obj)

        # Run the packet and check results
        ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST})
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST + 4})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # Remove a member
        self.mc_group.remove(ac_port2.hld_obj)

        # Re-run
        run_and_compare_list(self, self.device, ingress_packet, expected_packets[:1])

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    def test_l2_switch_flooding_single(self):
        self.in_ac_port.hld_obj.attach_to_switch(self.sw1.hld_obj)
        eth_port = T.sa_ethernet_port(self, self.device, self.out_sys_port1)
        ac_port = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 1,
            self.topology.filter_group_def,
            self.sw1,
            eth_port,
            None,
            VLAN,
            0x0)
        self.mc_group.add(ac_port.hld_obj, self.out_sys_port1.hld_obj)

        # Run the packet and check results
        ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_dsp_different_slice(self):
        self.in_ac_port.hld_obj.attach_to_switch(self.sw1.hld_obj)
        # Create SPA and add the first system port to it
        spa_port = T.spa_port(self, self.device, 123)
        spa_port.add(self.out_sys_port1)
        spa_port.add(self.out_sys_port2)

        # Create an AC port over the SPA
        eth_port = T.sa_ethernet_port(self, self.device, spa_port)
        ac_port = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE + 1, None, self.sw1, eth_port, None, VLAN, 0x0)
        self.mc_group.add(ac_port.hld_obj, self.out_sys_port1.hld_obj)

        # Run the packet and check results
        ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE,
                                 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST})  # out_sys_port1
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # Change the dsp
        self.mc_group.set_destination_system_port(ac_port.hld_obj, self.out_sys_port2.hld_obj)

        # Re-run the packet and check results
        ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE1, 'ifg': OUT_IFG1,
                                 'pif': OUT_SERDES_FIRST1})  # out_sys_port2
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_dsp_same_slice(self):
        self.in_ac_port.hld_obj.attach_to_switch(self.sw1.hld_obj)
        # Create SPA and add the first system port to it
        spa_port = T.spa_port(self, self.device, 123)
        spa_port.add(self.out_sys_port1)

        # Create a system port on the same slice like the first system port, so that the SPA will
        # not get ifg-remove notification when the system port is removed
        out_mac_port_first_serdes = T.get_device_next3_first_serdes(0)
        out_mac_port_last_serdes = T.get_device_next3_last_serdes(1)
        out_mac_port = T.mac_port(self, self.device, OUT_SLICE, OUT_IFG, out_mac_port_first_serdes, out_mac_port_last_serdes)
        out_sys_port = T.system_port(self, self.device, SYS_PORT_GID_BASE + 3, out_mac_port)
        spa_port.add(out_sys_port)

        out_mac_port.activate()

        # Create an AC port over the SPA
        eth_port = T.sa_ethernet_port(self, self.device, spa_port)
        ac_port = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE + 1, None, self.sw1, eth_port, None, VLAN, 0x0)
        self.mc_group.add(ac_port.hld_obj, out_sys_port.hld_obj)

        # Run the packet and check results
        ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG,
                                 'pif': out_mac_port_first_serdes})  # PIF of local system port
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # Change the dsp
        self.mc_group.set_destination_system_port(ac_port.hld_obj, self.out_sys_port1.hld_obj)

        # Re-run the packet and check results
        ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG,
                                 'pif': OUT_SERDES_FIRST})  # PIF of the global port
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def test_two_groups_same_port(self):
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

        self.mc_group.add(ac_port1.hld_obj, self.out_sys_port1.hld_obj)

        mc_group2 = self.device.create_l2_multicast_group(MC_GROUP_GID + 1, sdk.la_replication_paradigm_e_EGRESS)
        mc_group2.add(ac_port1.hld_obj, self.out_sys_port1.hld_obj)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_remove_member_over_spa(self):
        self.in_ac_port.hld_obj.attach_to_switch(self.sw1.hld_obj)
        print("----- Matilda type=", self.device.get_int_property(sdk.la_device_property_e_MATILDA_MODEL_TYPE))
        spa_p_pif = 16
        if self.device.get_int_property(sdk.la_device_property_e_MATILDA_MODEL_TYPE) in [4, 5]:
            spa_p_pif = 14
        print("----- spa_p_pif=", spa_p_pif)
        mac_port1 = T.mac_port(self, self.device, 0, 0, spa_p_pif, spa_p_pif + 1)
        mac_port2 = T.mac_port(self, self.device, 1, 0, 8, 9)

        sys_port1 = T.system_port(self, self.device, 0x10, mac_port1)
        sys_port2 = T.system_port(self, self.device, 0x20, mac_port2)

        spa_port = T.spa_port(self, self.device, 0x40)
        spa_port.add(sys_port1)

        eth_port = T.sa_ethernet_port(self, self.device, spa_port)
        mac_addr = T.mac_addr('71:72:73:74:25:76')
        l2_ac_port = T.l2_ac_port(self, self.device,
                                  0x50,  # GID
                                  None,  # filter group
                                  None,  # switch
                                  eth_port,
                                  mac_addr)

        self.mc_group = self.device.create_l2_multicast_group(0x50, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_group.add(l2_ac_port.hld_obj, sys_port1.hld_obj)

        spa_port.add(sys_port2)

        self.mc_group.remove(l2_ac_port.hld_obj)

    def test_l2_p2p_mtu(self):
        self.in_ac_port.hld_obj.set_destination(self.mc_group)

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
        ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE1, 'ifg': OUT_IFG1,
                                 'pif': OUT_SERDES_FIRST1, 'skip_mtu_test': True})
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG,
                                 'pif': OUT_SERDES_FIRST, 'skip_mtu_test': True})
        MTU.run_mtu_tests(self, self.device, ingress_packet, expected_packets)

    def test_l2_members_same_sys_port_mtu(self):
        self.in_ac_port.hld_obj.set_destination(self.mc_group)

        # Create 2 output AC ports over the same ethernet port
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
        ac_port2 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 2,
            self.topology.filter_group_def,
            self.sw1,
            eth_port1,
            None,
            VLAN + 1,
            0x0)

        # Push extra tag to 2nd member to distinguish between the packets
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = VLAN + 2

        ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        # Add the output AC ports to the MC group
        self.mc_group.add(ac_port1.hld_obj, self.out_sys_port1.hld_obj)
        self.mc_group.add(ac_port2.hld_obj, self.out_sys_port1.hld_obj)

        # Run the packet and check results
        ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG,
                                 'pif': OUT_SERDES_FIRST, 'skip_mtu_test': True})
        expected_packets.append({'data': self.out_packet_with_vlan, 'slice': OUT_SLICE,
                                 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST, 'skip_mtu_test': True})
        MTU.run_mtu_tests(self, self.device, ingress_packet, expected_packets)

    # disable tx and rx port
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_forwarding_with_disable_rx(self):
        self.create_port_setup_disable()
        # Run the packet and check results
        ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE1, 'ifg': OUT_IFG1, 'pif': OUT_SERDES_FIRST1})
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)
        self.in_ac_port.hld_obj.disable()
        run_and_drop(self, self.device, self.in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)
        self.device.destroy(self.in_ac_port.hld_obj)
        run_and_drop(self, self.device, self.in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_forwarding_with_disable_tx1(self):
        self.create_port_setup_disable()
        # Run the packet and check results
        ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        expected_packets_disable = []
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE1, 'ifg': OUT_IFG1, 'pif': OUT_SERDES_FIRST1})
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        self.ac_port1.hld_obj.disable()
        expected_packets_disable.append({'data': self.out_packet, 'slice': OUT_SLICE1, 'ifg': OUT_IFG1, 'pif': OUT_SERDES_FIRST1})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets_disable)

        self.mc_group.remove(self.ac_port1.hld_obj)
        self.device.destroy(self.ac_port1.hld_obj)
        run_and_compare_list(self, self.device, ingress_packet, expected_packets_disable)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_forwarding_with_disable_tx2(self):
        self.create_port_setup_disable()
        # Run the packet and check results
        ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        expected_packets_disable = []
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE1, 'ifg': OUT_IFG1, 'pif': OUT_SERDES_FIRST1})
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        self.ac_port2.hld_obj.disable()
        expected_packets_disable.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets_disable)

        self.mc_group.remove(self.ac_port2.hld_obj)
        self.device.destroy(self.ac_port2.hld_obj)
        run_and_compare_list(self, self.device, ingress_packet, expected_packets_disable)


if __name__ == '__main__':
    unittest.main()
