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

from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import ip_test_base
import sim_utils
import topology as T
from sdk_test_case_base import *
import smart_slices_choise as ssch
import decor

import nplapicli as nplapi
import decor

PRIVATE_DATA_DEFAULT = 0xfedcba9876543210

SYS_PORT_GID_BASE = 23

IN_SLICE = T.get_device_slice(3)  # must be an odd number
IN_IFG = T.get_device_ifg(0)
IN_PIF_FIRST = T.get_device_first_serdes(4)
IN_PIF_LAST = IN_PIF_FIRST + 1
OUT_SLICE = T.get_device_slice(4)
OUT_IFG = T.get_device_ifg(1)
OUT_IFG_ETH3 = T.get_device_ifg(0)
OUT_PIF_FIRST = T.get_device_out_first_serdes(8)
OUT_PIF_LAST = OUT_PIF_FIRST + 1
OUT_PIF_ETH3_FIRST = T.get_device_out_next_first_serdes(10)
OUT_PIF_ETH3_LAST = OUT_PIF_ETH3_FIRST + 1

IN_SP_GID = SYS_PORT_GID_BASE
OUT_SP_GID = SYS_PORT_GID_BASE + 1
OUT_SP_GID_ETH3 = SYS_PORT_GID_BASE + 100
RECYCLE_SP_GID = SYS_PORT_GID_BASE + 3

AC_PORT_GID_BASE = 10

SWITCH_GID = 100

DST_MAC = T.mac_addr('ca:fe:ca:fe:ca:fe')
SRC_MAC = T.mac_addr('de:ad:de:ad:de:ad')
MCID_MAC = T.mac_addr('00:fe:ca:fe:ca:fe')
VLAN = 0xAB9

PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
HOST_MAC_ADDR = "fe:dc:ba:98:76:54"

PUNT_VLAN = 0xA13

MIRROR_CMD_GID = 9

MIRROR_GID_INGRESS_OFFSET = 32
MIRROR_GID_EGRESS_OFFSET = 0
MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET

MIRROR_VLAN = 0xA12

MCID = 0x15
FLOOD_MCID = MCID + 1


class punt_inject_port_base(sdk_test_case_base):
    PRIVATE_DATA = 0x1234567890abcdef
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    TTL = 128
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    INJECT_SLICE = T.get_device_slice(2)  # must be an even number
    INJECT_IFG = T.get_device_ifg(0)
    INJECT_PIF_FIRST = T.get_device_next_first_serdes(8)
    INJECT_PIF_LAST = INJECT_PIF_FIRST + 1
    INJECT_SP_GID = SYS_PORT_GID_BASE + 2

    def setUp(self):
        super().setUp()
        ssch.rechoose_even_inject_slice(self, self.device)

        # MATILDA_SAVE -- need review
        global IN_SLICE, OUT_SLICE
        IN_SLICE = T.choose_active_slices(self.device, IN_SLICE, [3, 1])
        OUT_SLICE = T.choose_active_slices(self.device, OUT_SLICE, [5, 0])
        self.IN_SLICE, self.OUT_SLICE = IN_SLICE, OUT_SLICE

        self.create_system_setup()
        self.create_packets()

    def create_packets(self):
        in_packet_base = Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        out_packet_base = Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        self.in_packet, self.out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

    def create_system_setup(self):
        self.sw1 = T.switch(self, self.device, SWITCH_GID)
        self.ac_profile = T.ac_profile(self, self.device)

        # Add 'cafecafecafe' to the MAC table, going to AC port 2
        self.dest_mac = DST_MAC

        self.eth_port1 = T.ethernet_port(
            self, self.device, IN_SLICE, IN_IFG, IN_SP_GID, IN_PIF_FIRST, IN_PIF_LAST)
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
            self, self.device, OUT_SLICE, OUT_IFG, OUT_SP_GID, OUT_PIF_FIRST, OUT_PIF_LAST)
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

        self.eth_port3 = T.ethernet_port(
            self, self.device, OUT_SLICE, OUT_IFG_ETH3, OUT_SP_GID_ETH3, OUT_PIF_ETH3_FIRST, OUT_PIF_ETH3_LAST)
        self.eth_port3.set_ac_profile(self.ac_profile)
        self.ac_port3 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 2,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port3,
            None,
            VLAN,
            0x0)

    def add_default_route(self):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = 0x0
        prefix.length = 0
        self.topology.vrf.hld_obj.add_ipv4_route(
            prefix, self.topology.nh_l3_ac_def.hld_obj, PRIVATE_DATA_DEFAULT, False)

    def _test_inject_down(self):
        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        # Regular packet flow
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

        dest_id = sdk.la_get_destination_id_from_gid(sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP, OUT_SP_GID)

        self.inject_down_packet = \
            Ether(dst=PUNT_INJECT_PORT_MAC_ADDR, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=Ethertype.Inject.value) / \
            InjectDown(dest=dest_id, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            self.in_packet

        run_and_compare(
            self,
            self.device,
            self.inject_down_packet,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_PIF_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

    def _test_inject_mcid(self):
        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        in_mcid_packet_base = Ether(dst=MCID_MAC.addr_str, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        out_mcid_packet_base = Ether(dst=MCID_MAC.addr_str, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        in_mcid_packet, out_mcid_packet = pad_input_and_output_packets(in_mcid_packet_base, out_mcid_packet_base)

        mc_group_flood = self.device.create_l2_multicast_group(FLOOD_MCID, sdk.la_replication_paradigm_e_EGRESS)
        self.assertIsNotNone(mc_group_flood)
        mc_group_flood.add(self.ac_port2.hld_obj, self.eth_port2.sys_port.hld_obj)
        mc_group_flood.add(self.ac_port3.hld_obj, self.eth_port3.sys_port.hld_obj)
        self.sw1.hld_obj.set_flood_destination(mc_group_flood)

        mc_group_mcid = self.device.create_l2_multicast_group(MCID, sdk.la_replication_paradigm_e_EGRESS)
        self.assertIsNotNone(mc_group_mcid)
        mc_group_mcid.add(self.ac_port2.hld_obj, self.eth_port2.sys_port.hld_obj)

        ingress_packet = {'data': in_mcid_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_PIF_FIRST}
        expected_packets = []
        expected_packets.append({'data': out_mcid_packet, 'slice': OUT_SLICE,
                                 'ifg': OUT_IFG, 'pif': OUT_PIF_FIRST})
        expected_packets.append({'data': out_mcid_packet, 'slice': OUT_SLICE,
                                 'ifg': OUT_IFG_ETH3, 'pif': OUT_PIF_ETH3_FIRST})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        dest_id = sdk.la_get_destination_id_from_gid(
            sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP,
            T.RCY_SYS_PORT_GID_BASE - IN_SLICE)

        inject_mcid_packet = \
            Ether(dst=PUNT_INJECT_PORT_MAC_ADDR, src=HOST_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=Ethertype.Inject.value) / \
            InjectDown(dest=dest_id, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            Ether(dst=PUNT_INJECT_PORT_MAC_ADDR, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=Ethertype.Inject.value) / \
            InjectUpDestOverride(destination=0xe0015, ssp_gid=IN_SP_GID) / \
            in_mcid_packet

        ingress_packet = {
            'data': inject_mcid_packet,
            'slice': self.INJECT_SLICE,
            'ifg': self.INJECT_IFG,
            'pif': self.INJECT_PIF_FIRST}

        expected_packets = []
        expected_packets.append({'data': out_mcid_packet, 'slice': OUT_SLICE,
                                 'ifg': OUT_IFG, 'pif': OUT_PIF_FIRST})

        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def _test_inject_down_and_up(self):
        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        # Regular packet flow
        #run_and_compare(self, self.in_packet, IN_SLICE, IN_IFG, IN_PIF_FIRST, self.out_packet, OUT_SLICE, OUT_IFG, OUT_PIF_FIRST)

        # SYS_PORT_GID of the RCY port is needed. See topology. See topology how it assigned.
        dest_id = sdk.la_get_destination_id_from_gid(
            sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP,
            T.RCY_SYS_PORT_GID_BASE - IN_SLICE)
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def _test_inject_down_and_up(self):
        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        # Regular packet flow
        #run_and_compare(self, self.in_packet, IN_SLICE, IN_IFG, IN_PIF_FIRST, self.out_packet, OUT_SLICE, OUT_IFG, OUT_PIF_FIRST)

        # SYS_PORT_GID of the RCY port is needed. See topology. See topology how it assigned.
        dest_id = sdk.la_get_destination_id_from_gid(
            sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP,
            T.RCY_SYS_PORT_GID_BASE - IN_SLICE)

        self.inject_down_up_packet = \
            Ether(dst=PUNT_INJECT_PORT_MAC_ADDR, src=HOST_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=Ethertype.Inject.value) / \
            InjectDown(dest=dest_id, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            Ether(dst=PUNT_INJECT_PORT_MAC_ADDR, src=HOST_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=Ethertype.Inject.value) / \
            InjectUp(ssp_gid=IN_SP_GID) / \
            self.in_packet

        run_and_compare(
            self,
            self.device,
            self.inject_down_up_packet,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_PIF_FIRST,
            self.out_packet,
            OUT_SLICE, OUT_IFG, OUT_PIF_FIRST)

    def _test_inject_down_pci(self):
        pi_port = self.topology.inject_ports[self.INJECT_SLICE]
        pci_serdes = self.device.get_pci_serdes()

        # Regular packet flow
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

        dest_id = sdk.la_get_destination_id_from_gid(sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP, OUT_SP_GID)

        self.inject_down_packet = \
            Ether(dst=PUNT_INJECT_PORT_MAC_ADDR, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=Ethertype.Inject.value) / \
            InjectDown(dest=dest_id, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            self.in_packet

        run_and_compare(
            self,
            self.device,
            self.inject_down_packet,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            pci_serdes,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

    def _test_inject_up(self):
        pi_port = T.punt_inject_port(
            self,
            self.device,
            IN_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        # Regular packet flow
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

        self.inject_up_packet = \
            Ether(dst=PUNT_INJECT_PORT_MAC_ADDR, src=HOST_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=Ethertype.Inject.value) / \
            InjectUp(ssp_gid=IN_SP_GID) / \
            self.in_packet

        run_and_compare(
            self,
            self.device,
            self.inject_up_packet,
            IN_SLICE,
            self.INJECT_IFG,
            self.INJECT_PIF_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

    def _test_inject_up_ipv6_nd(self):

        DIP_LL_MC = T.ipv6_addr('ff02:0000:0000:0000:0000:0000:0000:1234')

        in_packet_base = \
            Ether(dst='33:33:00:00:12:34', src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=VLAN) / \
            IPv6(dst=DIP_LL_MC.addr_str) / \
            ICMPv6ND_NS() / \
            ICMPv6NDOptSrcLLAddr(lladdr='01:23:45:67:89:ab')

        self.in_packet, self.out_packet = pad_input_and_output_packets(in_packet_base, in_packet_base)

        self.sw1.hld_obj.set_flood_destination(self.ac_port2.hld_obj)

        pi_port = T.punt_inject_port(
            self,
            self.device,
            IN_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        self.inject_up_packet = \
            Ether(dst=PUNT_INJECT_PORT_MAC_ADDR, src=HOST_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=Ethertype.Inject.value) / \
            InjectUp(ssp_gid=IN_SP_GID) / \
            self.in_packet

        run_and_compare(
            self,
            self.device,
            self.inject_up_packet,
            IN_SLICE,
            self.INJECT_IFG,
            self.INJECT_PIF_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

    def _test_inject_up_with_trailer(self):
        pi_port = T.punt_inject_port(
            self,
            self.device,
            IN_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        # Regular packet flow
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

        self.inject_up_packet = \
            Ether(dst=PUNT_INJECT_PORT_MAC_ADDR, src=HOST_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=Ethertype.Inject.value) / \
            InjectUpDirectWithTrailer(ssp_gid=IN_SP_GID) / \
            self.in_packet

        run_and_compare(
            self,
            self.device,
            self.inject_up_packet,
            IN_SLICE,
            self.INJECT_IFG,
            self.INJECT_PIF_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

    def _test_punt_inject_creation(self):
        pi_port = self.topology.inject_ports[self.INJECT_SLICE]

        punt_dest_l2 = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN)
        # create the same destination again
        try:
            punt_dest_l3 = T.create_l2_punt_destination(
                self, self.device, T.L2_PUNT_DESTINATION2_GID, pi_port, HOST_MAC_ADDR, PUNT_VLAN)
            self.assertFail()
        except sdk.BaseException:
            pass

    def _test_punt_trap(self):
        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        punt_dest = T.create_l2_punt_destination(self, self.device, T.L2_PUNT_DESTINATION2_GID, pi_port, HOST_MAC_ADDR, PUNT_VLAN)

        priority = 0
        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_IP_UNICAST_RPF)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_IP_UNICAST_RPF, priority, None, punt_dest, False, False, True, 0)

        try:
            self.device.destroy(punt_dest)
            self.assertFail()
        except sdk.BaseException:
            pass

    def _test_punt_trap_fail(self):
        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        punt_dest = T.create_l2_punt_destination(self, self.device, T.L2_PUNT_DESTINATION2_GID, pi_port, HOST_MAC_ADDR, PUNT_VLAN)

        host_mac_addr = T.mac_addr(HOST_MAC_ADDR)

        priority = 0

        (out_priority, out_counter, out_punt_dest, out_skip_inject_up_packets, out_skip_p2p_packets,
         out_overwrite_phb, out_tc) = self.device.get_trap_configuration(sdk.LA_EVENT_L3_IP_UNICAST_RPF)
        self.assertEqual(out_priority, sdk.LA_EVENT_L3_IP_UNICAST_RPF)
        self.assertEqual(out_punt_dest, None)
        self.assertEqual(out_overwrite_phb, True)
        self.assertEqual(out_tc, 0)

        self.device.set_trap_configuration(sdk.LA_EVENT_L3_IP_UNICAST_RPF, priority, None, punt_dest, False, False, True, 0)

        (out_priority, out_counter, out_punt_dest, out_skip_inject_up_packets, out_skip_p2p_packets,
         out_overwrite_phb, out_tc) = self.device.get_trap_configuration(sdk.LA_EVENT_L3_IP_UNICAST_RPF)
        self.assertEqual(out_priority, priority)
        self.assertNotEqual(out_punt_dest, None)
        self.assertEqual(out_overwrite_phb, True)
        self.assertEqual(out_tc, 0)

    def _test_snoop_ethernet(self):

        input_packet = \
            Ether(dst=self.dest_mac.addr_str, src=self.dest_mac.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=VLAN) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.TTL) / TCP()

        punt_packet = Ether(dst=HOST_MAC_ADDR,
                            src=PUNT_INJECT_PORT_MAC_ADDR,
                            type=Ethertype.Dot1Q.value) / Dot1Q(prio=0,
                                                                id=0,
                                                                vlan=PUNT_VLAN,
                                                                type=Ethertype.Punt.value) / Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                  fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                  next_header_offset=0,
                                                                                                  source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                                                                                                  code=sdk.LA_EVENT_ETHERNET_SA_DA_ERROR,
                                                                                                  source_sp=IN_SP_GID,
                                                                                                  destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                  source_lp=AC_PORT_GID_BASE | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                                                                                                  # destination_lp=sdk.la_packet_types.LA_L2_LOGICAL_PORT_GID_INVALID,
                                                                                                  destination_lp=sdk.LA_EVENT_ETHERNET_SA_DA_ERROR,
                                                                                                  relay_id=0,
                                                                                                  lpts_flow_type=0) / Ether(dst=self.dest_mac.addr_str,
                                                                                                                            src=self.dest_mac.addr_str,
                                                                                                                            type=Ethertype.Dot1Q.value) / Dot1Q(vlan=VLAN) / IP(src=self.SIP.addr_str,
                                                                                                                                                                                dst=self.DIP.addr_str,
                                                                                                                                                                                ttl=self.TTL) / TCP()

        snoop_packet = Ether(dst=HOST_MAC_ADDR,
                             src=PUNT_INJECT_PORT_MAC_ADDR,
                             type=Ethertype.Dot1Q.value) / Dot1Q(prio=0,
                                                                 id=0,
                                                                 vlan=MIRROR_VLAN,
                                                                 type=Ethertype.Punt.value) / Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                   next_header_offset=0,
                                                                                                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                   code=MIRROR_CMD_INGRESS_GID,
                                                                                                   source_sp=IN_SP_GID,
                                                                                                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                   source_lp=AC_PORT_GID_BASE | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                                                                                                   destination_lp=AC_PORT_GID_BASE + 1,
                                                                                                   relay_id=SWITCH_GID,
                                                                                                   lpts_flow_type=0) / Ether(dst=self.dest_mac.addr_str,
                                                                                                                             src=self.dest_mac.addr_str,
                                                                                                                             type=Ethertype.Dot1Q.value) / Dot1Q(vlan=VLAN) / IP(src=self.SIP.addr_str,
                                                                                                                                                                                 dst=self.DIP.addr_str,
                                                                                                                                                                                 ttl=self.TTL) / TCP()

        # Setup punt and trap
        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        punt_dest = T.create_l2_punt_destination(self, self.device, T.L2_PUNT_DESTINATION2_GID, pi_port, HOST_MAC_ADDR, PUNT_VLAN)
        mirror_cmd = T.create_l2_mirror_command(self.device, MIRROR_CMD_INGRESS_GID, pi_port, HOST_MAC_ADDR, MIRROR_VLAN)

        priority = 0

        # 1: The default trap setting will drop the packet
        run_and_drop(self, self.device, input_packet, IN_SLICE, IN_IFG, IN_PIF_FIRST)

        # 2: Clear the trap -> the packet will go out
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)
        run_and_compare(self, self.device,
                        input_packet, IN_SLICE, IN_IFG, IN_PIF_FIRST,
                        input_packet, OUT_SLICE, OUT_IFG, OUT_PIF_FIRST)

        # 3: Set the trap to punt
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR, priority, None, punt_dest, False, False, True, 0)
        run_and_compare(self, self.device,
                        input_packet, IN_SLICE, IN_IFG, IN_PIF_FIRST,
                        punt_packet, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)

        # 4: Clear trap and set snoop -> packet will go out and another packet with punt header will be generated.
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)
        self.device.set_snoop_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR, priority, False, False, mirror_cmd)

        ingress_packet = {'data': input_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_PIF_FIRST}
        expected_packets = []
        expected_packets.append({'data': input_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_PIF_FIRST})
        expected_packets.append({'data': snoop_packet, 'slice': self.INJECT_SLICE,
                                 'ifg': self.INJECT_IFG, 'pif': self.INJECT_PIF_FIRST})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # Teardown
        self.device.clear_snoop_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)

    def _test_snoop_ethernet_short(self):

        input_packet = \
            Ether(dst=self.dest_mac.addr_str, src=self.dest_mac.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=VLAN) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.TTL) / TCP()

        snoop_packet = Ether(dst=HOST_MAC_ADDR,
                             src=PUNT_INJECT_PORT_MAC_ADDR,
                             type=Ethertype.Dot1Q.value) / Dot1Q(prio=0,
                                                                 id=0,
                                                                 vlan=MIRROR_VLAN,
                                                                 type=Ethertype.Punt.value) / Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                   next_header_offset=0,
                                                                                                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                   code=MIRROR_CMD_INGRESS_GID,
                                                                                                   source_sp=IN_SP_GID,
                                                                                                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                   source_lp=AC_PORT_GID_BASE | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                                                                                                   destination_lp=AC_PORT_GID_BASE + 1,
                                                                                                   relay_id=SWITCH_GID,
                                                                                                   lpts_flow_type=0) / Ether(dst=self.dest_mac.addr_str,
                                                                                                                             src=self.dest_mac.addr_str,
                                                                                                                             type=Ethertype.Dot1Q.value) / Dot1Q(vlan=VLAN) / IP(src=self.SIP.addr_str,
                                                                                                                                                                                 dst=self.DIP.addr_str,
                                                                                                                                                                                 ttl=self.TTL) / TCP()

        # Setup punt and trap
        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        mirror_cmd = T.create_l2_mirror_command(self.device, MIRROR_CMD_INGRESS_GID, pi_port, HOST_MAC_ADDR, MIRROR_VLAN)

        priority = 0

        # Clear trap and set snoop -> packet will go out and another packet with punt header will be generated.
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)
        self.device.set_snoop_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR, priority, False, False, mirror_cmd)

        ingress_packet = {'data': input_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_PIF_FIRST}
        expected_packets = []
        expected_packets.append({'data': input_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_PIF_FIRST})
        expected_packets.append({'data': snoop_packet, 'slice': self.INJECT_SLICE,
                                 'ifg': self.INJECT_IFG, 'pif': self.INJECT_PIF_FIRST})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # Teardown
        self.device.clear_snoop_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)

    def _test_snoop_ethernet_short_pci(self):

        input_packet = \
            Ether(dst=self.dest_mac.addr_str, src=self.dest_mac.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=VLAN) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.TTL) / TCP()

        snoop_packet = Ether(dst=HOST_MAC_ADDR,
                             src=PUNT_INJECT_PORT_MAC_ADDR,
                             type=Ethertype.Dot1Q.value) / Dot1Q(prio=0,
                                                                 id=0,
                                                                 vlan=MIRROR_VLAN,
                                                                 type=Ethertype.Punt.value) / Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                   next_header_offset=0,
                                                                                                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                   code=MIRROR_CMD_INGRESS_GID,
                                                                                                   source_sp=IN_SP_GID,
                                                                                                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                   source_lp=AC_PORT_GID_BASE | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                                                                                                   destination_lp=AC_PORT_GID_BASE + 1,
                                                                                                   relay_id=SWITCH_GID,
                                                                                                   lpts_flow_type=0) / Ether(dst=self.dest_mac.addr_str,
                                                                                                                             src=self.dest_mac.addr_str,
                                                                                                                             type=Ethertype.Dot1Q.value) / Dot1Q(vlan=VLAN) / IP(src=self.SIP.addr_str,
                                                                                                                                                                                 dst=self.DIP.addr_str,
                                                                                                                                                                                 ttl=self.TTL) / TCP()

        # Setup punt and trap
        pi_port = self.topology.inject_ports[self.INJECT_SLICE]
        pci_serdes = self.device.get_pci_serdes()
        mirror_cmd = T.create_l2_mirror_command(self.device, MIRROR_CMD_INGRESS_GID, pi_port, HOST_MAC_ADDR, MIRROR_VLAN)

        priority = 0

        # Clear trap and set snoop -> packet will go out and another packet with punt header will be generated.
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)
        self.device.set_snoop_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR, priority, False, False, mirror_cmd)

        ingress_packet = {'data': input_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_PIF_FIRST}
        expected_packets = []
        expected_packets.append({'data': input_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_PIF_FIRST})
        expected_packets.append({'data': snoop_packet, 'slice': self.INJECT_SLICE, 'ifg': self.INJECT_IFG, 'pif': pci_serdes})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # Teardown
        self.device.clear_snoop_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)

    def _test_traps_egress(self):

        input_packet = \
            Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.TTL)

        self.topology.rx_switch.hld_obj.set_mac_entry(
            DST_MAC.hld_obj,
            self.topology.tx_l2_ac_port_reg.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        self.topology.tx_l2_ac_port_reg.hld_obj.set_stp_state(sdk.la_port_stp_state_e_BLOCKING)

        punt_packet = Ether(dst=HOST_MAC_ADDR,
                            src=PUNT_INJECT_PORT_MAC_ADDR,
                            type=Ethertype.Dot1Q.value) / Dot1Q(prio=0,
                                                                id=0,
                                                                vlan=PUNT_VLAN,
                                                                type=Ethertype.Punt.value) / Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                  fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                  next_header_offset=0,
                                                                                                  source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_EGRESS_TRAP,
                                                                                                  code=sdk.LA_EVENT_ETHERNET_EGRESS_STP_BLOCK,
                                                                                                  source_sp=0xFFFF,
                                                                                                  destination_sp=T.TX_SVI_SYS_PORT_REG_GID,
                                                                                                  source_lp=T.RX_L2_AC_PORT_GID | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                                                                                                  destination_lp=T.TX_L2_AC_PORT_REG_GID,
                                                                                                  relay_id=T.RX_SWITCH_GID,
                                                                                                  lpts_flow_type=0) / Ether(dst=DST_MAC.addr_str,
                                                                                                                            src=SRC_MAC.addr_str,
                                                                                                                            type=Ethertype.Dot1Q.value) / Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / IP(src=self.SIP.addr_str,
                                                                                                                                                                                                dst=self.DIP.addr_str,
                                                                                                                                                                                                ttl=self.TTL)

        # Setup punt and trap
        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        punt_dest = T.create_l2_punt_destination(self, self.device, T.L2_PUNT_DESTINATION2_GID, pi_port, HOST_MAC_ADDR, PUNT_VLAN)

        # test
        priority = 0
        run_and_drop(self, self.device, input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        self.device.set_trap_configuration(
            sdk.LA_EVENT_ETHERNET_EGRESS_STP_BLOCK, priority, None, punt_dest, False, False, True, 0)

        run_and_compare(self, self.device,
                        input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        punt_packet, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)

    def _test_traps_ethernet(self):

        in_packet_sa_da = Ether(dst=DST_MAC.addr_str, src=DST_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.TTL) / \
            TCP()

        punt_packet = Ether(dst=HOST_MAC_ADDR,
                            src=PUNT_INJECT_PORT_MAC_ADDR,
                            type=Ethertype.Dot1Q.value) / Dot1Q(prio=0,
                                                                id=0,
                                                                vlan=PUNT_VLAN,
                                                                type=Ethertype.Punt.value) / Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                  fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                  next_header_offset=0,
                                                                                                  source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                                                                                                  code=sdk.LA_EVENT_ETHERNET_SA_DA_ERROR,
                                                                                                  source_sp=IN_SP_GID,
                                                                                                  destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                  source_lp=AC_PORT_GID_BASE | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                                                                                                  # destination_lp=sdk.la_packet_types.LA_L2_LOGICAL_PORT_GID_INVALID,
                                                                                                  destination_lp=sdk.LA_EVENT_ETHERNET_SA_DA_ERROR,
                                                                                                  relay_id=0,
                                                                                                  lpts_flow_type=0) / Ether(dst=DST_MAC.addr_str,
                                                                                                                            src=DST_MAC.addr_str,
                                                                                                                            type=Ethertype.Dot1Q.value) / Dot1Q(prio=2,
                                                                                                                                                                id=1,
                                                                                                                                                                vlan=VLAN) / IP(src=self.SIP.addr_str,
                                                                                                                                                                                dst=self.DIP.addr_str,
                                                                                                                                                                                ttl=self.TTL) / TCP()

        # Setup punt and trap
        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        punt_dest = T.create_l2_punt_destination(self, self.device, T.L2_PUNT_DESTINATION2_GID, pi_port, HOST_MAC_ADDR, PUNT_VLAN)

        priority = 0
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR, priority, None, punt_dest, False, False, True, 0)

        # test
        run_and_compare(self, self.device,
                        in_packet_sa_da, IN_SLICE, IN_IFG, IN_PIF_FIRST,
                        punt_packet, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)

    def _test_traps_ethernet_pci(self):

        in_packet_sa_da = Ether(dst=DST_MAC.addr_str, src=DST_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.TTL) / \
            TCP()

        punt_packet = Ether(dst=HOST_MAC_ADDR,
                            src=PUNT_INJECT_PORT_MAC_ADDR,
                            type=Ethertype.Dot1Q.value) / Dot1Q(prio=0,
                                                                id=0,
                                                                vlan=PUNT_VLAN,
                                                                type=Ethertype.Punt.value) / Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                  fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                  next_header_offset=0,
                                                                                                  source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                                                                                                  code=sdk.LA_EVENT_ETHERNET_SA_DA_ERROR,
                                                                                                  source_sp=IN_SP_GID,
                                                                                                  destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                  source_lp=AC_PORT_GID_BASE | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                                                                                                  # destination_lp=sdk.la_packet_types.LA_L2_LOGICAL_PORT_GID_INVALID,
                                                                                                  destination_lp=sdk.LA_EVENT_ETHERNET_SA_DA_ERROR,
                                                                                                  relay_id=0,
                                                                                                  lpts_flow_type=0) / Ether(dst=DST_MAC.addr_str,
                                                                                                                            src=DST_MAC.addr_str,
                                                                                                                            type=Ethertype.Dot1Q.value) / Dot1Q(prio=2,
                                                                                                                                                                id=1,
                                                                                                                                                                vlan=VLAN) / IP(src=self.SIP.addr_str,
                                                                                                                                                                                dst=self.DIP.addr_str,
                                                                                                                                                                                ttl=self.TTL) / TCP()

        pi_port = self.topology.inject_ports[self.INJECT_SLICE]
        punt_dest = T.create_l2_punt_destination(self, self.device, T.L2_PUNT_DESTINATION2_GID, pi_port, HOST_MAC_ADDR, PUNT_VLAN)

        priority = 0
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR, priority, None, punt_dest, False, False, True, 0)

        # test
        run_and_compare(self, self.device,
                        in_packet_sa_da, IN_SLICE, IN_IFG, IN_PIF_FIRST,
                        punt_packet, self.INJECT_SLICE, T.PI_IFG, T.PI_PIF)

    def _test_traps_non_inject_up(self):
        pi_port = T.punt_inject_port(
            self,
            self.device,
            IN_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        # Regular packet flow
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

        base_packet_without_padding = Ether(dst=DST_MAC.addr_str, src=DST_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        base_packet, __ = enlarge_packet_to_min_length(base_packet_without_padding)

        # Create inject packet with SA == DA
        self.inject_up_packet_sa_da = \
            Ether(dst=PUNT_INJECT_PORT_MAC_ADDR, src=HOST_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=Ethertype.Inject.value) / \
            InjectUp(ssp_gid=IN_SP_GID) / \
            base_packet

        # Configure trap to be invoked in case of inject up packets (last parameter == False)
        trap_cnt = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR, 0, trap_cnt, None, False, False, True, 0)

        run_and_drop(
            self,
            self.device,
            self.inject_up_packet_sa_da,
            IN_SLICE,
            self.INJECT_IFG,
            self.INJECT_PIF_FIRST)

        packets, bytes = trap_cnt.read(0, True, True)
        self.assertEqual(packets, 1)

        self.out_packet_sa_da = base_packet

        # Configure trap NOT to be invoked in case of inject up packets (last parameter == True)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR, 0, trap_cnt, None, True, False, True, 0)

        run_and_compare(
            self,
            self.device,
            self.inject_up_packet_sa_da,
            IN_SLICE,
            self.INJECT_IFG,
            self.INJECT_PIF_FIRST,
            self.out_packet_sa_da,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

        packets, bytes = trap_cnt.read(0, True, True)
        self.assertEqual(packets, 0)

    def _test_no_route_to_sender_rpf_loose_nh(self):

        self.l3_port_impl_class = T.ip_svi_base
        self.ip_impl_class = ip_test_base.ipv4_test_base
        self.ip_impl = self.ip_impl_class()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)

        input_packet = \
            Ether(dst=T.RX_SVI_MAC.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.TTL)

        punt_packet = \
            Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
                 next_header_offset=18,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP, code=sdk.LA_EVENT_L3_IP_UNICAST_RPF,
                 source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 #source_lp=T.RX_SVI_GID, destination_lp=sdk.la_packet_types.LA_L3_LOGICAL_PORT_GID_INVALID,
                 source_lp=T.RX_SVI_GID, destination_lp=sdk.LA_EVENT_L3_IP_UNICAST_RPF,
                 relay_id=T.VRF_GID, lpts_flow_type=0
                 ) / \
            Ether(dst=T.RX_SVI_MAC.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.TTL)

        # Setup punt and trap
        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        punt_dest = T.create_l2_punt_destination(self, self.device, T.L2_PUNT_DESTINATION2_GID, pi_port, HOST_MAC_ADDR, PUNT_VLAN)

        priority = 0
        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_IP_UNICAST_RPF)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_IP_UNICAST_RPF, priority, None, punt_dest, False, False, True, 0)

        # test
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_nh, self.PRIVATE_DATA)

        # set loose rpf mode
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_LOOSE)

        run_and_compare(self, self.device,
                        input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        punt_packet, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)

    def _test_punt_inject_counter(self):
        pci_ports = self.device.get_objects(sdk.la_object.object_type_e_PCI_PORT)

        inject_count = pci_ports[0].get_inject_count(True)
        punt_count = pci_ports[0].get_punt_count(True)

        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        dest_id = sdk.la_get_destination_id_from_gid(
            sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP,
            T.RCY_SYS_PORT_GID_BASE - IN_SLICE)

        self.inject_down_up_packet = \
            Ether(dst=PUNT_INJECT_PORT_MAC_ADDR, src=HOST_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=Ethertype.Inject.value) / \
            InjectDown(dest=dest_id, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            Ether(dst=PUNT_INJECT_PORT_MAC_ADDR, src=HOST_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN, type=Ethertype.Inject.value) / \
            InjectUp(ssp_gid=IN_SP_GID) / \
            self.in_packet

        run_and_compare(
            self,
            self.device,
            self.inject_down_up_packet,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_PIF_FIRST,
            self.out_packet,
            OUT_SLICE, OUT_IFG, OUT_PIF_FIRST)

        inject_count = pci_ports[0].get_inject_count(False)
        self.assertIsNotNone(inject_count)

        punt_count = pci_ports[0].get_punt_count(False)
        self.assertIsNotNone(punt_count)
