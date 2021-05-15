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
from leaba import sdk
import unittest
import sim_utils
import topology as T
from sdk_test_case_base import *

SPA_SLICE = T.get_device_slice(4)
SPA_IFG = 0
SPA_SLICE_2 = T.get_device_slice(SPA_SLICE + 1)
SPA_IFG_2 = T.get_device_ifg(SPA_IFG + 1)
SPA_FIRST_SERDES1 = T.get_device_first_serdes(2)
SPA_LAST_SERDES1 = SPA_FIRST_SERDES1 + 1
SPA_FIRST_SERDES2 = T.get_device_next_first_serdes(4)
SPA_LAST_SERDES2 = SPA_FIRST_SERDES2 + 1

IN_SLICE = T.get_device_slice(2)
IN_IFG = 0
IN_SERDES_FIRST = T.get_device_out_first_serdes(4)
IN_SERDES_LAST = IN_SERDES_FIRST + 1
OUT_SLICE = T.get_device_slice(4)
OUT_IFG = T.get_device_ifg(1)
OUT_SERDES_FIRST = T.get_device_out_next_first_serdes(8)
OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

SYS_PORT_GID_BASE = 23
AC_PORT_GID_BASE = 10

DST_MAC = "16:6b:f1:f2:25:16"
SRC_MAC = "e6:b2:3f:fc:6a:c9"
SRC_IP = "152.38.55.47"
DST_IP = "28.152.169.29"

VLAN = 0x3EF
DEFAULT_VLAN = 0x999
DEFAULT_SWITCH_GID = 0x999
SWITCH_GID = 0x3EF


class l2_vlan_editing_base(sdk_test_case_base):

    def setUp(self):
        super().setUp()
        # MATILDA_SAVE -- need review
        global OUT_SLICE, IN_SLICE, SPA_SLICE, SPA_SLICE_2, SPA_IFG_2
        IN_SLICE = T.choose_active_slices(self.device, IN_SLICE, [2, 3])
        OUT_SLICE = T.choose_active_slices(self.device, OUT_SLICE, [4, 1])
        active_slices = self.device.get_used_slices()
        SPA_SLICE = T.choose_active_slices(self.device, SPA_SLICE, [4, 0])
        SPA_SLICE_2 = T.get_device_slice(SPA_SLICE + 1)
        SPA_SLICE_2 = T.choose_active_slices(self.device, SPA_SLICE_2, [5, 1])
        SPA_IFG_2 = T.get_device_ifg(SPA_IFG + 1)
        self.ac_profile = T.ac_profile(self, self.device)

        self.mac_port_member_1 = T.mac_port(
            self,
            self.device,
            SPA_SLICE,
            SPA_IFG,
            SPA_FIRST_SERDES1,
            SPA_LAST_SERDES1)
        self.sys_port_member_1 = T.system_port(self, self.device, 100, self.mac_port_member_1)

        self.mac_port_member_2 = T.mac_port(
            self,
            self.device,
            SPA_SLICE_2,
            SPA_IFG_2,
            SPA_FIRST_SERDES2,
            SPA_LAST_SERDES2)
        self.sys_port_member_2 = T.system_port(self, self.device, 101, self.mac_port_member_2)

        self.eth_port1 = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, SYS_PORT_GID_BASE, IN_SERDES_FIRST, IN_SERDES_LAST)
        self.eth_port1.set_ac_profile(self.ac_profile)
        self.ac_port1 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            None,
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
        self.ac_port2 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE +
                                     1, self.topology.filter_group_def, None, self.eth_port2, None, VLAN, 0x0)

        self.ac_port1.hld_obj.set_destination(self.ac_port2.hld_obj)
        self.ac_port2.hld_obj.set_destination(self.ac_port1.hld_obj)

    def init_spa_port(self):
        self.spa_port = T.spa_port(self, self.device, 123)
        self.eth_port_spa = T.sa_ethernet_port(self, self.device, self.spa_port)

    def _test_nop(self, disable_rx=False, disable_tx=False):
        # Inject packet for simulation

        # nop - no vlan insertion, same packet in and out
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 0
        eve.num_tags_to_pop = 0

        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        if(disable_rx):
            self.ac_port1.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        if(disable_tx):
            self.ac_port2.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

    def _test_pop1(self, disable_rx=False, disable_tx=False):
        # Inject packet for simulation

        # pop1 - one vlan header removal, out packet without first vlan header
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 0
        eve.num_tags_to_pop = 1

        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        if(disable_rx):
            self.ac_port1.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        if(disable_tx):
            self.ac_port2.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

    def _test_pop2(self, disable_rx=False, disable_tx=False):
        # Inject packet for simulation

        # pop2 - two vlan header removals, out packet without first two vlan headers
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 0
        eve.num_tags_to_pop = 2

        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        if(disable_rx):
            self.ac_port1.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        if(disable_tx):
            self.ac_port2.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

    def _test_push1(self, disable_rx=False, disable_tx=False):
        # Inject packet for simulation

        # push1 - one vlan header insertion, out packet with extra vlan header
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0xace, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = 0xace

        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        if(disable_rx):
            self.ac_port1.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        if(disable_tx):
            self.ac_port2.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

    def _test_push2(self, disable_rx=False, disable_tx=False):
        # Inject packet for simulation

        # push2 - two vlan header insertions, out packet with extra two vlan headers
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0xace, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=0xdad, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 2
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = 0xace
        eve.tag1.tpid = Ethertype.QinQ.value
        eve.tag1.tci.fields.vid = 0xdad

        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)
        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        if(disable_rx):
            self.ac_port1.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        if(disable_tx):
            self.ac_port2.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

    def _test_push2_mtu(self):
        # Inject packet for simulation

        # push2 - two vlan header insertions, out packet with extra two vlan headers
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0xace, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=0xdad, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 2
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = 0xace
        eve.tag1.tpid = Ethertype.QinQ.value
        eve.tag1.tci.fields.vid = 0xdad

        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)
        o_mtu = self.eth_port2.hld_obj.get_mtu()
        self.eth_port2.hld_obj.set_mtu(1100)
        out_packet, pad_len = U.enlarge_packet_to_min_length(out_packet, 1100 + 1)
        in_packet, __ = U.enlarge_packet_to_min_length(in_packet, pad_len + len(in_packet))
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)
        self.eth_port2.hld_obj.set_mtu(o_mtu)

    def _test_tag1_pop2(self):
        # Inject packet for simulation

        # pop2 - two vlan header removals, packet should be dropped - only one vlan tag
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, __ = enlarge_packet_to_min_length(in_packet_base)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 0
        eve.num_tags_to_pop = 2

        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

    def _test_translate_any_1(self):
        # translate_any_1:
            # Ingress with one or no vlan tag ( which is customer vlan )
            # Egress with  two vlan tags ( inner vlan is customer vlan and outer vlan is service vlan)
        selector = sdk.la_ac_profile.key_selector_e_PORT
        self.ac_profile_with_port_only = T.ac_profile(self, self.device, single_vlan_selector=selector, dual_vlan_selector=selector)

        # Delete ac_port1
        self.ac_port1.hld_obj.set_destination(None)
        self.ac_port2.hld_obj.set_destination(None)
        self.ac_port1.destroy()

        self.eth_port1.set_ac_profile(self.ac_profile_with_port_only)

        self.switch = T.switch(self, self.device, SWITCH_GID)

        # Create ac_port1 without vid1 and vid2
        self.ac_port1 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE,
                                     self.topology.filter_group_def, None, self.eth_port1, None, 0x0, 0x0)

        self.ac_port1.hld_obj.attach_to_switch(self.switch.hld_obj)
        self.ac_port2.hld_obj.attach_to_switch(self.switch.hld_obj)

        self.dest_mac = T.mac_addr(DST_MAC)
        self.switch.hld_obj.set_mac_entry(self.dest_mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = VLAN

        # Set eve to ac_port2 with vid tag as VLAN.
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x679) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=VLAN, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x679) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        # Packet without tag
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.IPv4.value) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=VLAN, type=Ethertype.IPv4.value) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

    def _test_translate_many_1(self):
        # translate_many_1:
            # Ingress with one vlan tag ( which is customer vlan )
            # Egress with  two vlan tags ( inner vlan is customer vlan and outer vlan is service vlan)

        # Delete ac_port1
        self.ac_port1.hld_obj.set_destination(None)
        self.ac_port2.hld_obj.set_destination(None)
        self.ac_port1.destroy()

        selector = sdk.la_ac_profile.key_selector_e_PORT_VLAN_VLAN_WITH_FALLBACK
        # Attach an ac profile with fallback to eth_port1
        self.ac_profile_with_fallback = T.ac_profile(
            self,
            self.device,
            with_fallback=True,
            single_vlan_selector=selector)
        self.ac_profile_with_fallback.hld_obj.set_default_vid_per_format_enabled(sdk.LA_PACKET_VLAN_FORMAT_802Q, True)

        pvf = sdk.la_packet_vlan_format_t()
        pvf.outer_vlan_is_priority = False
        pvf.tpid1 = 0x9100
        pvf.tpid2 = 0x8100
        self.ac_profile_with_fallback.hld_obj.set_default_vid_per_format_enabled(pvf, True)

        self.eth_port1.set_ac_profile(self.ac_profile_with_fallback)

        # Create ac_port1
        self.ac_port1 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE,
                                     self.topology.filter_group_def, None, self.eth_port1, None, VLAN, 0x0)

        self.ac_port1.hld_obj.set_destination(self.ac_port2.hld_obj)
        self.ac_port2.hld_obj.set_destination(self.ac_port1.hld_obj)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = 0xace

        # Set eve to ac_port2 with vid tag as 0xace.
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        # TestCase1: Adding different service mapping entries
        self.ac_port1.hld_obj.add_service_mapping_vid(0xabc)
        self.ac_port1.hld_obj.add_service_mapping_vid(0x111)
        self.ac_port1.hld_obj.add_service_mapping_vid(0x123)

        # destroy the ac port to make sure that the service mapping entries are also deleted.
        self.ac_port1.hld_obj.set_destination(None)
        self.ac_port2.hld_obj.set_destination(None)
        self.ac_port1.destroy()

        # Create ac_port1
        self.ac_port1 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE,
                                     self.topology.filter_group_def, None, self.eth_port1, None, VLAN, 0x0)
        self.ac_port1.hld_obj.set_destination(self.ac_port2.hld_obj)
        self.ac_port2.hld_obj.set_destination(self.ac_port1.hld_obj)

        # Adding different service mapping entries
        self.ac_port1.hld_obj.add_service_mapping_vid(0xabc)
        self.ac_port1.hld_obj.add_service_mapping_vid(0x111)
        self.ac_port1.hld_obj.add_service_mapping_vid(0x123)

        vid_list = []
        (vid_list) = self.ac_port1.hld_obj.get_service_mapping_vid_list()
        self.assertEqual(vid_list[0], 0xabc)
        self.assertEqual(vid_list[1], 0x111)
        self.assertEqual(vid_list[2], 0x123)

        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x111, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x999) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0xace, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x111, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x999) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        # TestCase2: destroy the port to make sure that the service mapping entries are also deleted.
        self.ac_port1.hld_obj.set_destination(None)
        self.ac_port2.hld_obj.set_destination(None)
        self.ac_port1.destroy()

        # Create ac_port1
        self.ac_port1 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE,
                                     self.topology.filter_group_def, None, self.eth_port1, None, VLAN, 0x0)
        self.ac_port1.hld_obj.set_destination(self.ac_port2.hld_obj)
        self.ac_port2.hld_obj.set_destination(self.ac_port1.hld_obj)

        # Adding different service mapping entries
        self.ac_port1.hld_obj.add_service_mapping_vid(0xabc)
        self.ac_port1.hld_obj.add_service_mapping_vid(0x111)
        self.ac_port1.hld_obj.add_service_mapping_vid(0x123)

        vid_list = []
        (vid_list) = self.ac_port1.hld_obj.get_service_mapping_vid_list()
        self.assertEqual(vid_list[0], 0xabc)
        self.assertEqual(vid_list[1], 0x111)
        self.assertEqual(vid_list[2], 0x123)

        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        # TestCase3: Packet should be dropped if the mapping is removed
        self.ac_port1.hld_obj.remove_service_mapping_vid(0x111)

        (vid_list) = self.ac_port1.hld_obj.get_service_mapping_vid_list()
        self.assertEqual(vid_list[0], 0xabc)
        self.assertEqual(vid_list[1], 0x123)

        run_and_drop(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST)

        # TestCase4: Add back the deleted mapping
        self.ac_port1.hld_obj.add_service_mapping_vid(0x111)

        (vid_list) = self.ac_port1.hld_obj.get_service_mapping_vid_list()
        self.assertEqual(vid_list[0], 0xabc)
        self.assertEqual(vid_list[1], 0x123)
        self.assertEqual(vid_list[2], 0x111)

        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        # TestCase5: Add new mapping
        self.ac_port1.hld_obj.add_service_mapping_vid(0x679)

        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x679) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0xace, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x679) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        # TestCase6: Create a default service port, so that any unmapped entries will carry the default vlan.
        self.default_switch = T.switch(self, self.device, DEFAULT_SWITCH_GID)

        self.ac_portdummy = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 5,
            self.topology.filter_group_def,
            self.default_switch,
            self.eth_port1,
            None,
            0x0,
            0x0)

        self.ac_port3 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 2,
            self.topology.filter_group_def,
            self.default_switch,
            self.eth_port1,
            None,
            DEFAULT_SWITCH_GID,
            0x0)

        self.ac_port4 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 3,
            self.topology.filter_group_def,
            self.default_switch,
            self.eth_port2,
            None,
            DEFAULT_SWITCH_GID,
            0x0)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = DEFAULT_VLAN

        self.ac_port4.hld_obj.set_egress_vlan_edit_command(eve)

        self.dest_mac = T.mac_addr(DST_MAC)
        self.ac_port3.hld_obj.set_mac_learning_mode(sdk.la_lp_mac_learning_mode_e_STANDALONE)
        self.default_switch.hld_obj.set_mac_entry(self.dest_mac.hld_obj, self.ac_port4.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

        # add the default mapping entry
        self.ac_port3.hld_obj.add_service_mapping_vid(0x0)

        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x333) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=DEFAULT_VLAN, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x333) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        # TestCase7: Remove the default mapping entry
        self.ac_port3.hld_obj.remove_service_mapping_vid(0x0)

        run_and_drop(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST)

        self.ac_port3.destroy()
        self.ac_port4.destroy()
        self.ac_portdummy.destroy()
        self.default_switch.hld_obj.remove_mac_entry(self.dest_mac.hld_obj)
        self.default_switch.destroy()
        self.ac_port1.hld_obj.set_destination(None)
        self.ac_port2.hld_obj.set_destination(None)
        self.ac_port1.destroy()

    def _test_translate_many_1_with_spa(self):
        self.init_spa_port()

        # translate_many_1:
        # Ingress with one vlan tag ( which is customer vlan )
        # Egress with  two vlan tags ( inner vlan is customer vlan and outer vlan is service vlan)

        # Delete ac_port1
        self.ac_port1.hld_obj.set_destination(None)
        self.ac_port2.hld_obj.set_destination(None)
        self.ac_port1.destroy()

        selector = sdk.la_ac_profile.key_selector_e_PORT_VLAN_VLAN_WITH_FALLBACK
        # Attach an ac profile with fallback to eth_port1
        self.ac_profile_with_fallback = T.ac_profile(
            self,
            self.device,
            with_fallback=True,
            single_vlan_selector=selector)
        self.ac_profile_with_fallback.hld_obj.set_default_vid_per_format_enabled(sdk.LA_PACKET_VLAN_FORMAT_802Q, True)

        pvf = sdk.la_packet_vlan_format_t()
        pvf.outer_vlan_is_priority = False
        pvf.tpid1 = 0x9100
        pvf.tpid2 = 0x8100
        self.ac_profile_with_fallback.hld_obj.set_default_vid_per_format_enabled(pvf, True)

        self.eth_port_spa.set_ac_profile(self.ac_profile_with_fallback)

        # Create ac_port1
        self.ac_port1 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE,
                                     self.topology.filter_group_def, None, self.eth_port_spa, None, VLAN, 0x0)

        self.ac_port1.hld_obj.set_destination(self.ac_port2.hld_obj)
        self.ac_port2.hld_obj.set_destination(self.ac_port1.hld_obj)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = 0xace

        # Set eve to ac_port2 with vid tag as 0xace.
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        # TestCase1: Adding different service mapping entries before adding member ports.
        self.ac_port1.hld_obj.add_service_mapping_vid(0xabc)
        self.ac_port1.hld_obj.add_service_mapping_vid(0x111)
        self.ac_port1.hld_obj.add_service_mapping_vid(0x123)

        vid_list = []
        (vid_list) = self.ac_port1.hld_obj.get_service_mapping_vid_list()
        self.assertEqual(vid_list[0], 0xabc)
        self.assertEqual(vid_list[1], 0x111)
        self.assertEqual(vid_list[2], 0x123)

        # TestCase2: Adding first member port
        self.spa_port.add(self.sys_port_member_1)

        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x111, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x999) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0xace, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x111, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x999) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        run_and_compare(
            self,
            self.device,
            in_packet,
            SPA_SLICE,
            SPA_IFG,
            SPA_FIRST_SERDES1,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        # TestCase3: Adding second member port.
        self.spa_port.add(self.sys_port_member_2)

        run_and_compare(
            self,
            self.device,
            in_packet,
            SPA_SLICE_2,
            SPA_IFG_2,
            SPA_FIRST_SERDES2,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        # Removing first member port.
        self.spa_port.remove(self.sys_port_member_1)

        run_and_drop(
            self,
            self.device,
            in_packet,
            SPA_SLICE,
            SPA_IFG,
            SPA_FIRST_SERDES1)

        run_and_compare(
            self,
            self.device,
            in_packet,
            SPA_SLICE_2,
            SPA_IFG_2,
            SPA_FIRST_SERDES2,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        # TestCase4: Removing second member port, adding back first member port.
        self.spa_port.remove(self.sys_port_member_2)
        self.spa_port.add(self.sys_port_member_1)

        run_and_drop(
            self,
            self.device,
            in_packet,
            SPA_SLICE_2,
            SPA_IFG_2,
            SPA_FIRST_SERDES2)

        run_and_compare(
            self,
            self.device,
            in_packet,
            SPA_SLICE,
            SPA_IFG,
            SPA_FIRST_SERDES1,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        # TestCase5: destroy the SPA port to make sure that the service mapping entries are also deleted.
        self.ac_port1.hld_obj.set_destination(None)
        self.ac_port2.hld_obj.set_destination(None)
        self.spa_port.remove(self.sys_port_member_1)
        self.ac_port1.destroy()

        # Create ac_port1
        self.ac_port1 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE,
                                     self.topology.filter_group_def, None, self.eth_port_spa, None, VLAN, 0x0)
        self.ac_port1.hld_obj.set_destination(self.ac_port2.hld_obj)
        self.ac_port2.hld_obj.set_destination(self.ac_port1.hld_obj)
        self.spa_port.add(self.sys_port_member_1)
        self.spa_port.add(self.sys_port_member_2)

        # Adding different service mapping entries
        self.ac_port1.hld_obj.add_service_mapping_vid(0xabc)
        self.ac_port1.hld_obj.add_service_mapping_vid(0x111)
        self.ac_port1.hld_obj.add_service_mapping_vid(0x123)

        vid_list = []
        (vid_list) = self.ac_port1.hld_obj.get_service_mapping_vid_list()
        self.assertEqual(vid_list[0], 0xabc)
        self.assertEqual(vid_list[1], 0x111)
        self.assertEqual(vid_list[2], 0x123)

        run_and_compare(
            self,
            self.device,
            in_packet,
            SPA_SLICE,
            SPA_IFG,
            SPA_FIRST_SERDES1,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        run_and_compare(
            self,
            self.device,
            in_packet,
            SPA_SLICE_2,
            SPA_IFG_2,
            SPA_FIRST_SERDES2,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        # TestCase6: Packet should be dropped if the mapping is removed
        self.ac_port1.hld_obj.remove_service_mapping_vid(0x111)

        (vid_list) = self.ac_port1.hld_obj.get_service_mapping_vid_list()
        self.assertEqual(vid_list[0], 0xabc)
        self.assertEqual(vid_list[1], 0x123)

        run_and_drop(
            self,
            self.device,
            in_packet,
            SPA_SLICE,
            SPA_IFG,
            SPA_FIRST_SERDES1)

        run_and_drop(
            self,
            self.device,
            in_packet,
            SPA_SLICE_2,
            SPA_IFG_2,
            SPA_FIRST_SERDES2)

        # TestCase7: Add back the deleted mapping.
        self.ac_port1.hld_obj.add_service_mapping_vid(0x111)

        (vid_list) = self.ac_port1.hld_obj.get_service_mapping_vid_list()
        self.assertEqual(vid_list[0], 0xabc)
        self.assertEqual(vid_list[1], 0x123)
        self.assertEqual(vid_list[2], 0x111)

        run_and_compare(
            self,
            self.device,
            in_packet,
            SPA_SLICE,
            SPA_IFG,
            SPA_FIRST_SERDES1,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        run_and_compare(
            self,
            self.device,
            in_packet,
            SPA_SLICE_2,
            SPA_IFG_2,
            SPA_FIRST_SERDES2,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        # TestCase8: Add new mapping
        self.ac_port1.hld_obj.add_service_mapping_vid(0x679)

        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x679) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0xace, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x679) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        run_and_compare(
            self,
            self.device,
            in_packet,
            SPA_SLICE,
            SPA_IFG,
            SPA_FIRST_SERDES1,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        run_and_compare(
            self,
            self.device,
            in_packet,
            SPA_SLICE_2,
            SPA_IFG_2,
            SPA_FIRST_SERDES2,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        # TestCase9: Create a default service port, so that any unmapped entries will carry the default vlan.
        self.default_switch = T.switch(self, self.device, DEFAULT_SWITCH_GID)

        self.ac_portdummy = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 5,
            self.topology.filter_group_def,
            self.default_switch,
            self.eth_port_spa,
            None,
            0x0,
            0x0)

        self.ac_port3 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 2,
            self.topology.filter_group_def,
            self.default_switch,
            self.eth_port_spa,
            None,
            DEFAULT_SWITCH_GID,
            0x0)

        self.ac_port4 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 3,
            self.topology.filter_group_def,
            self.default_switch,
            self.eth_port2,
            None,
            DEFAULT_SWITCH_GID,
            0x0)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = DEFAULT_VLAN

        self.ac_port4.hld_obj.set_egress_vlan_edit_command(eve)

        self.dest_mac = T.mac_addr(DST_MAC)
        self.ac_port3.hld_obj.set_mac_learning_mode(sdk.la_lp_mac_learning_mode_e_STANDALONE)
        self.default_switch.hld_obj.set_mac_entry(self.dest_mac.hld_obj, self.ac_port4.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

        # add the default mapping entry
        self.ac_port3.hld_obj.add_service_mapping_vid(0x0)

        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x333) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=DEFAULT_VLAN, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x333) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        run_and_compare(
            self,
            self.device,
            in_packet,
            SPA_SLICE,
            SPA_IFG,
            SPA_FIRST_SERDES1,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        run_and_compare(
            self,
            self.device,
            in_packet,
            SPA_SLICE_2,
            SPA_IFG_2,
            SPA_FIRST_SERDES2,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        # TestCase10: Remove the default mapping entry
        self.ac_port3.hld_obj.remove_service_mapping_vid(0x0)

        run_and_drop(
            self,
            self.device,
            in_packet,
            SPA_SLICE,
            SPA_IFG,
            SPA_FIRST_SERDES1)

        run_and_drop(
            self,
            self.device,
            in_packet,
            SPA_SLICE_2,
            SPA_IFG_2,
            SPA_FIRST_SERDES2)

        self.ac_port3.destroy()
        self.ac_port4.destroy()
        self.ac_portdummy.destroy()
        self.default_switch.hld_obj.remove_mac_entry(self.dest_mac.hld_obj)
        self.ac_port1.hld_obj.set_destination(None)
        self.ac_port2.hld_obj.set_destination(None)
        self.ac_port1.destroy()

    def _test_translate_1_1(self, disable_rx=False, disable_tx=False):

        # in packet vlans
        IN_PACKET_OUTER_TAG_TPID = Ethertype.Dot1Q.value
        IN_PACKET_OUTER_TAG_VID = 0x3ef

        IN_PACKET_INNER_TAG_TPID = Ethertype.Dot1Q.value
        IN_PACKET_INNER_TAG_VID = 0x3eb

        # ive tags
        IVE_TAG_0_TPID = Ethertype.QinQ.value
        IVE_TAG_0_VID = 0xace

        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=IN_PACKET_OUTER_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_OUTER_TAG_VID, type=IN_PACKET_INNER_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_INNER_TAG_VID) / \
            IP(src=SRC_IP, dst=DST_IP)

        # checking that out packet tpid got overwrite
        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=IVE_TAG_0_TPID) / \
            Dot1Q(vlan=IVE_TAG_0_VID, type=IN_PACKET_INNER_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_INNER_TAG_VID) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 1
        eve.tag0.tpid = IVE_TAG_0_TPID
        eve.tag0.tci.fields.vid = IVE_TAG_0_VID

        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        if(disable_rx):
            self.ac_port1.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        if(disable_tx):
            self.ac_port2.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

    def _test_translate_1_2(self, disable_rx=False, disable_tx=False):
        # Inject packet for simulation

        # translate_1_2 - two vlan header insertions, one vlan header removal, out packet has extra vlan header
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=0xace, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0xdad, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 2
        eve.num_tags_to_pop = 1
        eve.tag0.tpid = Ethertype.QinQ.value
        eve.tag0.tci.fields.vid = 0xace
        eve.tag1.tpid = Ethertype.Dot1Q.value
        eve.tag1.tci.fields.vid = 0xdad

        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        if(disable_rx):
            self.ac_port1.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        if(disable_tx):
            self.ac_port2.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

    def _test_translate_2_1(self, disable_rx=False, disable_tx=False):
        # Inject packet for simulation

        # in packet vlans
        IN_PACKET_OUTER_TAG_TPID = Ethertype.Dot1Q.value
        IN_PACKET_OUTER_TAG_VID = 0x3ef

        IN_PACKET_MIDDLE_TAG_TPID = Ethertype.Dot1Q.value
        IN_PACKET_MIDDLE_TAG_VID = 0x3ea

        IN_PACKET_INNER_TAG_TPID = Ethertype.Dot1Q.value
        IN_PACKET_INNER_TAG_VID = 0x3eb

        # ive tags
        IVE_TAG_0_TPID = Ethertype.QinQ.value
        IVE_TAG_0_VID = 0xace

        # translate_2_1 - one vlan header insertion, two vlan header removals, out packet is one vlan header smaller
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=IN_PACKET_OUTER_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_OUTER_TAG_VID, type=IN_PACKET_MIDDLE_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_MIDDLE_TAG_VID, type=IN_PACKET_INNER_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_INNER_TAG_VID) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=IVE_TAG_0_TPID) / \
            Dot1Q(vlan=IVE_TAG_0_VID, type=IN_PACKET_INNER_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_INNER_TAG_VID) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 2
        eve.tag0.tpid = IVE_TAG_0_TPID
        eve.tag0.tci.fields.vid = IVE_TAG_0_VID

        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        if(disable_rx):
            self.ac_port1.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        if(disable_tx):
            self.ac_port2.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

    def _test_translate_2_2(self, disable_rx=False, disable_tx=False):
        # Inject packet for simulation

        # translate_2_2 - two vlan header insertions, two vlan header removals, out packet same size, different headers

        # in packet vlans
        IN_PACKET_OUTER_TAG_TPID = Ethertype.Dot1Q.value
        IN_PACKET_OUTER_TAG_VID = 0x3ef

        IN_PACKET_MIDDLE_TAG_TPID = Ethertype.QinQ.value
        IN_PACKET_MIDDLE_TAG_VID = 0x3ea

        IN_PACKET_INNER_TAG_TPID = Ethertype.Dot1Q.value
        IN_PACKET_INNER_TAG_VID = 0x3eb

        # ive tags
        IVE_TAG_0_TPID = Ethertype.QinQ.value
        IVE_TAG_0_VID = 0xace

        IVE_TAG_1_TPID = Ethertype.Dot1Q.value
        IVE_TAG_1_VID = 0xdad

        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=IN_PACKET_OUTER_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_OUTER_TAG_VID, type=IN_PACKET_MIDDLE_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_MIDDLE_TAG_VID, type=IN_PACKET_INNER_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_INNER_TAG_VID) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=IVE_TAG_0_TPID) / \
            Dot1Q(vlan=IVE_TAG_0_VID, type=IVE_TAG_1_TPID) / \
            Dot1Q(vlan=IVE_TAG_1_VID, type=IN_PACKET_INNER_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_INNER_TAG_VID) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 2
        eve.num_tags_to_pop = 2
        eve.tag0.tpid = IVE_TAG_0_TPID
        eve.tag0.tci.fields.vid = IVE_TAG_0_VID
        eve.tag1.tpid = IVE_TAG_1_TPID
        eve.tag1.tci.fields.vid = IVE_TAG_1_VID

        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        if(disable_rx):
            self.ac_port1.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        if(disable_tx):
            self.ac_port2.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

    def _test_nop_ive(self, disable_rx=False, disable_tx=False):
        # Inject packet for simulation

        # nop - no vlan insertion, same packet in and out
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 0
        ive.num_tags_to_pop = 0

        self.ac_port1.hld_obj.set_ingress_vlan_edit_command(ive)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        if(disable_rx):
            self.ac_port1.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        if(disable_tx):
            self.ac_port2.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

    def _test_pop1_ive(self, disable_rx=False, disable_tx=False):
        # Inject packet for simulation

        # pop1 - one vlan header removal, out packet without first vlan header
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)
        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 0
        ive.num_tags_to_pop = 1

        self.ac_port1.hld_obj.set_ingress_vlan_edit_command(ive)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        if(disable_rx):
            self.ac_port1.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        if(disable_tx):
            self.ac_port2.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

    def _test_pop2_ive(self, disable_rx=False, disable_tx=False):
        # Inject packet for simulation

        # pop2 - two vlan header removals, out packet without first two vlan headers
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 0
        ive.num_tags_to_pop = 2

        self.ac_port1.hld_obj.set_ingress_vlan_edit_command(ive)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        if(disable_rx):
            self.ac_port1.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        if(disable_tx):
            self.ac_port2.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

    def _test_push1_ive(self, disable_rx=False, disable_tx=False):
        # Inject packet for simulation

        # push1 - one vlan header insertion, out packet with extra vlan header
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0xace, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 1
        ive.num_tags_to_pop = 0
        ive.tag0.tpid = Ethertype.Dot1Q.value
        ive.tag0.tci.fields.vid = 0xace

        self.ac_port1.hld_obj.set_ingress_vlan_edit_command(ive)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        if(disable_rx):
            self.ac_port1.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        if(disable_tx):
            self.ac_port2.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

    def _test_push2_ive(self, disable_rx=False, disable_tx=False):
        # Inject packet for simulation

        # push2 - two vlan header insertions, out packet with extra two vlan headers
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0xace, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=0xdad, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 2
        ive.num_tags_to_pop = 0
        ive.tag0.tpid = Ethertype.Dot1Q.value
        ive.tag0.tci.fields.vid = 0xace
        ive.tag1.tpid = Ethertype.QinQ.value
        ive.tag1.tci.fields.vid = 0xdad

        self.ac_port1.hld_obj.set_ingress_vlan_edit_command(ive)
        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        if(disable_rx):
            self.ac_port1.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        if(disable_tx):
            self.ac_port2.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

    def _test_translate_1_1_ive(self, disable_rx=False, disable_tx=False):

        # translate_1_1 - one vlan header insertion, one vlan header removal, out packet same size, different headers

        # in packet vlans
        IN_PACKET_OUTER_TAG_TPID = Ethertype.Dot1Q.value
        IN_PACKET_OUTER_TAG_VID = 0x3ef

        IN_PACKET_INNER_TAG_TPID = Ethertype.Dot1Q.value
        IN_PACKET_INNER_TAG_VID = 0x3eb

        # ive tags
        IVE_TAG_0_TPID = Ethertype.QinQ.value
        IVE_TAG_0_VID = 0xace

        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=IN_PACKET_OUTER_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_OUTER_TAG_VID, type=IN_PACKET_INNER_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_INNER_TAG_VID) / \
            IP(src=SRC_IP, dst=DST_IP)

        # checking that out packet tpid got overwrite
        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=IVE_TAG_0_TPID) / \
            Dot1Q(vlan=IVE_TAG_0_VID, type=IN_PACKET_INNER_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_INNER_TAG_VID) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 1
        ive.num_tags_to_pop = 1
        ive.tag0.tpid = IVE_TAG_0_TPID
        ive.tag0.tci.fields.vid = IVE_TAG_0_VID

        self.ac_port1.hld_obj.set_ingress_vlan_edit_command(ive)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        if(disable_rx):
            self.ac_port1.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        if(disable_tx):
            self.ac_port2.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

    def _test_translate_1_2_ive(self, disable_rx=False, disable_tx=False):
        # Inject packet for simulation

        # translate_1_2 - two vlan header insertions, one vlan header removal, out packet has extra vlan header
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=0xace, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0xdad, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=0x3ef) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 2
        ive.num_tags_to_pop = 1
        ive.tag0.tpid = Ethertype.QinQ.value
        ive.tag0.tci.fields.vid = 0xace
        ive.tag1.tpid = Ethertype.Dot1Q.value
        ive.tag1.tci.fields.vid = 0xdad

        self.ac_port1.hld_obj.set_ingress_vlan_edit_command(ive)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        if(disable_rx):
            self.ac_port1.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        if(disable_tx):
            self.ac_port2.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

    def _test_translate_2_1_ive(self, disable_rx=False, disable_tx=False):
        # Inject packet for simulation

        # in packet vlans
        IN_PACKET_OUTER_TAG_TPID = Ethertype.Dot1Q.value
        IN_PACKET_OUTER_TAG_VID = 0x3ef

        IN_PACKET_MIDDLE_TAG_TPID = Ethertype.Dot1Q.value
        IN_PACKET_MIDDLE_TAG_VID = 0x3ea

        IN_PACKET_INNER_TAG_TPID = Ethertype.Dot1Q.value
        IN_PACKET_INNER_TAG_VID = 0x3eb

        # ive tags
        IVE_TAG_0_TPID = Ethertype.QinQ.value
        IVE_TAG_0_VID = 0xace

        # translate_2_1 - one vlan header insertion, two vlan header removals, out packet is one vlan header smaller
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=IN_PACKET_OUTER_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_OUTER_TAG_VID, type=IN_PACKET_MIDDLE_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_MIDDLE_TAG_VID, type=IN_PACKET_INNER_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_INNER_TAG_VID) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=IVE_TAG_0_TPID) / \
            Dot1Q(vlan=IVE_TAG_0_VID, type=IN_PACKET_INNER_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_INNER_TAG_VID) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 1
        ive.num_tags_to_pop = 2
        ive.tag0.tpid = IVE_TAG_0_TPID
        ive.tag0.tci.fields.vid = IVE_TAG_0_VID

        self.ac_port1.hld_obj.set_ingress_vlan_edit_command(ive)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        if(disable_rx):
            self.ac_port1.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        if(disable_tx):
            self.ac_port2.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

    def _test_translate_2_2_ive(self, disable_rx=False, disable_tx=False):
        # Inject packet for simulation

        # translate_2_2 - two vlan header insertions, two vlan header removals, out packet same size, different headers

        # in packet vlans
        IN_PACKET_OUTER_TAG_TPID = Ethertype.Dot1Q.value
        IN_PACKET_OUTER_TAG_VID = 0x3ef

        IN_PACKET_MIDDLE_TAG_TPID = Ethertype.QinQ.value
        IN_PACKET_MIDDLE_TAG_VID = 0x3ea

        IN_PACKET_INNER_TAG_TPID = Ethertype.Dot1Q.value
        IN_PACKET_INNER_TAG_VID = 0x3eb

        # ive tags
        IVE_TAG_0_TPID = Ethertype.QinQ.value
        IVE_TAG_0_VID = 0xace

        IVE_TAG_1_TPID = Ethertype.Dot1Q.value
        IVE_TAG_1_VID = 0xdad

        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=IN_PACKET_OUTER_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_OUTER_TAG_VID, type=IN_PACKET_MIDDLE_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_MIDDLE_TAG_VID, type=IN_PACKET_INNER_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_INNER_TAG_VID) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=IVE_TAG_0_TPID) / \
            Dot1Q(vlan=IVE_TAG_0_VID, type=IVE_TAG_1_TPID) / \
            Dot1Q(vlan=IVE_TAG_1_VID, type=IN_PACKET_INNER_TAG_TPID) / \
            Dot1Q(vlan=IN_PACKET_INNER_TAG_VID) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 2
        ive.num_tags_to_pop = 2
        ive.tag0.tpid = IVE_TAG_0_TPID
        ive.tag0.tci.fields.vid = IVE_TAG_0_VID
        ive.tag1.tpid = IVE_TAG_1_TPID
        ive.tag1.tci.fields.vid = IVE_TAG_1_VID

        self.ac_port1.hld_obj.set_ingress_vlan_edit_command(ive)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        if(disable_rx):
            self.ac_port1.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        if(disable_tx):
            self.ac_port2.hld_obj.disable()
            U.run_and_drop(self, self.device, in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

    def _test_vlan_table_overflow(self):
        # create 5 different tpid profiles and test table overflow
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 2
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = 0x9099
        eve.tag0.tci.fields.vid = 0xacb
        eve.tag1.tci.fields.vid = 0xdcd

        for tpid in range(0x9100, 0x9200):
            eve.tag1.tpid = tpid
            try:
                self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)
                self.assertFail()
            except BaseException:
                break

        # test - table is still accessible
        eve.tag1.tpid = Ethertype.QinQ.value
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        # test - check untagged tag1 recognition
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = 0x9099
        eve.tag0.tci.fields.vid = 0xacb
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

    def _test_access_to_trunk(self):
        VLAN1 = 0
        VLAN2 = 0

        self.ac_port1.hld_obj.set_destination(None)
        self.ac_port2.hld_obj.set_destination(None)
        self.ac_port1.destroy()
        self.ac_port2.destroy()

        self.ac_port3 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 2,
            self.topology.filter_group_def,
            None,
            self.eth_port1,
            None,
            VLAN1,
            VLAN2)

        self.ac_port4 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 3,
            self.topology.filter_group_def,
            None,
            self.eth_port2,
            None,
            VLAN,
            VLAN2)

        self.ac_port3.hld_obj.set_destination(self.ac_port4.hld_obj)
        self.ac_port4.hld_obj.set_destination(self.ac_port3.hld_obj)

        # Untagged packet
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=0x0800) / \
            IP(src=SRC_IP, dst=DST_IP)

        # Tagged packet with PCPDEI zero
        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, vlan=VLAN) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = VLAN
        eve.pcpdei_rewrite_only = False
        self.ac_port4.hld_obj.set_egress_vlan_edit_command(eve)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        self.ac_port3.hld_obj.set_destination(None)
        self.ac_port4.hld_obj.set_destination(None)
        self.ac_port3.destroy()
        self.ac_port4.destroy()

    def _test_port_default_pcpdei(self):
        # Tagged packet with PCPDEI (2, 0)
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, vlan=VLAN) / \
            IP(src=SRC_IP, dst=DST_IP)

        # Tagged packet with PCPDEI (2, 0)
        out_packet_base1 = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, vlan=VLAN) / \
            IP(src=SRC_IP, dst=DST_IP)

        # Tagged packet with PCPDEI (5, 0)
        out_packet_base2 = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=5, vlan=VLAN) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet1 = pad_input_and_output_packets(in_packet_base, out_packet_base1)
        in_packet, out_packet2 = pad_input_and_output_packets(in_packet_base, out_packet_base2)

        # IVE profile on AC1
        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 0
        ive.num_tags_to_pop = 1
        ive.tag0.tpid = Ethertype.Dot1Q.value
        ive.tag0.tci.fields.vid = VLAN
        ive.pcpdei_rewrite_only = False
        self.ac_port1.hld_obj.set_ingress_vlan_edit_command(ive)

        # EVE profile on AC2
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = VLAN
        eve.pcpdei_rewrite_only = False
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        # Test without port default pcpdei on eth1 port.
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet1,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        # Set port default pcpdei on eth1 port.
        IN_PCPDEI5 = sdk.la_vlan_pcpdei()
        IN_PCPDEI5.fields.pcp = 5
        IN_PCPDEI5.fields.dei = 0
        OUT_PCPDEI = sdk.la_vlan_pcpdei()

        self.eth_port1.hld_obj.set_ingress_default_pcpdei(IN_PCPDEI5)
        OUT_PCPDEI = self.eth_port1.hld_obj.get_ingress_default_pcpdei()
        self.assertEqual(IN_PCPDEI5.fields.pcp, OUT_PCPDEI.fields.pcp)
        self.assertEqual(IN_PCPDEI5.fields.dei, OUT_PCPDEI.fields.dei)

        # Create new AC profile with default pcpdei enabled.
        ac_profile = self.eth_port1.hld_obj.get_ac_profile()
        ac_profile.set_default_pcpdei_per_format_enabled(sdk.LA_PACKET_VLAN_FORMAT_802Q, True)
        out_enabled = ac_profile.get_default_pcpdei_per_format_enabled(sdk.LA_PACKET_VLAN_FORMAT_802Q)
        self.assertEqual(True, out_enabled)

        # Test with port default pcpdei on eth1 port.
        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet2,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)
