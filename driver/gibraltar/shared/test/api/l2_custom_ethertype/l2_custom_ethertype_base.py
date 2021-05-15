#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import topology as T
from sdk_test_case_base import *

IN_SLICE = T.get_device_slice(2)
IN_IFG = 0
IN_SERDES_FIRST = T.get_device_out_first_serdes(4)
IN_SERDES_LAST = IN_SERDES_FIRST + 1
OUT_SLICE = T.get_device_slice(4)
OUT_IFG = T.get_device_ifg(1)
OUT_SERDES_FIRST = T.get_device_out_next_first_serdes(8)
OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

SPA_SLICE_1 = T.get_device_slice(4)
SPA_IFG_1 = 0
SPA_FIRST_SERDES_1 = T.get_device_first_serdes(2)
SPA_LAST_SERDES_1 = SPA_FIRST_SERDES_1 + 1


SPA_PORT_GID_BASE = 100
SYS_PORT_GID_BASE = 23
AC_PORT_GID_BASE = 10
SPA_MEMBER_PORT1_GID_BASE = 200
SPA_MEMBER_PORT2_GID_BASE = SPA_MEMBER_PORT1_GID_BASE + 1

DST_MAC = "16:6b:f1:f2:25:16"
SRC_MAC = "e6:b2:3f:fc:6a:c9"
SRC_IP = "10.1.1.1"
DST_IP = "10.1.1.2"

VLAN = 0x3EF
DEFAULT_VLAN = 0x999
DEFAULT_SWITCH_GID = 0x999
SWITCH_GID = 0x3EF


class ac_profile:
    def __init__(self, testcase, device, tpids,
                 selector = sdk.la_ac_profile.key_selector_e_PORT_VLAN):
        self.testcase = testcase
        self.device = device
        ac_profile = self.device.create_ac_profile()
        testcase.assertIsNotNone(ac_profile)

        for tpid in tpids:
            pvf = sdk.la_packet_vlan_format_t()
            pvf.outer_vlan_is_priority = False
            pvf.tpid1 = tpid[0]
            pvf.tpid2 = tpid[1]
            ac_profile.set_key_selector_per_format(pvf, selector)

        self.hld_obj = ac_profile

    def destroy(self):
        self.device.destroy(self.hld_obj)
        self.hld_obj = None


class l2_custom_ethertype_base(sdk_test_case_base):

    def setUp(self):
        super().setUp()
        #global OUT_SLICE, IN_SLICE, SPA_SLICE_1, SPA_SLICE_2, SPA_IFG_2, VLAN
        global OUT_SLICE, IN_SLICE, SPA_SLICE_1

        IN_SLICE = T.choose_active_slices(self.device, IN_SLICE, [2, 3])
        OUT_SLICE = T.choose_active_slices(self.device, OUT_SLICE, [4, 1])
        SPA_SLICE_1 = T.choose_active_slices(self.device, SPA_SLICE_1, [4, 0])
        #SPA_SLICE_2 = T.get_device_slice(SPA_SLICE_1 + 1)
        #SPA_IFG_2 = T.get_device_ifg(SPA_IFG_1 + 1)

        self.mac_port_member_1 = T.mac_port(
            self,
            self.device,
            SPA_SLICE_1,
            SPA_IFG_1,
            SPA_FIRST_SERDES_1,
            SPA_LAST_SERDES_1)

        self.mac_port_member_1.activate()
        self.sys_port_member_1 = T.system_port(self, self.device, SPA_MEMBER_PORT1_GID_BASE, self.mac_port_member_1)

        self.rx_pkt_tpids = [[Ethertype.Dot1Q.value, 0]]

        self.ac_profile = ac_profile(self, self.device, self.rx_pkt_tpids)

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
        self.ac_port2 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE + 1,
                                     self.topology.filter_group_def, None, self.eth_port2, None, VLAN, 0x0)
        self.switch = T.switch(self, self.device, SWITCH_GID)
        self.mac = T.mac_addr(DST_MAC)

    def tearDown(self):
        super().tearDown()

    def init_spa_port(self):
        self.spa_port = T.spa_port(self, self.device, SPA_PORT_GID_BASE)
        self.eth_port_spa = T.sa_ethernet_port(self, self.device, self.spa_port)

    def _test_single_custom_supported_ethtype_single_tag_rx(self):
        """
        Test Case Details
         a) Confgiure custom Ethertype QinQ in ac profile and set the same on ethport 1
         b) Send the pkt tpid with Ethertype.Dot1Q.value, Ethertype.QinQ.value and
            Ethertype.Unknown.value on ethport1
         c) Pkt with tpid QinQ is received on ethport 1 should be recived on eth port 2 and other pkts should be dropped
        """

        allowed_tpid = Ethertype.QinQ.value

        allowed_tpids = [[allowed_tpid, 0]]

        ac_profile1 = ac_profile(self, self.device, allowed_tpids,
                                 sdk.la_ac_profile.key_selector_e_PORT_VLAN)

        self.eth_port1.set_ac_profile(ac_profile1)

        rx_pkt_tpids = [[Ethertype.Dot1Q.value, 0], [Ethertype.Unknown.value, 0]]
        rx_pkt_tpids.append([allowed_tpid, 0])

        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 0
        ive.num_tags_to_pop = 1
        ive.tag0.tpid = 0
        ive.tag0.tci.fields.vid = 0
        self.ac_port1.hld_obj.set_ingress_vlan_edit_command(ive)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = VLAN
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        self.switch.hld_obj.set_mac_entry(self.mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        self.ac_port1.hld_obj.attach_to_switch(self.switch.hld_obj)
        self.ac_port2.hld_obj.attach_to_switch(self.switch.hld_obj)

        for tpid in rx_pkt_tpids:
            in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=tpid[0]) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

            if (tpid[0] == allowed_tpid):
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
            else:
                run_and_drop(
                    self,
                    self.device,
                    in_packet,
                    IN_SLICE,
                    IN_IFG,
                    IN_SERDES_FIRST)

    def _test_custom_supported_ethtype_single_tag_rx(self):
        """
        Test Case Details
         a) Confgiure custom Ethertype Dot1Q and QinQ in ac profile and set the same on ethport 1
         b) Send the pkt tpid with Ethertype.Dot1Q.value, Ethertype.QinQ.value, Ethertype.SVLAN.value and
            Ethertype.Unknown.value on ethport1
         c) Pkts which are received on ethport 1 should be recived on eth port 2 with tpid value as Dot1Q
            except tpid with  Ethertype.Unknown.value
        """
        allowed_tpids = [[Ethertype.Dot1Q.value, 0], [Ethertype.QinQ.value, 0]]

        ac_profile1 = ac_profile(self, self.device, allowed_tpids,
                                 sdk.la_ac_profile.key_selector_e_PORT_VLAN)

        self.eth_port1.set_ac_profile(ac_profile1)
        allowed_tpids.append([Ethertype.SVLAN.value, 0])
        rx_pkt_tpids = allowed_tpids
        drop_tpid = Ethertype.Unknown.value
        rx_pkt_tpids.append([drop_tpid, 0])

        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 0
        ive.num_tags_to_pop = 1
        ive.tag0.tpid = 0
        ive.tag0.tci.fields.vid = 0
        self.ac_port1.hld_obj.set_ingress_vlan_edit_command(ive)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = VLAN
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        self.switch.hld_obj.set_mac_entry(self.mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        self.ac_port1.hld_obj.attach_to_switch(self.switch.hld_obj)
        self.ac_port2.hld_obj.attach_to_switch(self.switch.hld_obj)

        for tpid in rx_pkt_tpids:
            in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=tpid[0]) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

            if (tpid[0] != drop_tpid):
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
            else:
                run_and_drop(
                    self,
                    self.device,
                    in_packet,
                    IN_SLICE,
                    IN_IFG,
                    IN_SERDES_FIRST)

    def _test_custom_supported_ethtype_single_tag_rx_ive(self):
        """
        Test Case Details:
         a) Confgiure custom Ethertype Dot1Q and QinQ in ac profile and set the same on ethport 1
         b) Change the incoming pkt tpid by using IVE via translate operation i.e push and pop operation
         c) Send the pkt tpid with Ethertype.Dot1Q.value, Ethertype.QinQ.value, Ethertype.SVLAN.value and
            Ethertype.Unknown.value on ethport1
         d) Pkts which are received on ethport 1 with configured custom Ethertype should be recived on eth port 2
            with changed tpid at IVE and other pkts should  be dropped
        """

        allowed_tpids = [[Ethertype.Dot1Q.value, 0], [Ethertype.QinQ.value, 0]]
        #allowed_tpids = [[Ethertype.QinQ.value, 0]]

        ac_profile1 = ac_profile(self, self.device, allowed_tpids,
                                 sdk.la_ac_profile.key_selector_e_PORT_VLAN)
        self.eth_port1.set_ac_profile(ac_profile1)

        allowed_tpids.append([Ethertype.SVLAN.value, 0])
        rx_pkt_tpids = allowed_tpids

        drop_tpid = Ethertype.Unknown.value

        rx_pkt_tpids.append([drop_tpid, 0])

        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 1
        ive.num_tags_to_pop = 1
        ive.tag0.tpid = Ethertype.Dot1Q.value
        ive.tag0.tci.fields.vid = VLAN
        self.ac_port1.hld_obj.set_ingress_vlan_edit_command(ive)

        self.switch.hld_obj.set_mac_entry(self.mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        self.ac_port1.hld_obj.attach_to_switch(self.switch.hld_obj)
        self.ac_port2.hld_obj.attach_to_switch(self.switch.hld_obj)

        for tpid in rx_pkt_tpids:
            in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=tpid[0]) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

            if (tpid[0] != drop_tpid):
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
            else:
                run_and_drop(
                    self,
                    self.device,
                    in_packet,
                    IN_SLICE,
                    IN_IFG,
                    IN_SERDES_FIRST)

    def _test_custom_supported_ethtype_single_tag_tx_eve(self):
        """
        Test Case Details:
         a) Confgiure custom Ethertype Dot1Q and QinQ in ac profile and set the same on ethport 1
         b) Change the outgoing pkt tpid by using EVE translate operation i.e. push and pop at EVE.
         c) Send the pkt tpid with Ethertype.Dot1Q.value, Ethertype.QinQ.value, Ethertype.SVLAN.value and
            Ethertype.Unknown.value on ethport1
         d) Pkts which are received on ethport 1 should be recived on eth port 2
            with changed tpid vlaue for the configured custom Ethertype on ethport 1 and other pkts should be dropped
        """
        allowed_tpids = [[Ethertype.QinQ.value, 0]]

        ac_profile1 = ac_profile(self, self.device, allowed_tpids,
                                 sdk.la_ac_profile.key_selector_e_PORT_VLAN)
        self.eth_port1.set_ac_profile(ac_profile1)

        allowed_tpids.append([Ethertype.SVLAN.value, 0])
        rx_pkt_tpids = allowed_tpids

        drop_tpid = Ethertype.Unknown.value

        rx_pkt_tpids.append([drop_tpid, 0])

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 1
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = VLAN
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        self.switch.hld_obj.set_mac_entry(self.mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        self.ac_port1.hld_obj.attach_to_switch(self.switch.hld_obj)
        self.ac_port2.hld_obj.attach_to_switch(self.switch.hld_obj)

        for tpid in rx_pkt_tpids:
            in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=tpid[0]) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

            if (tpid[0] != drop_tpid):
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
            else:
                run_and_drop(
                    self,
                    self.device,
                    in_packet,
                    IN_SLICE,
                    IN_IFG,
                    IN_SERDES_FIRST)

    def _test_custom_supported_ethtype_single_tag_rx_ive_eve_xlate(self):
        """
        Test Case Details:
         a) Confgiure custom Ethertype Dot1Q and QinQ in ac profile and set the same on ethport 1
         b) Change the incoming pkt tpid by using IVE  with Unknown tpid value via translate operation i.e push and pop operation
         c) Change the IVE translated tpid by using EVE via translate operation i.e push and pop operation
         d) Send the pkt tpid with Ethertype.Dot1Q.value, Ethertype.QinQ.value, Ethertype.SVLAN.value and
            Ethertype.Unknown.value on ethport1
         d) Pkts which are received on ethport 1 should be dropped  at eth port 2 as EVE translat operation drops the pkt
            by EVE drop table as Unknown tpid  is not programmed in EveDropVlanEthTypeReg
        """
        allowed_tpids = [[Ethertype.QinQ.value, 0]]

        ac_profile1 = ac_profile(self, self.device, allowed_tpids,
                                 sdk.la_ac_profile.key_selector_e_PORT_VLAN)
        self.eth_port1.set_ac_profile(ac_profile1)

        allowed_tpids.append([Ethertype.SVLAN.value, 0])
        rx_pkt_tpids = allowed_tpids

        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 1
        ive.num_tags_to_pop = 1
        ive.tag0.tpid = Ethertype.Unknown.value
        ive.tag0.tci.fields.vid = VLAN
        self.ac_port1.hld_obj.set_ingress_vlan_edit_command(ive)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 1
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = VLAN
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        self.switch.hld_obj.set_mac_entry(self.mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        self.ac_port1.hld_obj.attach_to_switch(self.switch.hld_obj)
        self.ac_port2.hld_obj.attach_to_switch(self.switch.hld_obj)

        for tpid in rx_pkt_tpids:
            in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=tpid[0]) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

            run_and_drop(
                self,
                self.device,
                in_packet,
                IN_SLICE,
                IN_IFG,
                IN_SERDES_FIRST)

    def _test_custom_supported_ethtype_single_tag_tx(self):
        """
         Test case details:
         case 1:
             a) Configure ac_profile with tpids 0 with selector as key_selector_e_PORT and set same on the eth_port1
             b) Create l2 ac_port1 on eth_port1 with vid1 as 0 and vid2 as 0
             c) On l2 ac_port2, set EVE with tpid as QinQ and vlan value
             d) Send untagged pkt on eth_port1
             e) On eth_port2, pkt should be received with tpid as QinQ with vlan value is set on eth_port2

         case 2:
             a) configure custom Ethettype Dot1Q, QinQ in ac profile and set the same on ethport 1
             b) Confgiure custom QinQ in ac profile  and set the same on ethport 2
             c) Send the single tag pkt with tpid as Ethertype.Dot1Q.value, Ethertype.QinQ.value and  Ethertype.SVLAN.value on  ethport 1
             d) Pkts which are received on ethport 1 should be recived on eth port 2 with tpid value as QinQ.value
        """
        self.ac_port1.destroy()
        ac_profile0 = ac_profile(self, self.device, [[0, 0]],
                                 sdk.la_ac_profile.key_selector_e_PORT)
        self.eth_port1.set_ac_profile(ac_profile0)

        self.ac_port1 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE,
                                     self.topology.filter_group_def, None, self.eth_port1, None, 0x0, 0x0)
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.QinQ.value
        eve.tag0.tci.fields.vid = VLAN
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        self.switch.hld_obj.set_mac_entry(self.mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        self.ac_port1.hld_obj.attach_to_switch(self.switch.hld_obj)
        self.ac_port2.hld_obj.attach_to_switch(self.switch.hld_obj)
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.IPv4.value) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=VLAN) / \
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

        # remove ac port1 as needs to be created with VLAN
        self.ac_port1.destroy()

        allowed_tpids = [[Ethertype.Dot1Q.value, 0], [Ethertype.QinQ.value, 0]]

        ac_profile1 = ac_profile(self, self.device, allowed_tpids,
                                 sdk.la_ac_profile.key_selector_e_PORT_VLAN)

        self.eth_port1.set_ac_profile(ac_profile1)

        self.ac_port1 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE,
                                     self.topology.filter_group_def, None, self.eth_port1, None, VLAN, 0x0)

        allowed_tpids.append([Ethertype.SVLAN.value, 0])

        rx_pkt_tpids = allowed_tpids

        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 0
        ive.num_tags_to_pop = 1
        ive.tag0.tpid = 0
        ive.tag0.tci.fields.vid = 0
        self.ac_port1.hld_obj.set_ingress_vlan_edit_command(ive)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.SVLAN.value
        eve.tag0.tci.fields.vid = VLAN
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        self.switch.hld_obj.set_mac_entry(self.mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        self.ac_port1.hld_obj.attach_to_switch(self.switch.hld_obj)

        for tpid in rx_pkt_tpids:
            in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=tpid[0]) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.SVLAN.value) / \
                Dot1Q(vlan=VLAN) / \
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

    def _test_custom_supported_ethtype_double_tag_rx(self):
        """
        Test Case Details:
         a) Confgiure custom Ethertype Dot1Q and QinQ in ac profile and set the same on ethport 1
         b) case 1)Send double tag pkt outer tpid with Ethertype.Dot1Q.value, Ethertype.QinQ.value, Ethertype.SVLAN.value and
            Ethertype.Unknown.value and inner tpid as Ethertype.Unknown.value on ethport1
            case 2)Send the pkt outer tpid with Ethertype.Dot1Q.value, Ethertype.QinQ.value, Ethertype.SVLAN.value and
            Ethertype.Unknown.value and inner tpid as outer tpid on ethport1
         c) Pkts which are received on ethport 1 should be recived on eth port 2 with tpid value as Dot1Q
            except tpid with  Ethertype.Unknown.value and inner tpid shouldn't be changed.
        """
        allowed_tpids = [[Ethertype.Dot1Q.value, 0], [Ethertype.QinQ.value, 0]]

        ac_profile1 = ac_profile(self, self.device, allowed_tpids,
                                 sdk.la_ac_profile.key_selector_e_PORT_VLAN)

        self.eth_port1.set_ac_profile(ac_profile1)

        allowed_tpids.append([Ethertype.SVLAN.value, 0])

        drop_tpid = Ethertype.Unknown.value

        rx_pkt_tpids = allowed_tpids

        rx_pkt_tpids.append([drop_tpid, 0])

        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 0
        ive.num_tags_to_pop = 1
        ive.tag0.tpid = 0
        ive.tag0.tci.fields.vid = 0
        self.ac_port1.hld_obj.set_ingress_vlan_edit_command(ive)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = VLAN
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        self.switch.hld_obj.set_mac_entry(self.mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        self.ac_port1.hld_obj.attach_to_switch(self.switch.hld_obj)
        self.ac_port2.hld_obj.attach_to_switch(self.switch.hld_obj)
        """
        case 1 : Inner tpid is Ethertype.Unknown.value and this shouldn't be affected
        """
        for tpid in rx_pkt_tpids:
            in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=tpid[0]) / \
                Dot1Q(vlan=VLAN, type=Ethertype.Unknown.value) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=VLAN, type=Ethertype.Unknown.value) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

            if (tpid[0] != drop_tpid):
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
            else:
                run_and_drop(
                    self,
                    self.device,
                    in_packet,
                    IN_SLICE,
                    IN_IFG,
                    IN_SERDES_FIRST)
        """
        case 2 : Inner tpid is same as outer tpid. The inner tpid shouldn't be affected
        """
        for tpid in rx_pkt_tpids:
            in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=tpid[0]) / \
                Dot1Q(vlan=VLAN, type=tpid) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=VLAN, type=tpid) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

            if (tpid[0] != drop_tpid):
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
            else:
                run_and_drop(
                    self,
                    self.device,
                    in_packet,
                    IN_SLICE,
                    IN_IFG,
                    IN_SERDES_FIRST)

    def _test_custom_supported_ethtype_double_tag_tx(self):
        """
         Test case detaails:
         a) configure custom  Ethettype Dot1Q, QinQ in ac profile and set the same on ethport 1
         b) Confgiure custom  QinQ in ac profile  and set the same on ethport 2
         c) case 1)Send double tag pkt outer tpid with Ethertype.Dot1Q.value, Ethertype.QinQ.value and Ethertype.SVLAN.value
            and inner tpid as Ethertype.Unknown.value on ethport1
            case 2)Send the pkt outer tpid with Ethertype.Dot1Q.value, Ethertype.QinQ.value and Ethertype.SVLAN.value
            and inner tpid as outer tpid on ethport1
         d) Pkts which are received on ethport 1 should be recived on eth port 2 with outer tpid value as QinQ.value and inner
            tpid should be same as original pkt
        """
        self.ac_port1.destroy()
        self.ac_port2.destroy()

        allowed_tpids = [[Ethertype.Dot1Q.value, 0], [Ethertype.QinQ.value, 0]]

        ac_profile1 = ac_profile(self, self.device, allowed_tpids,
                                 sdk.la_ac_profile.key_selector_e_PORT_VLAN)

        self.eth_port1.set_ac_profile(ac_profile1)

        allowed_tpids.append([Ethertype.SVLAN.value, 0])

        self.ac_port1 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE,
                                     self.topology.filter_group_def, None, self.eth_port1, None, VLAN, 0x0)

        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 0
        ive.num_tags_to_pop = 1
        ive.tag0.tpid = 0
        ive.tag0.tci.fields.vid = 0
        self.ac_port1.hld_obj.set_ingress_vlan_edit_command(ive)

        self.ac_port2 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE + 1,
                                     self.topology.filter_group_def, None, self.eth_port2, None, VLAN, 0x0)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.QinQ.value
        eve.tag0.tci.fields.vid = VLAN
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        self.switch.hld_obj.set_mac_entry(self.mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        self.ac_port1.hld_obj.attach_to_switch(self.switch.hld_obj)
        self.ac_port2.hld_obj.attach_to_switch(self.switch.hld_obj)
        rx_pkt_tpids = allowed_tpids
        """
        case 1 : Inner tpid is Ethertype.Unknown.value and this shouldn't be affected
        """

        for tpid in rx_pkt_tpids:
            in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=tpid[0]) / \
                Dot1Q(vlan=VLAN, type=Ethertype.Unknown.value) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.QinQ.value) / \
                Dot1Q(vlan=VLAN, type=Ethertype.Unknown.value) / \
                Dot1Q(vlan=VLAN) / \
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
        """
        case 2 : Inner tpid is same as outer tpid. The inner tpid shouldn't be affected
        """

        for tpid in rx_pkt_tpids:
            in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=tpid[0]) / \
                Dot1Q(vlan=VLAN, type=tpid) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.QinQ.value) / \
                Dot1Q(vlan=VLAN, type=tpid) / \
                Dot1Q(vlan=VLAN) / \
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

    def _test_single_custom_supported_ethtype_single_tag_rx_tx_on_spa(self):
        """
        Test Case Details:
         case 1:
         a) Confgiure custom Ethertype QinQ in ac profile and set the same on ethport_spa
         b) Send the pkt tpid with Ethertype.Dot1Q.value, Ethertype.QinQ.value and
            Ethertype.Unknown.value on ethport_spa1
         c) Pkt with tpid QinQ is received on ethport_spa should be recived on eth port 2 and other pkts should be dropped
         case 2:
         a) Confgiure custom Ethertype QinQ, Dot1Q in ac profile and set the same on eth_port_3
         b) Configure eve tpid value as QinQ and set as egress vlan edit for the ac port on eth_port_spa`
         c) Send the pkt tpid with Dot1Q, QinQ and  SVLAN on eth_port_3
         d) Pkt which are received on eth_port_3 should be recived on eth_port_spa with tpid QinQ
        """
        self.ac_port1.destroy()
        self.ac_port2.destroy()

        """
        case 1: Send pkt on eth_port_spa and pkt should be received on
        eth_port_2 for the allowed tpids and other pkts should be dropped
        """

        allowed_tpid = Ethertype.QinQ.value

        allowed_tpids = [[allowed_tpid, 0]]

        ac_profile1 = ac_profile(self, self.device, allowed_tpids,
                                 sdk.la_ac_profile.key_selector_e_PORT_VLAN)
        self.init_spa_port()
        self.eth_port_spa.set_ac_profile(ac_profile1)

        self.ac_port1 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE, self.topology.filter_group_def, None,
                                     self.eth_port_spa, None, VLAN, 0x0)

        rx_pkt_tpids = allowed_tpids

        rx_pkt_tpids.append([Ethertype.Dot1Q.value, 0])
        rx_pkt_tpids.append([Ethertype.Unknown.value, 0])

        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 0
        ive.num_tags_to_pop = 1
        ive.tag0.tpid = 0
        ive.tag0.tci.fields.vid = 0
        self.ac_port1.hld_obj.set_ingress_vlan_edit_command(ive)

        self.ac_port2 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE + 1,
                                     self.topology.filter_group_def, None, self.eth_port2, None, VLAN, 0x0)
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = VLAN
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        self.switch.hld_obj.set_mac_entry(self.mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        self.ac_port1.hld_obj.attach_to_switch(self.switch.hld_obj)
        self.ac_port2.hld_obj.attach_to_switch(self.switch.hld_obj)

        # Add first member port
        self.spa_port.add(self.sys_port_member_1)
        self.spa_port.hld_obj.set_member_transmit_enabled(self.sys_port_member_1.hld_obj, True)

        for tpid in rx_pkt_tpids:
            in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=tpid[0]) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

            if (tpid[0] == allowed_tpid):
                run_and_compare(
                    self,
                    self.device,
                    in_packet,
                    SPA_SLICE_1,
                    SPA_IFG_1,
                    SPA_FIRST_SERDES_1,
                    out_packet,
                    OUT_SLICE,
                    OUT_IFG,
                    OUT_SERDES_FIRST)
            else:
                run_and_drop(
                    self,
                    self.device,
                    in_packet,
                    SPA_SLICE_1,
                    SPA_IFG_1,
                    SPA_FIRST_SERDES_1)
        """
        # case 2: Send pkt on eth_port1  and pkt should be received on SPA port with tpid QinQ
        """
        allowed_tpids = [[Ethertype.Dot1Q.value, 0], [Ethertype.QinQ.value, 0]]

        allowed_tpids = [[Ethertype.QinQ.value, 0]]
        ac_profile1 = ac_profile(self, self.device, allowed_tpids,
                                 sdk.la_ac_profile.key_selector_e_PORT_VLAN)

        self.eth_port1.set_ac_profile(ac_profile1)

        allowed_tpids.append([Ethertype.SVLAN.value, 0])

        self.ac_port3 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE + 2,
                                     self.topology.filter_group_def, None, self.eth_port1, None, VLAN, 0x0)

        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 0
        ive.num_tags_to_pop = 1
        ive.tag0.tpid = 0
        ive.tag0.tci.fields.vid = 0
        self.ac_port3.hld_obj.set_ingress_vlan_edit_command(ive)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.QinQ.value
        eve.tag0.tci.fields.vid = VLAN
        self.ac_port1.hld_obj.set_egress_vlan_edit_command(eve)
        mac = T.mac_addr(SRC_MAC)
        self.switch.hld_obj.set_mac_entry(mac.hld_obj, self.ac_port1.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        self.ac_port3.hld_obj.attach_to_switch(self.switch.hld_obj)
        rx_pkt_tpids = allowed_tpids
        for tpid in rx_pkt_tpids:
            in_packet_base = Ether(dst=SRC_MAC, src=DST_MAC, type=tpid[0]) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            out_packet_base = Ether(dst=SRC_MAC, src=DST_MAC, type=Ethertype.QinQ.value) / \
                Dot1Q(vlan=VLAN) / \
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
                SPA_SLICE_1,
                SPA_IFG_1,
                SPA_FIRST_SERDES_1)

    def _test_custom_supported_ethtype_QinQ_tunnel_rx_tx(self):
        """
        Test Case Details:
        Case 1: Rx Traffic
         a) Confgiure custom Ethertype Dot1Q and QinQ in ac profile with selector as key_selector_e_PORT and set the same on ethport 1
         b) Send the pkt tpid with Ethertype.Dot1Q.value, Ethertype.QinQ.value, Ethertype.SVLAN.value and
            Ethertype.Unknown.value with CVLAN  on ethport1
         c) Pkts which are received on ethport 1 should be recived on eth port 2 with double tag with outer tpid value as Dot1Q
           and SVLAN. The orignal pkt tpid and CVLAN shouldn't be touched. The pkt with Ethertype.Unknown.value should be dropped.
        Case 2: Tx Traffic
         a) Reverse traffic
        """
        self.ac_port1.destroy()

        allowed_tpids = [[Ethertype.Dot1Q.value, 0], [Ethertype.QinQ.value, 0]]

        ac_profile1 = ac_profile(self, self.device, allowed_tpids,
                                 sdk.la_ac_profile.key_selector_e_PORT)

        self.eth_port1.set_ac_profile(ac_profile1)
        self.ac_port1 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE,
                                     self.topology.filter_group_def, None, self.eth_port1, None, 0x0, 0x0)
        allowed_tpids.append([Ethertype.SVLAN.value, 0])

        rx_pkt_tpids = allowed_tpids

        drop_tpid = Ethertype.Unknown.value

        rx_pkt_tpids.append([drop_tpid, 0])

        CVLAN = 0x100
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = VLAN
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        self.switch.hld_obj.set_mac_entry(self.mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        self.ac_port1.hld_obj.attach_to_switch(self.switch.hld_obj)
        self.ac_port2.hld_obj.attach_to_switch(self.switch.hld_obj)

        for tpid in rx_pkt_tpids:
            in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=tpid[0]) / \
                Dot1Q(vlan=CVLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=VLAN, type=tpid[0]) / \
                Dot1Q(vlan=CVLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

            if (tpid[0] != drop_tpid):
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
            else:
                run_and_drop(
                    self,
                    self.device,
                    in_packet,
                    IN_SLICE,
                    IN_IFG,
                    IN_SERDES_FIRST)
        """
        Reverse traffic
        """
        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 0
        ive.num_tags_to_pop = 1
        ive.tag0.tpid = Ethertype.Dot1Q.value
        ive.tag0.tci.fields.vid = 0
        self.ac_port2.hld_obj.set_ingress_vlan_edit_command(ive)
        mac = T.mac_addr(SRC_MAC)
        self.switch.hld_obj.set_mac_entry(mac.hld_obj, self.ac_port1.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

        in_packet_base = Ether(dst=SRC_MAC, src=DST_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=VLAN, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=CVLAN) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=SRC_MAC, src=DST_MAC, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=CVLAN) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        run_and_compare(
            self,
            self.device,
            in_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST,
            out_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST)

    def _test_custom_supported_ethtype_ac_profile_change_rx(self):
        """
        Test Case Details: The intention of this TC is to change the ac profile on the fly, w/o deleting the ac port
        a) In the setUp function ac_profile is created and same is being set to eth_port1 and eth_port2.ac_port1 and ac_port2 are created
         on eth_port1 and eth_port2 respectively.
        b) New ac_profile is created here with Dot1Q & QinQ tpids and same is applied on eth_port1 without destorying the ac_port1
        c) Send the pkt with Dot1Q, QinQ, SVLAN and unknowen tpids on eth_port1
        d) All the pkts should be received on eth_port2 with tpid 0x8100 except Unknown tpid pkt
        """

        allowed_tpids = [[Ethertype.Dot1Q.value, 0], [Ethertype.QinQ.value, 0]]

        ac_profile1 = ac_profile(self, self.device, allowed_tpids,
                                 sdk.la_ac_profile.key_selector_e_PORT_VLAN)

        self.eth_port1.set_ac_profile(ac_profile1)

        allowed_tpids.append([Ethertype.SVLAN.value, 0])

        rx_pkt_tpids = allowed_tpids

        drop_tpid = Ethertype.Unknown.value

        rx_pkt_tpids.append([drop_tpid, 0])

        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 0
        ive.num_tags_to_pop = 1
        ive.tag0.tpid = 0
        ive.tag0.tci.fields.vid = 0
        self.ac_port1.hld_obj.set_ingress_vlan_edit_command(ive)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = VLAN
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        self.switch.hld_obj.set_mac_entry(self.mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        self.ac_port1.hld_obj.attach_to_switch(self.switch.hld_obj)
        self.ac_port2.hld_obj.attach_to_switch(self.switch.hld_obj)

        for tpid in rx_pkt_tpids:
            in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=tpid[0]) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

            if (tpid[0] != drop_tpid):
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
            else:
                run_and_drop(
                    self,
                    self.device,
                    in_packet,
                    IN_SLICE,
                    IN_IFG,
                    IN_SERDES_FIRST)

    def _test_custom_supported_ethtype_ac_profile_content_update_rx(self):
        """
        Test Case Details: The intention of this TC is to update the existing ac profile content
        a) In the setUp function ac_profile is created and same is being set to eth_port1 and eth_port2.ac_port1 and ac_port2 are created
         on eth_port1 and eth_port2 respectively.
        b) Add the new tpid (QinQ) in the ac_profile which is created in the setUp
        c) Send the pkt with Dot1Q, QinQ
        d) All the pkts should be received on eth_port2 with tpid 0x8100
        """
        pvf = sdk.la_packet_vlan_format_t()
        pvf.outer_vlan_is_priority = False
        pvf.tpid1 = Ethertype.QinQ.value
        pvf.tpid2 = 0x0000
        self.ac_profile.hld_obj.set_key_selector_per_format(pvf, sdk.la_ac_profile.key_selector_e_PORT_VLAN)

        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 0
        ive.num_tags_to_pop = 1
        ive.tag0.tpid = 0
        ive.tag0.tci.fields.vid = 0
        self.ac_port1.hld_obj.set_ingress_vlan_edit_command(ive)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = VLAN
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        self.switch.hld_obj.set_mac_entry(self.mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        self.ac_port1.hld_obj.attach_to_switch(self.switch.hld_obj)
        self.ac_port2.hld_obj.attach_to_switch(self.switch.hld_obj)

        for tpid in [Ethertype.Dot1Q.value, Ethertype.QinQ.value]:
            in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=tpid) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=VLAN) / \
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

    def _test_custom_supported_ethtype_selective_QinQ_tunnel_rx_tx(self):
        """
        Test Case Details:
        Case 1:
         a) Confgiure custom QinQ in ac profile with selector as key_selector_e_PORT_VLAN_VLAN_WITH_FALLBACK
         b) Set default vid from port for QinQ tpid
         c) Set ac_profile1 on eth_port 1
         d) Add service mapping for customer vlan
         e) Send the pkt tpid with QinQ, SVLAN and Unknown with CVLAN  on ethport1
         f) Pkts which are received on ethport 1 should be recived on eth port 2 with double tag with outer tpid value as Dot1Q
           and SVLAN. The orignal pkt tpid and CVLAN shouldn't be touched. The pkt with Ethertype.Unknown.value should be dropped.
        Case 2:
         a) Create a default_switch,ac_port3 on eth_port 1 and ac_port4 on eth_port 2 respectively
         b) Attach ac_port3 to default_swith and add service mapping with vid as 0 on ac_port3
         c) Send the pkt tpid with QinQ, SVLAN and Unknown with CVLAN  on ethport1
         f) Pkts which are received on ethport 1 should be recived on eth port 2 with double tag with outer tpid value as Dot1Q
           and SVLAN. The orignal pkt tpid and CVLAN shouldn't be touched. The pkt with Ethertype.Unknown.value should be dropped.
        Case 3:
         a) Reverse traffic for non default QinQ tunnel
        Case 4:
         a) Reverse traffic for default QinQ tunnel
        """
        self.ac_port1.destroy()

        allowed_tpids = [[Ethertype.QinQ.value, 0]]

        ac_profile1 = ac_profile(self, self.device, allowed_tpids,
                                 sdk.la_ac_profile.key_selector_e_PORT_VLAN_VLAN_WITH_FALLBACK)

        # set default vid to take vlan1 from port
        pvf = sdk.la_packet_vlan_format_t()
        pvf.outer_vlan_is_priority = False
        pvf.tpid1 = Ethertype.QinQ.value
        pvf.tpid2 = 0
        ac_profile1.hld_obj.set_default_vid_per_format_enabled(pvf, True)

        self.eth_port1.set_ac_profile(ac_profile1)
        self.ac_port1 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE,
                                     self.topology.filter_group_def, None, self.eth_port1, None, VLAN, 0x0)

        allowed_tpids.append([Ethertype.SVLAN.value, 0])

        drop_tpid = Ethertype.Unknown.value
        rx_pkt_tpids = allowed_tpids
        rx_pkt_tpids.append([drop_tpid, 0])

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = VLAN
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        self.ac_port1.hld_obj.attach_to_switch(self.switch.hld_obj)

        CVLAN = 0x100
        self.ac_port1.hld_obj.add_service_mapping_vid(CVLAN)
        self.ac_port1.hld_obj.add_service_mapping_vid(0x200)
        self.ac_port1.hld_obj.add_service_mapping_vid(0x300)

        self.switch.hld_obj.set_mac_entry(self.mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        self.ac_port2.hld_obj.attach_to_switch(self.switch.hld_obj)

        for tpid in rx_pkt_tpids:
            in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=tpid[0]) / \
                Dot1Q(vlan=CVLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=VLAN, type=tpid[0]) / \
                Dot1Q(vlan=CVLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

            if (tpid[0] != drop_tpid):
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
            else:
                run_and_drop(
                    self,
                    self.device,
                    in_packet,
                    IN_SLICE,
                    IN_IFG,
                    IN_SERDES_FIRST)

        self.default_switch = T.switch(self, self.device, DEFAULT_SWITCH_GID)
        DEFAULT_VLAN = 0x500

        self.ac_port3 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE + 2,
                                     self.topology.filter_group_def, None, self.eth_port1, None, 0, 0x0)

        self.ac_port4 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE + 3,
                                     self.topology.filter_group_def, None, self.eth_port2, None, DEFAULT_VLAN, 0x0)

        self.default_switch.hld_obj.set_mac_entry(self.mac.hld_obj, self.ac_port4.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

        self.ac_port3.hld_obj.attach_to_switch(self.default_switch.hld_obj)
        self.ac_port4.hld_obj.attach_to_switch(self.default_switch.hld_obj)
        # Add default mapping entry
        self.ac_port3.hld_obj.add_service_mapping_vid(0x0)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = DEFAULT_VLAN
        self.ac_port4.hld_obj.set_egress_vlan_edit_command(eve)

        for tpid in rx_pkt_tpids:
            in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=tpid[0]) / \
                Dot1Q(vlan=0x150) / \
                IP(src=SRC_IP, dst=DST_IP)

            out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=DEFAULT_VLAN, type=tpid[0]) / \
                Dot1Q(vlan=0x150) / \
                IP(src=SRC_IP, dst=DST_IP)

            in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

            if (tpid[0] != drop_tpid):
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
            else:
                run_and_drop(
                    self,
                    self.device,
                    in_packet,
                    IN_SLICE,
                    IN_IFG,
                    IN_SERDES_FIRST)
        """
        Reverse traffic for non-default QinQ tunnel
        """
        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 0
        ive.num_tags_to_pop = 1
        ive.tag0.tpid = Ethertype.Dot1Q.value
        ive.tag0.tci.fields.vid = 0
        self.ac_port2.hld_obj.set_ingress_vlan_edit_command(ive)
        mac = T.mac_addr(SRC_MAC)
        self.switch.hld_obj.set_mac_entry(mac.hld_obj, self.ac_port1.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

        in_packet_base = Ether(dst=SRC_MAC, src=DST_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=VLAN, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=CVLAN) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=SRC_MAC, src=DST_MAC, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=CVLAN) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        run_and_compare(
            self,
            self.device,
            in_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST,
            out_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST)
        """
        Reverse traffic for default QinQ tunnel
        """
        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 0
        ive.num_tags_to_pop = 1
        ive.tag0.tpid = Ethertype.Dot1Q.value
        ive.tag0.tci.fields.vid = DEFAULT_VLAN
        self.ac_port4.hld_obj.set_ingress_vlan_edit_command(ive)
        mac = T.mac_addr(SRC_MAC)
        self.default_switch.hld_obj.set_mac_entry(mac.hld_obj, self.ac_port3.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

        in_packet_base = Ether(dst=SRC_MAC, src=DST_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=DEFAULT_VLAN, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=0x150) / \
            IP(src=SRC_IP, dst=DST_IP)

        out_packet_base = Ether(dst=SRC_MAC, src=DST_MAC, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=0x150) / \
            IP(src=SRC_IP, dst=DST_IP)

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        run_and_compare(
            self,
            self.device,
            in_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST,
            out_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST)

    def _test_custom_supported_ethtype_double_tag_honor_both_tpid_rx(self):
        """
        Test Case Details:
         a) Confgiure custom Ethertype set [QinQ, Dot1Q] in ac profile and set the same on ethport 1
         b) Send double tag pkt wtih outer tpid as QinQ & inner tpid as Dot1Q, outer tpid as SVLAN.value &
            inner tpid as Dot1Q, outer tpid as unknown & inner tpid as 0 on eth port1
         c) Pkts which are received on ethport 1 should be recived on eth port 2 with tpid value as Dot1Q
            except tpid with  Unknown and inner tpid shouldn't be changed.
            Note: Only 0x88a8/0x9100 (outer) and 0x8100(inner) are supported. Remaining case, the inner tpid is
            not parsed
        """
        allowed_tpids = [[Ethertype.QinQ.value, Ethertype.Dot1Q.value]]

        ac_profile1 = ac_profile(self, self.device, allowed_tpids,
                                 sdk.la_ac_profile.key_selector_e_PORT_VLAN)

        self.eth_port1.set_ac_profile(ac_profile1)

        allowed_tpids.append([Ethertype.SVLAN.value, Ethertype.Dot1Q.value])

        drop_tpid = Ethertype.Unknown.value

        rx_pkt_tpids = allowed_tpids

        rx_pkt_tpids.append([drop_tpid, 0])

        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 0
        ive.num_tags_to_pop = 1
        ive.tag0.tpid = 0
        ive.tag0.tci.fields.vid = 0
        self.ac_port1.hld_obj.set_ingress_vlan_edit_command(ive)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = VLAN
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

        self.switch.hld_obj.set_mac_entry(self.mac.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        self.ac_port1.hld_obj.attach_to_switch(self.switch.hld_obj)
        self.ac_port2.hld_obj.attach_to_switch(self.switch.hld_obj)
        for tpid in rx_pkt_tpids:
            in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=tpid[0]) / \
                Dot1Q(vlan=VLAN, type=tpid[1]) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=VLAN, type=tpid[1]) / \
                Dot1Q(vlan=VLAN) / \
                IP(src=SRC_IP, dst=DST_IP)

            in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

            if (tpid[0] != drop_tpid):
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
            else:
                run_and_drop(
                    self,
                    self.device,
                    in_packet,
                    IN_SLICE,
                    IN_IFG,
                    IN_SERDES_FIRST)
