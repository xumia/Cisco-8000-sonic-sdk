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
import sim_utils
from scapy.all import *
import unittest
from leaba import sdk
import topology as T
from l2_switch_base import l2_switch_base
import nplapicli as nplapi


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l2_switch_bcast_snoop_test(l2_switch_base):

    IN_SLICE_1 = 3  # must be an odd number
    INJECT_SLICE = 2  # must be an even number
    INJECT_SLICE_1 = 0
    INJECT_IFG = 0
    INJECT_PIF_FIRST = 8
    INJECT_PIF_LAST = INJECT_PIF_FIRST + 1
    HOST_PIF = 18

    IN_SP_GID = l2_switch_base.SYS_PORT_GID_BASE
    OUT_SP_GID = l2_switch_base.SYS_PORT_GID_BASE + 1
    INJECT_SP_GID = l2_switch_base.SYS_PORT_GID_BASE + 2
    INJECT_SP_GID_1 = l2_switch_base.SYS_PORT_GID_BASE + 3
    RECYCLE_SP_GID = l2_switch_base.SYS_PORT_GID_BASE + 4

    PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
    PUNT_INJECT_PORT_MAC_ADDR_1 = "12:34:56:78:9a:bd"
    HOST_MAC_ADDR = "fe:dc:ba:98:76:54"

    PUNT_VLAN = 0xA13

    MIRROR_CMD_GID = 10

    MIRROR_GID_INGRESS_OFFSET = 32
    MIRROR_GID_EGRESS_OFFSET = 0
    MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
    MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET

    MIRROR_VLAN = 0xA12

    VRF_GID_LOCAL = 50 if not decor.is_gibraltar() else 0xF00
    RX_SVI_GID_LOCAL = 60
    RX_SVI_MAC_LOCAL = T.mac_addr('11:12:13:78:9a:bc')

    def choose_slices_better(self):
        # MATILDA_SAVE -- need review
        # done at super(): self.IN_SLOUT_SLICEICE=T.choose_active_slices(self.device, self.OUT_SLICE, [4,1], 1)
        self.IN_SLICE_1 = T.choose_active_slices(self.device, self.IN_SLICE_1, [3, 1, 5])
        self.INJECT_SLICE = T.choose_active_slices(self.device, self.INJECT_SLICE, [2, 4, 0])
        self.INJECT_SLICE_1 = T.choose_active_slices(self.device, self.INJECT_SLICE_1, [0, 2, 4])
        if self.IN_SLICE_1 == self.INJECT_SLICE:
            self.IN_IFG = 1

    def setUp(self):
        super().setUp()

        self.create_bcast_snoop_packets()
        self.set_flood_destination(is_ucast=False)
        self.install_an_entry_in_copc_mac_table(self.ARP_ETHER_TYPE, 0xffff, T.mac_addr(
            self.BCAST_MAC), sdk.LA_EVENT_ETHERNET_ARP, T.mac_addr('ff:ff:ff:ff:ff:ff'), 0x1)

    def create_bcast_snoop_packets(self):
        self.l2_packet_bcast = \
            Ether(dst=self.BCAST_MAC, src=self.SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.VLAN)

        self.in_packet_bcast = self.l2_packet_bcast / IP() / TCP()
        self.out_packet_bcast = self.in_packet_bcast
        self.arp_packet_bcast = self.l2_packet_bcast / ARP(op='who-has')
        self.snoop_hdr = Ether(dst=self.HOST_MAC_ADDR,
                               src=self.PUNT_INJECT_PORT_MAC_ADDR_1,
                               type=Ethertype.Dot1Q.value) / Dot1Q(prio=0,
                                                                   id=0,
                                                                   vlan=self.MIRROR_VLAN,
                                                                   type=Ethertype.Punt.value) / Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                     fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                     next_header_offset=0,
                                                                                                     source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                     code=self.MIRROR_CMD_INGRESS_GID,
                                                                                                     source_sp=self.IN_SP_GID,
                                                                                                     destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                     source_lp=self.AC_PORT_GID_BASE | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                                                                                                     destination_lp=0,
                                                                                                     relay_id=self.SWITCH_GID,
                                                                                                     lpts_flow_type=0)
        self.snoop_ip_packet_bcast = self.snoop_hdr / self.out_packet_bcast
        self.snoop_l2_packet_bcast = self.snoop_hdr / self.l2_packet_bcast
        self.snoop_arp_packet_bcast = self.snoop_hdr / self.arp_packet_bcast

        self.punt_hdr = Ether(dst=self.HOST_MAC_ADDR,
                              src=self.PUNT_INJECT_PORT_MAC_ADDR,
                              type=Ethertype.Dot1Q.value) / Dot1Q(prio=0,
                                                                  id=0,
                                                                  vlan=self.PUNT_VLAN,
                                                                  type=Ethertype.Punt.value) / Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                    fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                    next_header_offset=0,
                                                                                                    source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                                                                                                    code=sdk.LA_EVENT_ETHERNET_ARP,
                                                                                                    source_sp=self.IN_SP_GID,
                                                                                                    destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                    source_lp=self.AC_PORT_GID_BASE | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                                                                                                    # destination_lp=sdk.la_packet_types.LA_L2_LOGICAL_PORT_GID_INVALID,
                                                                                                    destination_lp=sdk.LA_EVENT_ETHERNET_ARP,
                                                                                                    relay_id=0,
                                                                                                    lpts_flow_type=0)

        self.punt_arp_packet_bcast = self.punt_hdr / self.arp_packet_bcast

    def create_topology(self):
        self.choose_slices_better()
        self.sw1 = T.switch(self, self.device, self.SWITCH_GID)
        self.ac_profile = T.ac_profile(self, self.device)

        self.eth_port1 = T.ethernet_port(
            self,
            self.device,
            self.IN_SLICE_1,
            self.IN_IFG,
            self.SYS_PORT_GID_BASE,
            self.IN_SERDES_FIRST,
            self.IN_SERDES_LAST)
        self.eth_port1.set_ac_profile(self.ac_profile)
        self.ac_port1 = T.l2_ac_port(
            self,
            self.device,
            self.AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port1,
            None,
            self.VLAN,
            0x0)

        self.eth_port2 = T.ethernet_port(
            self,
            self.device,
            self.OUT_SLICE,
            self.OUT_IFG,
            self.SYS_PORT_GID_BASE + 1,
            self.OUT_SERDES_FIRST,
            self.OUT_SERDES_LAST)
        self.eth_port2.set_ac_profile(self.ac_profile)
        self.ac_port2 = T.l2_ac_port(
            self,
            self.device,
            self.AC_PORT_GID_BASE + 1,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port2,
            None,
            self.VLAN,
            0x0)

        self.vrf = T.vrf(self, self.device, self.VRF_GID_LOCAL)
        self.rx_svi = T.svi_port(
            self,
            self.device,
            self.RX_SVI_GID_LOCAL,
            self.sw1,
            self.vrf,
            self.RX_SVI_MAC_LOCAL)

        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            self.PUNT_INJECT_PORT_MAC_ADDR)

        self.pi_port_1 = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE_1,
            self.INJECT_IFG,
            self.INJECT_SP_GID_1,
            self.INJECT_PIF_FIRST,
            self.PUNT_INJECT_PORT_MAC_ADDR_1)

        self.punt_dest = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            self.pi_port,
            self.HOST_MAC_ADDR,
            self.PUNT_VLAN)

        self.mirror_cmd = T.create_l2_mirror_command(
            self.device,
            self.MIRROR_CMD_INGRESS_GID,
            self.pi_port_1,
            self.HOST_MAC_ADDR, self.MIRROR_VLAN)

    def _test_l2_switch_ip_bcast_snoop(self):
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT)
        ingress_packet = {
            'data': self.in_packet_bcast,
            'slice': self.IN_SLICE_1,
            'ifg': self.IN_IFG,
            'pif': self.IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({
            'data': self.out_packet_bcast,
            'slice': self.OUT_SLICE,
            'ifg': self.OUT_IFG,
            'pif': self.OUT_SERDES_FIRST})  # PIF of local system port
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        self.device.set_snoop_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT, 0, False, False, self.mirror_cmd)

        expected_packets = []
        expected_packets.append({
            'data': self.out_packet_bcast,
            'slice': self.OUT_SLICE,
            'ifg': self.OUT_IFG,
            'pif': self.OUT_SERDES_FIRST})
        expected_packets.append({
            'data': self.snoop_ip_packet_bcast,
            'slice': self.INJECT_SLICE_1,
            'ifg': self.INJECT_IFG,
            'pif': self.INJECT_PIF_FIRST})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def _test_l2_switch_arp_bcast_snoop(self):
        self.eth_port1.hld_obj.set_copc_profile(0x0)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP)
        self.device.set_snoop_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT, 0, False, False, self.mirror_cmd)

        ingress_packet = {
            'data': self.arp_packet_bcast,
            'slice': self.IN_SLICE_1,
            'ifg': self.IN_IFG,
            'pif': self.IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({
            'data': self.arp_packet_bcast,
            'slice': self.OUT_SLICE,
            'ifg': self.OUT_IFG,
            'pif': self.OUT_SERDES_FIRST})
        expected_packets.append({
            'data': self.snoop_arp_packet_bcast,
            'slice': self.INJECT_SLICE_1,
            'ifg': self.INJECT_IFG,
            'pif': self.INJECT_PIF_FIRST})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        self.device.clear_snoop_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT)
        self.eth_port1.hld_obj.set_copc_profile(0x1)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP, 0, None, self.punt_dest, False, False, True, 0)

        run_and_compare(self, self.device,
                        self.arp_packet_bcast, self.IN_SLICE_1, self.IN_IFG, self.IN_SERDES_FIRST,
                        self.punt_arp_packet_bcast, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)

        self.eth_port1.hld_obj.set_copc_profile(0x1)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP)
        self.device.set_snoop_configuration(sdk.LA_EVENT_ETHERNET_ARP, 0, False, False, self.mirror_cmd)
        self.device.set_snoop_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT, 0, False, False, self.mirror_cmd)

        expected_packets = []
        expected_packets.append({
            'data': self.arp_packet_bcast,
            'slice': self.OUT_SLICE,
            'ifg': self.OUT_IFG,
            'pif': self.OUT_SERDES_FIRST})
        expected_packets.append({
            'data': self.snoop_arp_packet_bcast,
            'slice': self.INJECT_SLICE_1,
            'ifg': self.INJECT_IFG,
            'pif': self.INJECT_PIF_FIRST})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        self.device.clear_snoop_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT)
        self.device.clear_snoop_configuration(sdk.LA_EVENT_ETHERNET_ARP)

        self.eth_port1.hld_obj.set_copc_profile(0x1)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP, 0, None, self.punt_dest, False, False, True, 0)
        self.device.set_snoop_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT, 0, False, False, self.mirror_cmd)
        snoop_packet = self.snoop_arp_packet_bcast
        snoop_packet[Punt].fwd_header_type = sdk.la_packet_types.LA_HEADER_TYPE_REDIRECT

        # snoop_packet[Punt].destination_lp = sdk.la_packet_types.LA_L2_LOGICAL_PORT_GID_INVALID
        # instead of an invalid DLP, destination_lp carries the original redirect_code.  Snoop
        # packet now has visibility into what caused the redirect
        #
        snoop_packet[Punt].destination_lp = sdk.LA_EVENT_ETHERNET_ARP
        snoop_packet[Punt].relay_id = 0

        expected_packets = []
        expected_packets.append({
            'data': self.punt_arp_packet_bcast,
            'slice': self.INJECT_SLICE,
            'ifg': self.INJECT_IFG,
            'pif': self.INJECT_PIF_FIRST})
        expected_packets.append({
            'data': self.snoop_arp_packet_bcast,
            'slice': self.INJECT_SLICE_1,
            'ifg': self.INJECT_IFG,
            'pif': self.INJECT_PIF_FIRST})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def _test_l2_switch_l2_bcast_snoop(self):
        self.device.set_snoop_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT, 0, False, False, self.mirror_cmd)

        self.l2_packet_bcast, payload_len = enlarge_packet_to_min_length(self.l2_packet_bcast)
        ingress_packet = {
            'data': self.l2_packet_bcast,
            'slice': self.IN_SLICE_1,
            'ifg': self.IN_IFG,
            'pif': self.IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({
            'data': self.l2_packet_bcast,
            'slice': self.OUT_SLICE,
            'ifg': self.OUT_IFG,
            'pif': self.OUT_SERDES_FIRST})
        self.snoop_l2_packet_bcast = add_payload(self.snoop_l2_packet_bcast, payload_len)
        expected_packets.append({
            'data': self.snoop_l2_packet_bcast,
            'slice': self.INJECT_SLICE_1,
            'ifg': self.INJECT_IFG,
            'pif': self.INJECT_PIF_FIRST})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # Teardown
        self.clear_entries_from_copc_mac_table()
        self.device.clear_snoop_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_l2_switch_bcast_snoop(self):
        self._test_l2_switch_ip_bcast_snoop()
        self._test_l2_switch_arp_bcast_snoop()
        self._test_l2_switch_l2_bcast_snoop()


if __name__ == '__main__':
    unittest.main()
