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

import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import decor
import topology as T
import nplapicli as nplapi

from traps_base import *

DA_BCAST = T.mac_addr('ff:ff:ff:ff:ff:ff')
MIRROR_CMD_INGRESS_GID = 0x31


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_traps_misc(TrapsTest):
    ISIS_DAS = ['01:80:c2:00:00:14',
                '01:80:c2:00:00:15',
                '09:00:2b:00:00:04',
                '09:00:2b:00:00:05',
                '01:00:5e:90:00:02',
                '01:00:5e:90:00:03']

    def snoop_setup(self):
        sampling_rate = 1.0
        HOST_MAC_ADDR1 = T.mac_addr('cd:cd:cd:cd:cd:cd')
        mirror_cmd = T.create_l2_mirror_command(
            self.device,
            MIRROR_CMD_INGRESS_GID,
            self.pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN,
            sampling_rate)

        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x1)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT)
        self.device.set_snoop_configuration(sdk.LA_EVENT_ETHERNET_ARP, 0, False, False, mirror_cmd)
        self.install_an_entry_in_copc_mac_table(ARP_ETHER_TYPE, 0xffff, DA_BCAST, sdk.LA_EVENT_ETHERNET_ARP, DA_BCAST)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_arp_snoop(self):

        self.snoop_setup()

        INPUT_PACKET_WITH_VLAN_BASE = \
            S.Ether(dst=DA_BCAST.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.ARP(op='who-has')
        INPUT_PACKET_WITH_VLAN, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_VLAN_BASE)

        PUNT_PACKET_WITH_VLAN = S.Ether(dst=HOST_MAC_ADDR,
                                        src=PUNT_INJECT_PORT_MAC_ADDR,
                                        type=U.Ethertype.Dot1Q.value) / S.Dot1Q(prio=0,
                                                                                id=0,
                                                                                vlan=PUNT_VLAN,
                                                                                type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                                      fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                                      next_header_offset=0,
                                                                                                                      source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                                      code=MIRROR_CMD_INGRESS_GID,
                                                                                                                      source_sp=T.RX_SYS_PORT_GID,
                                                                                                                      destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                                      source_lp=T.RX_L2_AC_PORT_GID | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                                                                                                                      relay_id=T.RX_SWITCH_GID,
                                                                                                                      lpts_flow_type=0) / INPUT_PACKET_WITH_VLAN
        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 0
        ive.num_tags_to_pop = 1
        self.topology.rx_l2_ac_port.hld_obj.set_ingress_vlan_edit_command(ive)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_WITH_VLAN, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)


if __name__ == '__main__':
    unittest.main()
