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
import sim_utils
import topology as T
import decor

from traps.traps_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class traps_arp_test_is_at_bc_dmac_cscvq17411(TrapsTest):

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_arp_is_at_with_bc_dmac(self):
        ''' Traps TCAM management had an issue where traps at the HLD and NPLAPI layers would go out of sync. This happened when clearing.
            After loss of sync, inserting an inferior trap would place it before a superior one.
        '''

        BCAST_MAC = 'ff:ff:ff:ff:ff:ff'

        INPUT_PACKET_WITH_VLAN_BASE = \
            S.Ether(dst=BCAST_MAC, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_ONE_TAG_PORT_VID) / \
            S.ARP(op='is-at')
        INPUT_PACKET_WITH_VLAN, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_VLAN_BASE)

        # Packet punted with ARP trapping enabled
        npp_attribute = 0x1
        self.topology.rx_eth_port.hld_obj.set_copc_profile(npp_attribute)
        prof_val = self.topology.rx_eth_port.hld_obj.get_copc_profile()
        self.assertEqual(prof_val, npp_attribute)
        self.install_an_entry_in_copc_mac_table(
            ARP_ETHER_TYPE,
            0xffff,
            T.mac_addr(DONT_CARE_MAC),
            sdk.LA_EVENT_ETHERNET_ARP,
            T.mac_addr(DONT_CARE_MAC),
            npp_attribute)

        # Clear all traps to recreate the expected buggy scenario.
        for trap in range(sdk.LA_EVENT_ETHERNET_FIRST, sdk.LA_EVENT_APP_LAST + 1):
            try:
                self.device.clear_trap_configuration(trap)
            except BaseException:
                pass

        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_MULTICAST, 1, None, None, False, False, True, 0)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR, 1, None, None, False, False, True, 0)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP, 1, None, self.punt_dest, False, False, True, 0)

        # Clear a superior trap
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)

        # Insert an inferior trap
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT, 2, None, None, False, False, True, 0)

        # Verify that the packet is still caught on LA_EVENT_ETHERNET_ARP
        PUNT_PACKET = \
            S.Ether(dst=HOST_MAC_ADDR,
                    src=PUNT_INJECT_PORT_MAC_ADDR,
                    type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0,
                    id=0,
                    vlan=PUNT_VLAN,
                    type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_ARP,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_L3_AC_ONE_TAG_GID,
                   # destination_lp=sdk.la_packet_types.LA_L3_LOGICAL_PORT_GID_INVALID,
                   destination_lp=sdk.LA_EVENT_ETHERNET_ARP,
                   relay_id=self.PUNT_RELAY_ID,
                   lpts_flow_type=0) / \
            INPUT_PACKET_WITH_VLAN

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        # Teardown
        self.clear_entries_from_copc_mac_table()
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_MULTICAST)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT)


if __name__ == '__main__':
    unittest.main()
