#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import pdb
from pfc_base import *
import unittest
import decor
from pfc_local import *


@unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
class pfc_rx(pfc_local, pfc_base, pfc_common):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pfc(self):
        self.init_common()

        # Send a PFC packet on an enabled interface and check the counter.
        mac_port = self.m_mac_port.hld_obj
        run_and_drop(
            self,
            self.device,
            self.pfc_packet,
            mac_port.get_slice(),
            mac_port.get_ifg(),
            mac_port.get_first_serdes_id())

        packets, bytes = self.pfc_rx_counter.read(TC_VALUE, True, True)
        self.assertEqual(packets, 1)

        # Send an invalid PFC packet and check the trap.
        PUNT_HDR = \
            Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                 next_header_offset=0,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_NPUH,
                 code=sdk.LA_EVENT_OAMP_PFC_LOOKUP_FAILED,
                 source_sp=self.m_sys_port.hld_obj.get_gid(),
                 destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 source_lp=self.s_l3_ac_gid_phy, destination_lp=sdk.LA_EVENT_ETHERNET_L2CP0,
                 relay_id=0, lpts_flow_type=0)

        pfc_invalid = self.pfc_packet
        pfc_invalid.class_enable_vector = 0
        PUNT_HDR.code = sdk.LA_EVENT_OAMP_PFC_DROP_INVALID_RX
        PUNT_PACKET_PFC_INVALID = PUNT_HDR / pfc_invalid
        run_and_compare(
            self,
            self.device,
            pfc_invalid,
            mac_port.get_slice(),
            mac_port.get_ifg(),
            mac_port.get_first_serdes_id(),
            PUNT_PACKET_PFC_INVALID,
            self.PI_SLICE,
            self.PI_IFG,
            self.PI_PIF_FIRST)

        (p, c_or_m, d, skip_inject_up_packets, skip_p2p_packets,
         overwrite_phb, tc) = self.device.get_trap_configuration(sdk.LA_EVENT_OAMP_PFC_DROP_INVALID_RX)
        counter = c_or_m.downcast()
        packets, bytes = counter.read(0, True, True)
        self.assertEqual(packets, 1)

        # Verify that we just drop the packet when the trap is cleared.
        self.device.clear_trap_configuration(sdk.LA_EVENT_OAMP_PFC_DROP_INVALID_RX)
        run_and_drop(
            self,
            self.device,
            pfc_invalid,
            mac_port.get_slice(),
            mac_port.get_ifg(),
            mac_port.get_first_serdes_id())

        # Reenable the trap
        self.device.set_trap_configuration(sdk.LA_EVENT_OAMP_PFC_DROP_INVALID_RX, p, c_or_m,
                                           d, skip_inject_up_packets, skip_p2p_packets, overwrite_phb, tc)

        # Disable PFC on the interface and send a PFC packet and count the trap.
        PUNT_HDR.code = sdk.LA_EVENT_OAMP_PFC_LOOKUP_FAILED
        PUNT_PACKET_PFC_LOOKUP_FAILED = PUNT_HDR / self.pfc_packet

        mac_port.set_pfc_disable()
        run_and_compare(
            self,
            self.device,
            self.pfc_packet,
            mac_port.get_slice(),
            mac_port.get_ifg(),
            mac_port.get_first_serdes_id(),
            PUNT_PACKET_PFC_LOOKUP_FAILED,
            self.PI_SLICE,
            self.PI_IFG,
            self.PI_PIF_FIRST)

        (p, c_or_m, d, skip_inject_up_packets, skip_p2p_packets, overwrite_phb,
         tc) = self.device.get_trap_configuration(sdk.LA_EVENT_OAMP_PFC_LOOKUP_FAILED)
        counter = c_or_m.downcast()
        packets, bytes = counter.read(0, True, True)
        self.assertEqual(packets, 1)


if __name__ == '__main__':
    unittest.main()
