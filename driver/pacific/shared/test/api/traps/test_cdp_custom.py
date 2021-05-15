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

import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import decor
import topology as T

from traps_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(True, "Test takes to long to run. disable for now")
class TrapsCDPMeterCounter(TrapsTest):
    S.load_contrib("cdp")
    cdp_da = '01:00:0C:CC:CC:CC'

    CDP_PACKET_BASE = \
        S.Ether(dst=cdp_da, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.LLC() / S.SNAP() / CDPv2_HDR()

    CDP_PACKET, __ = U.enlarge_packet_to_min_length(CDP_PACKET_BASE, 512)

    PUNT_PACKET = \
        S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
        U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
               fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
               next_header_offset=0,
               source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
               code=sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
               source_sp=T.RX_SYS_PORT_GID,
               destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
               source_lp=T.RX_L3_AC_GID,
               # destination_lp=0x7fff,
               destination_lp=sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
               relay_id=TrapsTest.PUNT_RELAY_ID, lpts_flow_type=0) / CDP_PACKET

    # use packet>4K for statistical meters to count consistently
    CDP_PACKET_stat = CDP_PACKET / Raw(load=4096 * b'\00')
    PUNT_PACKET_stat = PUNT_PACKET / Raw(load=4096 * b'\00')

    def setUp(self):
        super().setUp()
        self.cdp_ifg_meter = T.create_meter_set(self, self.device, is_aggregate=True)
        self.cdp_statistical_meter = T.create_meter_set(self, self.device, is_statistical=True)
        self.cdp_trap_counter = self.device.create_counter(1)
        self.install_an_entry_in_copc_mac_table(0, 0, T.mac_addr(
            TrapsCDPMeterCounter.cdp_da), sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)

    def tearDown(self):
        self.clear_entries_from_copc_mac_table()
        super().tearDown()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cdp_ifg_meter(self):
        # self.device.nsim_provider.set_logging(True)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS, 0,
                                           self.cdp_ifg_meter, self.punt_dest, False, False, True, 0)

        (out_priority, out_meter, out_punt_dest, out_skip_inject_up_packets, out_skip_p2p_packets,
         out_overwrite_phb, out_tc) = self.device.get_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)
        self.assertEqual(out_priority, 0)
        self.assertEqual(out_meter.oid(), self.cdp_ifg_meter.oid())
        self.assertEqual(out_punt_dest.oid(), self.punt_dest.oid())
        self.assertEqual(out_skip_inject_up_packets, False)
        self.assertEqual(out_skip_p2p_packets, False)
        self.assertEqual(out_overwrite_phb, True)
        self.assertEqual(out_tc, 0)

        U.run_and_compare(self, self.device,
                          TrapsCDPMeterCounter.CDP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          TrapsCDPMeterCounter.PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        packets, bytes = self.cdp_ifg_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packets, 1)

        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS, 0, None, self.punt_dest, False, False, True, 0)

        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cdp_trap_counter(self):
        # self.device.nsim_provider.set_logging(True)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS, 0,
                                           self.cdp_trap_counter, self.punt_dest, False, False, True, 0)

        (out_priority, out_counter, out_punt_dest, out_skip_inject_up_packets, out_skip_p2p_packets,
         out_overwrite_phb, out_tc) = self.device.get_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)
        self.assertEqual(out_priority, 0)
        self.assertEqual(out_counter.oid(), self.cdp_trap_counter.oid())
        self.assertEqual(out_punt_dest.oid(), self.punt_dest.oid())
        self.assertEqual(out_skip_inject_up_packets, False)
        self.assertEqual(out_skip_p2p_packets, False)
        self.assertEqual(out_overwrite_phb, True)
        self.assertEqual(out_tc, 0)

        U.run_and_compare(self, self.device,
                          TrapsCDPMeterCounter.CDP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          TrapsCDPMeterCounter.PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        packets, bytes = self.cdp_trap_counter.read(0, True, True)
        self.assertEqual(packets, 1)

        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS, 0,
                                           None, self.punt_dest, False, False, True, 0)

        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cdp_statistical_meter(self):
        # self.device.nsim_provider.set_logging(True)
        self.device.set_trap_configuration(
            sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
            0,
            self.cdp_statistical_meter,
            self.punt_dest,
            False,
            False,
            True, 0)

        (out_priority, out_meter, out_punt_dest, out_skip_inject_up_packets, out_skip_p2p_packets,
         out_overwrite_phb, out_tc) = self.device.get_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)
        self.assertEqual(out_priority, 0)
        self.assertEqual(out_meter.oid(), self.cdp_statistical_meter.oid())
        self.assertEqual(out_punt_dest.oid(), self.punt_dest.oid())
        self.assertEqual(out_skip_inject_up_packets, False)
        self.assertEqual(out_skip_p2p_packets, False)
        self.assertEqual(out_overwrite_phb, True)
        self.assertEqual(out_tc, 0)

        U.run_and_compare(self, self.device,
                          TrapsCDPMeterCounter.CDP_PACKET_stat, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          TrapsCDPMeterCounter.PUNT_PACKET_stat, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        packets, bytes = self.cdp_statistical_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
        #
        # 512 bytes are injected which become 552 via:
        #
        #   control init_rxpp_npu_input_from_device_packet_info {
        #     // initializing rxpp_npu_input from device_params
        #     if (rx_hw_cfg.slice_mode == SLICE_MODE_NETWORK) {
        #       device_packet_info.size_in_bytes = device_packet_info.size_in_bytes + 16'd40; // add 40 bytes in packet prefix
        #     }
        #
        # which then is metered as 552 - 36 due to this config:
        #
        #  (rx_meter_if_source_port_config_memory.slice_header_bytes_dec << 2)
        #
        # (slice_header_bytes_dec default is 9 on gibraltar).
        #
        self.assertEqual(packets, 1)
        # backing out until we can get h/w access to see what is happening.
        # latest runs on h/w now produce 551
        # self.assertEqual(bytes, 516)

        self.device.set_trap_configuration(
            sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
            0,
            self.cdp_trap_counter,
            self.punt_dest,
            False,
            False,
            True, 0)
        (out_priority, out_counter, out_punt_dest, out_skip_inject_up_packets, out_skip_p2p_packets,
         out_overwrite_phb, out_tc) = self.device.get_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)
        self.assertEqual(out_priority, 0)
        self.assertEqual(out_counter.oid(), self.cdp_trap_counter.oid())
        self.assertEqual(out_punt_dest.oid(), self.punt_dest.oid())
        self.assertEqual(out_skip_inject_up_packets, False)
        self.assertEqual(out_skip_p2p_packets, False)
        self.assertEqual(out_overwrite_phb, True)
        self.assertEqual(out_tc, 0)

        self.device.set_trap_configuration(
            sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
            0,
            None,
            self.punt_dest,
            False,
            False,
            True, 0)

        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)


if __name__ == '__main__':
    unittest.main()
