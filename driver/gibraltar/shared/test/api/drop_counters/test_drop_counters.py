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
from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import ip_test_base
import topology as T
import sim_utils
from sdk_test_case_base import *
from trap_counter_utils import *
import smart_slices_choise as ssch
PRIVATE_DATA_DEFAULT = 0xfedcba9876543210

SYS_PORT_GID_BASE = 23

IN_SLICE = T.get_device_slice(2)
IN_IFG = 0
IN_PIF_FIRST = T.get_device_first_serdes(4)
IN_PIF_LAST = IN_PIF_FIRST + 3
IN_SP_GID = SYS_PORT_GID_BASE
OUT_SLICE = T.get_device_slice(4)
OUT_IFG = T.get_device_ifg(1)
OUT_PIF_FIRST = T.get_device_next_first_serdes(9)
OUT_PIF_LAST = OUT_PIF_FIRST + 3
OUT_SP_GID = SYS_PORT_GID_BASE + 1

AC_PORT_GID_BASE = 10

SWITCH_GID = 100

DST_MAC = T.mac_addr('ca:fe:ca:fe:ca:fe')
SRC_MAC = T.mac_addr('de:ad:de:ad:de:ad')
DST_MAC1 = T.mac_addr('ca:fe:ca:fe:ca:ef')
SRC_MAC1 = T.mac_addr('de:ad:de:ad:de:da')
VLAN = 0xAB9

HOST_MAC_ADDR = "ba:be:ca:fe:ba:be"


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_drop_counters(sdk_test_case_base):

    PRIVATE_DATA = 0x1234567890abcdef
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    DIP_NULL = T.ipv4_addr('39.39.39.39')
    SIP1 = T.ipv4_addr('12.11.12.10')
    DIP1 = T.ipv4_addr('82.82.95.250')
    TTL = 128
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    def setUp(self):
        super().setUp()

        self.add_default_route()
        self.create_packets()

    def create_packets(self):
        in_packet_base = Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        out_packet_base = Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        self.in_packet, self.out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

    def add_default_route(self):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = 0x0
        prefix.length = 0
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.topology.nh_l3_ac_def.hld_obj, PRIVATE_DATA_DEFAULT, False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_traps_ethernet(self):
        input_packet_base = \
            Ether(dst=self.SA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.TTL)
        input_packet, __ = enlarge_packet_to_min_length(input_packet_base)

        # Setup counter and trap
        counter = self.device.create_counter(1)

        priority = 0
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR, priority, counter, None, False, False, True, 0)

        # run the packet
        run_and_drop(self, self.device, input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        packets, bytes = counter.read(0,  # sub-counter index
                                      True,  # force_update
                                      True)  # clear_on_read
        self.assertEqual(packets, 1)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_hw_device(), "Test not supported when punt_egress_packets to host enabled")
    def test_traps_ethernet_pif(self):
        input_packet_base = \
            Ether(dst=self.SA.addr_str, src=self.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.TTL)
        input_packet, __ = enlarge_packet_to_min_length(input_packet_base)

        # Setup counter and trap
        counter_set_size = self.device.get_limit(sdk.limit_type_e_COUNTER_SET__MAX_PIF_COUNTER_OFFSET)
        counter = self.device.create_counter(counter_set_size)

        priority = 0
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR, priority, counter, None, False, False, True, 0)

        # run the packet
        run_and_drop(self, self.device, input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        run_and_drop(self, self.device, input_packet, T.RX_SLICE, T.RX_IFG1, T.FIRST_SERDES1)

        counts = get_trap_pif_packet_counts(self.device, sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)

        self.assertEqual(counts[0], 1)
        self.assertEqual(counts[2], 1)
        self.assertEqual(sum(counts), 2)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_traps_egress(self):
        input_packet_base = \
            Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.TTL)
        input_packet, __ = enlarge_packet_to_min_length(input_packet_base)

        self.topology.rx_switch.hld_obj.set_mac_entry(
            DST_MAC.hld_obj,
            self.topology.tx_l2_ac_port_reg.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        self.topology.tx_l2_ac_port_reg.hld_obj.set_stp_state(sdk.la_port_stp_state_e_BLOCKING)

        # Create counter
        counter = self.device.create_counter(1)

        # Setup punt and trap
        priority = 0
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_EGRESS_STP_BLOCK, priority, counter, None, False, False, True, 0)

        # test
        run_and_drop(self, self.device, input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # test counter
        packets, bytes = counter.read(0,  # sub-counter index
                                      True,  # force_update
                                      True)  # clear_on_read
        self.assertEqual(packets, 1)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device")
    def test_traps_egress_pif(self):
        input_packet_base = \
            Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.TTL)
        input_packet, __ = enlarge_packet_to_min_length(input_packet_base)

        self.topology.rx_switch.hld_obj.set_mac_entry(
            DST_MAC.hld_obj,
            self.topology.tx_l2_ac_port_reg.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        self.topology.tx_l2_ac_port_reg.hld_obj.set_stp_state(sdk.la_port_stp_state_e_BLOCKING)

        # Create counter
        counter_set_size = self.device.get_limit(sdk.limit_type_e_COUNTER_SET__MAX_PIF_COUNTER_OFFSET)
        counter = self.device.create_counter(counter_set_size)

        # Setup punt and trap
        priority = 0
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_EGRESS_STP_BLOCK, priority, counter, None, False, False, True, 0)

        # test
        run_and_drop(self, self.device, input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        counts = get_trap_pif_packet_counts(self.device, sdk.LA_EVENT_ETHERNET_EGRESS_STP_BLOCK)

        self.assertEqual(counts[0], 1)
        self.assertEqual(sum(counts), 1)


if __name__ == '__main__':
    unittest.main()
