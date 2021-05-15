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
from scapy.all import *
from leaba import sdk
import topology as T
import warm_boot_upgrade_rollback_test_utils as wb
from sdk_test_case_base import *


OUT_SLICE = T.get_device_slice(5)
OUT_IFG = T.get_device_ifg(1)
OUT_SERDES_FIRST = T.get_device_first_serdes(8)
OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

SYS_PORT_GID = 23
AC_PORT_GID = 10

DST_MAC = T.mac_addr("ca:fe:ca:fe:ca:fe")
SRC_MAC = T.mac_addr("de:ad:de:ad:de:ad")
VLAN = 0xAB9


class warm_boot_upgrade_rollback_l2_switch_base(sdk_test_case_base):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        global OUT_SLICE
        OUT_SLICE = T.choose_active_slices(cls.device, OUT_SLICE, [5, 2])

    def setUp(self):
        super().setUp()
        self.add_topology()
        self.create_packets()

    def add_topology(self):
        self.switch = self.topology.rx_switch
        self.ac_port1 = self.topology.rx_l2_ac_port

        self.eth_port2 = T.ethernet_port(
            self,
            self.device,
            OUT_SLICE,
            OUT_IFG,
            SYS_PORT_GID,
            OUT_SERDES_FIRST,
            OUT_SERDES_LAST)
        self.ac_port2 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID,
            self.topology.filter_group_def,
            self.switch,
            self.eth_port2,
            None,
            T.RX_L2_AC_PORT_VID1,
            T.RX_L2_AC_PORT_VID2)

    def create_packets(self):
        in_packet_base = Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L2_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L2_AC_PORT_VID2) / \
            IP() / TCP()

        out_packet_base = Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L2_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L2_AC_PORT_VID2) / \
            IP() / TCP()
        self.in_packet, self.out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

    def _test_warm_boot_l2_switch(self, change_config_after_wb):
        # Pass packet from port 1 to port 2
        self.switch.hld_obj.set_mac_entry(DST_MAC.hld_obj, self.ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        wb.warm_boot(self.device)

        if change_config_after_wb:
            # Pass packet from port 1 to itself by overwriting the existing MAC entry
            self.switch.hld_obj.set_mac_entry(DST_MAC.hld_obj, self.ac_port1.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
            self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SAME_INTERFACE)

            out_slice = T.RX_SLICE
            out_ifg = T.RX_IFG
            out_serdes = T.FIRST_SERDES
        else:
            out_slice = OUT_SLICE
            out_ifg = OUT_IFG
            out_serdes = OUT_SERDES_FIRST

        run_and_compare(
            self,
            self.device,
            self.in_packet,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.out_packet,
            out_slice,
            out_ifg,
            out_serdes)
