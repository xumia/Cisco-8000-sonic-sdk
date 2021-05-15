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

import unittest
from packet_test_utils import *
from scapy.all import *
from leaba import debug
import decor
from l2_l3_conversion_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l3_to_l2_forwarding(l2_l3_conversion_base):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip in auto-WB sanity")
    def test_l3_to_l2_forwaridng(self):
        self.create_l2_packets()
        l3_ac_port1 = T.l3_ac_port(self,
                                   self.device,
                                   L3_AC_PORT_GID,
                                   self.eth_port,
                                   self.vrf,
                                   L3_AC_PORT_MAC_ADDR,
                                   VID1,
                                   0)
        l3_ac_port1.hld_obj.disable()

        self.rx_l2_ac = T.l2_ac_port(self, self.device, L2_AC_PORT_GID,
                                     self.topology.filter_group_def,
                                     None,
                                     self.eth_port,
                                     None,
                                     VID1,
                                     0)
        self.tx_l2_ac = T.l2_ac_port(self, self.device, L2_AC_PORT_GID + 1,
                                     self.topology.filter_group_def,
                                     None,
                                     self.eth_port1,
                                     None,
                                     VID1,
                                     0)

        self.rx_l2_ac.hld_obj.set_destination(self.tx_l2_ac.hld_obj)
        run_and_compare_list(self, self.device, self.l2_ingress_packet, self.l2_expected_packets)
        self.device.destroy(l3_ac_port1.hld_obj)
        self.rx_l2_ac.hld_obj.set_destination(None)
        self.device.destroy(self.rx_l2_ac.hld_obj)
        self.device.destroy(self.tx_l2_ac.hld_obj)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip in auto-WB sanity")
    def test_l3_to_l2_forwaridng_1(self):
        rx_l3_ac_port = T.l3_ac_port(self,
                                     self.device,
                                     L3_AC_PORT_GID,
                                     self.eth_port,
                                     self.vrf,
                                     L3_AC_PORT_MAC_ADDR,
                                     VID1,
                                     0)

        tx_l3_ac_port = T.l3_ac_port(self,
                                     self.device,
                                     L3_AC_PORT_GID + 1,
                                     self.eth_port1,
                                     self.vrf,
                                     L3_AC_PORT_MAC_ADDR2,
                                     VID1,
                                     0)

        rx_l3_ac_port.hld_obj.disable()
        tx_l3_ac_port.hld_obj.disable()

        self.create_l2_topology()
        run_and_compare_list(self, self.device, self.l2_ingress_packet, self.l2_expected_packets)
        self.device.destroy(rx_l3_ac_port.hld_obj)
        self.device.destroy(tx_l3_ac_port.hld_obj)
        run_and_compare_list(self, self.device, self.l2_ingress_packet, self.l2_expected_packets)

        self.device.destroy(self.rx_l2_ac.hld_obj)
        self.device.destroy(self.tx_l2_ac.hld_obj)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip in auto-WB sanity")
    def test_l3_to_l2_forwaridng_mc(self):
        l3_ac_port1 = T.l3_ac_port(self,
                                   self.device,
                                   L3_AC_PORT_GID,
                                   self.eth_port,
                                   self.vrf,
                                   L3_AC_PORT_MAC_ADDR,
                                   VID1,
                                   0)
        l3_ac_port1.hld_obj.disable()

        self.create_l2_topology(mc=True)
        self.mc_group = self.device.create_l2_multicast_group(MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        mc_dest_mac = T.mac_addr(DST_MAC)
        self.sw1.hld_obj.set_mac_entry(mc_dest_mac.hld_obj, self.mc_group, sdk.LA_MAC_AGING_TIME_NEVER)

        self.mc_group.add(self.tx_l2_ac.hld_obj, self.eth_port1.hld_obj.get_system_port())
        self.mc_group.add(self.tx_l2_ac_1.hld_obj, self.eth_port2.hld_obj.get_system_port())

        run_and_compare_list(self, self.device, self.l2_ingress_packet, self.expected_packets1)

        self.device.destroy(l3_ac_port1.hld_obj)

        run_and_compare_list(self, self.device, self.l2_ingress_packet, self.expected_packets1)


if __name__ == '__main__':
    unittest.main()
