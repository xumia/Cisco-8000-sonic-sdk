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
import decor
import ip_test_base
from packet_test_utils import *
from leaba import debug
from leaba import sdk
from l2_l3_conversion_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l2_to_l3_forwaring(l2_l3_conversion_base):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip in auto-WB sanity")
    def test_l2_to_l3_forwarding(self):
        # Create topology and packets for L3 Port
        self.create_l3_topology()
        # Run L3 test
        run_and_compare_list(self, self.device, self.l3_ingress_packet, self.l3_expected_packets)

        # disable L3 TX and RX port
        self.tx_l3_ac_port.hld_obj.disable()
        run_and_drop(self, self.device, self.l3_in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)
        self.rx_l3_ac_port.hld_obj.disable()
        run_and_drop(self, self.device, self.l3_in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        # Create topology and packets for L2 Port
        self.create_l2_topology()
        # Run L2 test
        run_and_compare_list(self, self.device, self.l2_ingress_packet, self.l2_expected_packets)

        # Remove L3 Port and related objcts
        self.vrf.hld_obj.delete_ipv4_route(self.prefix)
        self.device.destroy(self.nh_l3_ac.hld_obj)
        self.device.destroy(self.tx_l3_ac_port.hld_obj)
        self.device.destroy(self.rx_l3_ac_port.hld_obj)

        # Run L2 test again to make sure things are intact after removing L3 ports
        run_and_compare_list(self, self.device, self.l2_ingress_packet, self.l2_expected_packets)

        # De-link L2 port
        self.rx_l2_ac.hld_obj.disable()
        run_and_drop(self, self.device, self.l2_in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)
        self.tx_l2_ac.hld_obj.disable()
        run_and_drop(self, self.device, self.l2_in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)

        # Create topology and packets for L3 Port
        self.create_l3_topology()
        # Run L3 test
        run_and_compare_list(self, self.device, self.l3_ingress_packet, self.l3_expected_packets)

        # Remove L2 Port and related objcts
        self.device.destroy(self.rx_l2_ac.hld_obj)
        self.device.destroy(self.tx_l2_ac.hld_obj)
        # Run L3 test again to make sure things are intact after removing L2 Ports
        run_and_compare_list(self, self.device, self.l3_ingress_packet, self.l3_expected_packets)


if __name__ == '__main__':
    unittest.main()
