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
from scapy.all import *
from l2_switch_mac_learn_base import *
import unittest
from leaba import sdk
import topology as T
import nplapicli
import sim_utils


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l2_switch_mac_forwarding_test(l2_switch_mac_learn_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_switch_mac_learning_multi_lr(self):
        self.MAX_LR_PER_PACKET = 10

        # generate list of mac addresses
        num_mac_to_test = 22
        mac_list = self.generate_macs("de:ad:00", num_mac_to_test)

        ingress_packets, expected_packets = self.create_learn_notification_packets(mac_list, self.dest_mac.addr_str)

        print("Sending packets with different MAC...")
        egress_packets = run_with_system_learn(self, self.device, ingress_packets, expected_packets)
        print("Total packets sent: {num_packets}".format(num_packets=len(ingress_packets)))
        print("Total packets received: {num_packets}".format(num_packets=len(egress_packets)))
        print("Total packets expected: {num_packets}".format(num_packets=len(expected_packets)))

        self.compare_egress_packets(egress_packets, expected_packets)


if __name__ == '__main__':
    unittest.main()
