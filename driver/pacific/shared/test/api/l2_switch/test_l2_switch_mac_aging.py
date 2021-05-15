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
from l2_switch_mac_learn_base import l2_switch_mac_learn_base
import unittest
from leaba import sdk
import topology as T
import time
import sim_utils
import nplapicli


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipUnless(decor.is_hw_device(), "Requires HW device")
class l2_switch_mac_aging_test(l2_switch_mac_learn_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_switch_mac_aging(self):
        self.age_interval = 1
        self.age_checks = 5
        self.MAX_LR_PER_PACKET = 11

        # Install dynamic MAC entries with age_owner set to 0 and 1 for verifying age notification behavior
        dynamic_owned_mac_addr = "00:06:06:06:06:06"
        dynamic_owned_mac = T.mac_addr(dynamic_owned_mac_addr)

        dynamic_mac_addr = "00:07:07:07:07:07"
        dynamic_mac = T.mac_addr(dynamic_mac_addr)

        self.sw1.hld_obj.set_mac_entry(dynamic_owned_mac.hld_obj, self.ac_port1.hld_obj, 1, True)
        self.sw1.hld_obj.set_mac_entry(dynamic_mac.hld_obj, self.ac_port2.hld_obj, 1, False)

        in_packets, exp_packets = self.create_learn_notification_packets([self.src_mac.addr_str], self.dest_mac.addr_str)
        run_with_system_learn_and_compare_list(self, self.device, in_packets[0], exp_packets)

        # Enable MAC aging
        self.device.set_mac_aging_interval(self.age_interval)

        self.sleep_time = (self.age_checks * self.age_interval) + 2
        time.sleep(self.sleep_time)

        exp_packets = self.create_age_notification_packets(dynamic_owned_mac)
        step_and_compare(self, self.device, exp_packets)

        # Age notificaiton received, now check age info
        age_info = self.sw1.hld_obj.get_mac_entry(dynamic_owned_mac.hld_obj)
        self.assertEqual(age_info[1].age_value, self.age_checks * self.age_interval)
        self.assertEqual(age_info[1].age_remaining, 0)

        # Verify age notification is sent again after one scan interval
        self.sleep_time = self.age_interval + 2
        time.sleep(self.sleep_time)
        step_and_compare(self, self.device, exp_packets)

        # Verify age_remaining is 0
        age_info = self.sw1.hld_obj.get_mac_entry(dynamic_owned_mac.hld_obj)
        self.assertEqual(age_info[1].age_value, self.age_checks * self.age_interval)
        self.assertEqual(age_info[1].age_remaining, 0)

        # Verify age_remaining is 0 for non-age-owner entry
        age_info = self.sw1.hld_obj.get_mac_entry(dynamic_mac.hld_obj)
        self.assertEqual(age_info[1].age_value, self.age_checks * self.age_interval)
        self.assertEqual(age_info[1].age_remaining, 0)


if __name__ == '__main__':
    unittest.main()
