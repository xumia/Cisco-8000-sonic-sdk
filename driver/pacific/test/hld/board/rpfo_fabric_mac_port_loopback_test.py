#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import time
import unittest
from leaba import sdk
import common_mac_port_board_test_base as base


class rpfo_fabric_mac_port_loopback(base.common_mac_port_board_test_base):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_case(self):
        self.device_create()
        self.device.reconnect()
        self.update_mac_ports_from_device()
        self.update_fabric_ports_from_device()
        print('Restored: mac ports {}, fabric ports {}'.format(len(self.common_mac_ports), len(self.common_fabric_ports)))
        self.print_mac_up()
        time.sleep(5)
        print('Mac ports after wait')
        self.print_mac_up()
        print('done')

    def device_create(self):
        # Do not use sim_utils.create_device(), because:
        #    a) It relies on SDK_DEVICE_NAME env var
        #    b) hw_device is initialized, no way to skip init
        #    c) hw_device sets TES_MODE_PUNT_EGRESS_PACKETS_TO_HOST bool property, which we do not need here.
        #
        # In short, we want to directly the "create" then "reconnect" flow.
        # Using sim_utils would inject unwanted things into flow.

        self.device_id = 0
        self.device_name = '/dev/uio0'
        self.device = sdk.la_create_device(self.device_name, self.device_id)
        self.ll_device = self.device.get_ll_device()
        self.pacific_tree = self.ll_device.get_pacific_tree()


if __name__ == '__main__':
    unittest.main()
