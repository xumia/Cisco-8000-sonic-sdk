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
from leaba import sdk
from snake_base import *
import decor
import warm_boot_test_utils as wb
from wb_sa_base import *
import time


@unittest.skip("Needs adjustments after merging WB with master")
@unittest.skipUnless(decor.is_hw_device(), "Requires HW device")
@unittest.skipUnless(decor.is_gibraltar(), "WB is only suppored for gibraltar")
class test_wb_sa(test_wb_sa_base):
    def test_wb_sa_port_state(self):
        '''
        verify port state machnine moves from active to tuned after warmboot
        '''
        print("checking port port state machine")
        self.setup_ports()
        device = self.snake.device
        mac_ports = self.snake.mph.mac_ports
        for i in range(len(mac_ports)):
            mac_ports[i].stop()
        for i in range(len(mac_ports)):
            mac_ports[i].set_link_management_enabled(False)
        for i in range(len(mac_ports)):
            mac_ports[i].activate()
        time.sleep(1)
        for i in range(len(mac_ports)):
            self.assertEqual(mac_ports[i].get_state(), sdk.la_mac_port.state_e_ACTIVE)
        wb.warm_boot(device)
        self.snake.mph.critical_fd, self.snake.mph.normal_fd = device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)
        mac_ports = device.get_objects(sdk.la_object.object_type_e_MAC_PORT)
        for i in range(len(mac_ports)):
            mac_ports[i].tune(True)
            self.assertEqual(mac_ports[i].get_state(), sdk.la_mac_port.state_e_TUNED)


if __name__ == '__main__':
    unittest.main()
