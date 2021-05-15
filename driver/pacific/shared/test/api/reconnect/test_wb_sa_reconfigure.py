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


@unittest.skip("Needs adjustments after merging WB with master")
@unittest.skipUnless(decor.is_hw_device(), "Requires HW device")
@unittest.skipUnless(decor.is_gibraltar(), "WB is only suppored for gibraltar")
@unittest.skipIf(decor.is_matilda("3.2"), "GB 3.2 Does not support mac_port->reconfigure() functionality")
class test_wb_sa(test_wb_sa_base):
    def test_wb_sa_reconfigure(self):
        '''
         reconfigure port to 50G from 100G and make sure ports come up after warmboot
        '''
        print("checking port reconfiguration")
        self.setup_ports()
        device = self.snake.device
        wb.warm_boot(device)
        self.snake.mph.critical_fd, self.snake.mph.normal_fd = device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)
        # reconfigure loopback mac ports
        mac_ports = device.get_objects(sdk.la_object.object_type_e_MAC_PORT)
        for i in range(1, len(mac_ports)):
            mac_ports[i].stop()
            mac_ports[i].reconfigure(2, sdk.la_mac_port.port_speed_e_E_50G, False, False, sdk.la_mac_port.fec_mode_e_RS_KP4)
        self.snake.mph.wait_mac_ports_down(timeout=DWELL_UP_TIME)
        for i in range(1, len(mac_ports)):
            mac_ports[i].activate()
        self.snake.mph.wait_mac_ports_up(timeout=DWELL_UP_TIME)
        for i in range(1, len(mac_ports)):
            self.assertEqual(mac_ports[i].get_speed(), sdk.la_mac_port.port_speed_e_E_50G)


if __name__ == '__main__':
    unittest.main()
