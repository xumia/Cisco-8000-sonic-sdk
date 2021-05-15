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
from ports_base import *
import tempfile
import time
DWELL_TIME = 40


@unittest.skip("Skip until WB is merged to master and stabilized.")
@unittest.skipUnless(decor.is_hw_device(), "Requires HW device")
@unittest.skipUnless(decor.is_gibraltar(), "WB is only suppored for gibraltar")
class test_wb_sa_port_state_change(ports_base):
    loop_mode = 'serdes'
    p2p_ext = False

    def test_wb_sa_port_state_change(self):
        '''
         call WB disconnect API, relese the port from spirent and make sure port state is in tuning
         call WB recoonect API, start the port from spirent and make sure port state is moving to link up
        '''
        print("checking port state changes")
        self.fill_args_from_env_vars(self.TRAFFIC_MODE.TRAFFIC_AFTER_ACTIVATE, False)
        self.snake.run_snake()
        self.open_spirent()
        all_up = self.snake.mph.wait_mac_ports_up(timeout=DWELL_UP_TIME)
        self.assertTrue(all_up, 'Some of port link are down.')
        device = self.snake.device
        warm_boot_filename = tempfile.mkstemp()[1]
        sdk_py_objs_metadata = wb.warm_boot_disconnect(device, warm_boot_filename)

        # bring down the spirent port
        print("set spirent port down")
        self.spirent.spirent_port.stc_port.project.command('L2TestBreakLinkCommand')

        # reconnect
        wb.warm_boot_reconnect(sdk_py_objs_metadata, warm_boot_filename)
        if os.path.exists(warm_boot_filename):
            os.remove(warm_boot_filename)

        self.snake.mph.critical_fd, self.snake.mph.normal_fd = device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)
        mac_ports = self.snake.mph.mac_ports

        time.sleep(DWELL_TIME)
        # for GB Port Sanity, it is flipping between TUNING and TUNED
        state = mac_ports[0].get_state()
        self.assertTrue(state == sdk.la_mac_port.state_e_TUNING or state ==
                        sdk.la_mac_port.state_e_TUNED, 'invalid port state: it should be TUNING or TUNED')

        # bring up the spirent port
        print("set spirent port up")
        self.spirent.spirent_port.stc_port.project.command('L2TestRestoreLinkCommand')
        time.sleep(DWELL_TIME)
        self.assertEqual(mac_ports[0].get_state(), sdk.la_mac_port.state_e_LINK_UP)


if __name__ == '__main__':
    unittest.main()
