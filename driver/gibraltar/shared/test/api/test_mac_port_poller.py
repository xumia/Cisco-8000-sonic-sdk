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
import unittest
from leaba import sdk
import sim_utils
import subprocess
import topology
import time
import os


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipUnless(os.getenv('USER') == 'root', "Requires root privilges for time adjustment")
class test_mac_port_poller(unittest.TestCase):

    def system_time_offset(self, advance=True):
        date_path_ls = subprocess.check_output('ls -l `which date`', shell=True).decode('utf8').split('\n')[0]
        if 'busybox' in date_path_ls:
            if advance:
                new_time = subprocess.check_output(
                    'date "+%Y-%m-%d %H:%M:%S" -D %s -d $(( $(date +%s) + 3600 ))',
                    shell=True).decode('utf8').split('\n')[0]
            else:
                new_time = subprocess.check_output(
                    'date "+%Y-%m-%d %H:%M:%S" -D %s -d $(( $(date +%s) - 3600 ))',
                    shell=True).decode('utf8').split('\n')[0]
            # Set the time in a separate step
            subprocess.check_output('date -s "%s"' % new_time, shell=True).decode('utf8').split('\n')[0]
        else:
            if advance:
                subprocess.check_output('date $(date +%m%d%H%M%Y.%S -d "1 hour")', shell=True)
            else:
                subprocess.check_output('date $(date +%m%d%H%M%Y.%S -d "1 hour ago")', shell=True)

    def link_up_check(self, mac_port, timeout):
        # Wait for link up
        for elapsed in range(timeout):
            link_up = True
            if mac_port.get_state() != mac_port.state_e_LINK_UP:
                link_up = False
            if link_up:
                break
            time.sleep(1)
        return link_up

    def setUp(self):
        self.device = sim_utils.create_device(1)
        os.system('date')

    def tearDown(self):
        self.system_time_offset(True)
        self.device.tearDown()
        os.system('date')

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mac_port_poller(self):
        slice_id = 0
        ifg_id = 0
        first_serdes_id = 4
        last_serdes_id = 5

        # serdes loopback link should come up in 6s
        loopback_timeout = 6
        speed = sdk.la_mac_port.port_speed_e_E_100G
        if topology.is_matilda_model(self.device):
            speed = sdk.la_mac_port.port_speed_e_E_50G

        mac_port = self.device.create_mac_port(slice_id, ifg_id, first_serdes_id, last_serdes_id,
                                               speed,
                                               sdk.la_mac_port.fc_mode_e_NONE,
                                               sdk.la_mac_port.fec_mode_e_RS_KP4)

        self.assertIsNotNone(mac_port)

        mac_port.set_loopback_mode(sdk.la_mac_port.loopback_mode_e_SERDES)
        mac_port.activate()

        link_up = self.link_up_check(mac_port, loopback_timeout)

        self.assertTrue(link_up, 'Link not up in {}s'.format(loopback_timeout))

        # roll back system clock by an hour
        self.system_time_offset(False)
        os.system('date')

        mac_port.stop()
        time.sleep(1)

        mac_port.activate()

        link_up = self.link_up_check(mac_port, loopback_timeout)

        self.assertTrue(link_up, 'Link not up in {}s after clock rolled back 1hr'.format(loopback_timeout))
        print("done")

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mac_port_link_up_assertion(self):
        slice_id = 0
        ifg_id = 0
        first_serdes_id = 4
        last_serdes_id = 5

        # serdes loopback link should come up in 6s
        loopback_timeout = 6
        speed = sdk.la_mac_port.port_speed_e_E_100G
        if topology.is_matilda_model(self.device):
            speed = sdk.la_mac_port.port_speed_e_E_50G

        mac_port = self.device.create_mac_port(slice_id, ifg_id, first_serdes_id, last_serdes_id,
                                               speed,
                                               sdk.la_mac_port.fc_mode_e_NONE,
                                               sdk.la_mac_port.fec_mode_e_RS_KP4)

        self.assertIsNotNone(mac_port)
        mac_port.set_loopback_mode(sdk.la_mac_port.loopback_mode_e_SERDES)
        mac_port.activate()
        self.assertFalse(mac_port.activate(), "mac link down")


if __name__ == '__main__':
    unittest.main()
