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


@unittest.skip("Skip until WB is merged to master and stabilized.")
@unittest.skipUnless(decor.is_hw_device(), "Requires HW device")
@unittest.skipUnless(decor.is_gibraltar(), "WB is only suppored for gibraltar")
class test_wb_sa_port_prop(ports_base):
    loop_mode = 'serdes'
    p2p_ext = False

    def test_wb_sa_port_prop(self):
        '''
        check port property persistence across warmboot, make sure no traffic interruption
        '''
        print("checking port property")
        self.fill_args_from_env_vars(self.TRAFFIC_MODE.TRAFFIC_AFTER_ACTIVATE, False)
        self.snake.run_snake()
        self.open_spirent()
        all_up = self.snake.mph.wait_mac_ports_up(timeout=DWELL_UP_TIME)
        self.assertTrue(all_up, 'Some of port link are down Before port property changes')
        self.spirent.add_data_streams(num_streams=1,
                                      gen_type="FIXED",
                                      min_packet_size=500,
                                      max_packet_size=500,
                                      rate_percentage=2,
                                      fixed_frame_length=370,
                                      pkt=Ether(src="00:01:02:03:FF:FF", dst="CA:FE:CA:FE:00:00", type=0x8100) / Dot1Q(vlan=256))
        device = self.snake.device
        mac_ports = self.snake.mph.mac_ports
        for i in range(len(mac_ports)):
            mac_ports[i].set_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR, sdk.la_mac_port.fc_mode_e_PAUSE)

        self.spirent.run_traffic()
        wb.warm_boot(device)
        # need to read it twice and makre sure traffic is still running
        res = self.spirent.spirent_port.get_statistic()
        res = self.spirent.spirent_port.get_statistic()
        self.assertFalse(res['rx_pps'] == 0)

        # Restore notification pipes manually
        self.snake.mph.critical_fd, self.snake.mph.normal_fd = device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)
        all_up = self.snake.mph.wait_mac_ports_up(timeout=DWELL_UP_TIME)
        self.assertTrue(all_up, 'Some of port link are down After port property changes')
        # Retrieve the re-created mac_port objects
        mac_ports = device.get_objects(sdk.la_object.object_type_e_MAC_PORT)
        for i in range(len(mac_ports)):
            fc_mode = mac_ports[i].get_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR)
            self.assertEqual(fc_mode, sdk.la_mac_port.fc_mode_e_PAUSE)

            self.assertEqual(mac_ports[i].get_serdes_tuning_mode(), sdk.la_mac_port.serdes_tuning_mode_e_ICAL)
            self.assertTrue(mac_ports[i].get_serdes_continuous_tuning_enabled())
            self.assertTrue(mac_ports[i].get_link_management_enabled())
            # traffic port is not in serdes loopback mode
            if i != 0:
                self.assertEqual(mac_ports[i].get_loopback_mode(), sdk.la_mac_port.loopback_mode_e_SERDES)
            self.assertFalse(mac_ports[i].get_pcs_test_mode())
            self.assertFalse(mac_ports[i].get_pma_test_mode())


if __name__ == '__main__':
    unittest.main()
