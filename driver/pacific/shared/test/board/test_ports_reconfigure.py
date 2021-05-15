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
import datetime

from leaba import sdk
from leaba import debug
import sim_utils
import lldcli
import json

from snake_standalone import snake_base_topology
from ports_base import *
import decor


@unittest.skipIf(decor.is_matilda("3.2"), "GB 3.2 Does not support mac_port->reconfigure() functionality")
@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ports_reconfigure_test(ports_base):
    loop_mode = 'serdes'
    p2p_ext = False

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_reconfigure(self):
        self.fill_args_from_env_vars('default_mix.json')
        self.snake.run_snake()
        all_up = self.snake.mph.wait_mac_ports_up(timeout=DWELL_UP_TIME)
        self.assertTrue(all_up, 'Some of port link are down Before Ports reconfig.')
        self.reconfig()
        all_up = self.snake.mph.wait_mac_ports_down(timeout=DWELL_UP_TIME)
        self.activate_ports()
        all_up = self.snake.mph.wait_mac_ports_up(timeout=DWELL_UP_TIME)
        self.snake.mph.print_mac_up()
        self.assertTrue(all_up, 'Some of port link are down After Ports reconfig.')

    def reconfig(self):
        with open(self.json_reconfig_mix, 'r') as fh:
            port_mix_map = json.load(fh)
            index = 0
            for loopback_port in port_mix_map['loopback_ports']:
                slice_list = loopback_port['slice'] if isinstance(loopback_port['slice'], list) else [loopback_port['slice']]
                ifg_list = loopback_port['ifg'] if isinstance(loopback_port['ifg'], list) else [loopback_port['ifg']]
                serdes_list = loopback_port['serdes'] if isinstance(loopback_port['serdes'], list) else [loopback_port['serdes']]
                serdes_count = loopback_port['serdes_count']
                speed = eval('sdk.la_mac_port.port_speed_e_E_{}G'.format(int(loopback_port['speed'])))
                fc = eval('sdk.la_mac_port.fc_mode_e_{}'.format(loopback_port['fc'].upper()))
                fec = eval('sdk.la_mac_port.fec_mode_e_{}'.format(loopback_port['fec'].upper()))
                #an = loopback_port['an'] if 'an' in loopback_port else False
                #fabric = loopback_port['fabric'] if 'fabric' in loopback_port else False
                for slice in slice_list:
                    for ifg in ifg_list:
                        for serdes in serdes_list:
                            try:
                                mp = self.snake.device.get_mac_port(slice, ifg, serdes)
                            except BaseException:
                                raise Exception(
                                    'Error: get_mac_port failed. slice=%d ifg=%d first_pif=%d' %
                                    (slice_id, ifg, serdes))
                            mp.stop()
                            mp.reconfigure(serdes_count, speed, fc, fc, fec)
                            index += 1

    def activate_ports(self):
        for mp in self.snake.mph.mac_ports:
            mp.activate()


if __name__ == '__main__':
    unittest.main()
    '''
    tc = ports_reconfigure_test()
    tc.setUp()
    tc.test_reconfigure()
    '''
