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
import time
from ports_base import *
import decor


LEGAL_DELAY_PACIFIC = 60
LEGAL_DELAY_GIBRALTAR = 16


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_time_to_link(ports_base):
    loop_mode = 'none'
    p2p_ext = True

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_time_to_link(self):
        self.fill_args_from_env_vars('default_mix.json')
        link_status = self.snake.run_snake()
        self.assertTrue(link_status, 'one or more port links are down')
        if self.is_pacific():
            timeout = LEGAL_DELAY_PACIFIC
        else:
            timeout = LEGAL_DELAY_GIBRALTAR

        self.outfile = open("{}/link_up_times_{}.csv".format(self.reports_dir, self.id()), "w+", 1)
        self.outfile.write('Link,name,FC,FEC,ANLT,Loopback,slice,IFG,SerDes,link state,pcs,time to link up\n')
        for shut_iter in range(self.test_iterations):
            if shut_iter != 0:
                self.shut_no_shut_mac_ports(self.snake.mph.mac_ports)

            for index, mp_time in enumerate(self.snake.mph.mac_time):
                current_delay = mp_time["after_port_up"] - mp_time["time_before_activate"]
                mac_info = self.snake.mph.get_mac_info(index)
                self.outfile.write(
                    '{index},{name},{fc_mode},{fec_mode},{anlt},{loopback},{slice},{ifg},{serdes},'
                    '{link_state},{pcs_status}'.format(**mac_info))
                self.outfile.write(',{:.2f}\n'.format(current_delay))
                self.assertLessEqual(
                    current_delay,
                    timeout,
                    'Port {} slice/ifg/serdes={}/{}/{} : expected time to link Less or equal to {} actual the time is {}'.format(
                        mac_info['name'],
                        mac_info['slice'],
                        mac_info['ifg'],
                        mac_info['serdes'],
                        timeout,
                        current_delay))
        self.outfile.close()


if __name__ == '__main__':
    unittest.main()
