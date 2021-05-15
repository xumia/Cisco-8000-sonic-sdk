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
from leaba import debug
import lldcli

from snake_standalone import snake_base_topology
from xena_connector import *
from traffic_gen_base import *
import sys

TRAFFIC_DWELL_TIME = 10
SHUT_ITERATIONS = 10

PATH = '/dev/uio0'
BOARD = 'shermanP5'
XENA_IP = '10.56.19.10'
XENA_PORT = '4/0'
JSON_MIX = '/mnt/ssd/sanity/sherman_100g.json'
PARAMS_JSON = 'examples/sanity/sherman_serdes_settings.json'
MODULE_TYPE = 'COPPER'
LOOP_MODE = 'none'
P2P_EXT = True
PROTOCOL = 'none'


class mac_port_stress_w_traffic(traffic_gen_base):
    def setUp(self):
        super().init(PATH,
                     BOARD,
                     XENA_IP,
                     XENA_PORT,
                     JSON_MIX,
                     PARAMS_JSON,
                     MODULE_TYPE,
                     LOOP_MODE,
                     P2P_EXT,
                     PROTOCOL)

    def tearDown(self):
        self.snake.device.flush()
        sdk.la_destroy_device(self.snake.device)

    def shut_no_shut_base_test(self, with_traffic):
        for shut_iter in range(SHUT_ITERATIONS):
            # Shutdown all ports
            for mac_port in self.snake.mph.mac_ports:
                mac_port.stop()

            self.snake.mph.wait_mac_ports_down()

            self.snake.mph.mac_ports_activate(MODULE_TYPE, PARAMS_JSON)
            self.snake.mph.wait_mac_ports_up()
            all_up = self.snake.mph.print_mac_up()

            self.assertTrue(all_up, 'Some of port link are down. iteration {}'.format(shut_iter))

            self.snake.mph.clear_mac_stats()

            if with_traffic:
                xena_info = self.xena.run_and_get_rx_tx(TRAFFIC_DWELL_TIME)
                tx_pkt = xena_info['tx_packets']
                rx_pkt = xena_info['rx_packets']

                self.assertEqual(rx_pkt, tx_pkt, 'iteration {}'.format(shut_iter))
                self.check_mac_stats(self.snake.mph.mac_ports, tx_pkt)

            self.check_mac_fec(self.snake.mph.mac_ports)

    def test_shut_no_shut_wo_traffic(self):
        self.shut_no_shut_base_test(False)

    def test_shut_no_shut_w_traffic(self):
        self.shut_no_shut_base_test(True)

    def _test_traffic_in_middle_shut_iter(self):
        self.xena.xena_port.StartTraffic()

        for shut_iter in range(SHUT_ITERATIONS):

            # Shutdown all ports
            for mac_port in self.snake.mph.mac_ports:
                mac_port.stop()

            self.snake.mph.wait_mac_ports_down()

            self.check_mac_progress(self.snake.mph.mac_ports, False)

            self.snake.mph.mac_ports_activate(MODULE_TYPE, PARAMS_JSON)
            self.snake.mph.wait_mac_ports_up()
            all_up = self.snake.mph.print_mac_up()

            self.assertTrue(all_up, 'Some of port link are down. iteration {}'.format(shut_iter))

            self.check_mac_progress(self.snake.mph.mac_ports, True)
            self.snake.mph.clear_mac_stats()
            self.check_mac_fec(self.snake.mph.mac_ports)

        self.xena.xena_port.StopTraffic()


if __name__ == '__main__':
    unittest.main()
