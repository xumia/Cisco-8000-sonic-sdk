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

TRAFFIC_DWELL_TIME = 25  # Time for 100Gbps, Packet Counter to reach wrap-around is ~22 seconds
INTERRUPTS_DISABLED_TIME = 2.5  # Time for 100Gbps Byte count to wrap around is 2.74 sec
INTERRUPTS_ENABLED_TIME = 0.25  # Time for Interrupt thread to read several Max counter interations
RUN_ITERATIONS = 10
INTERRUPT_ITERATIONS = 3

PATH = '/dev/uio0'
BOARD = 'shermanP5'
XENA_IP = '10.56.19.10'
XENA_PORT = '4/0'
JSON_MIX = '/mnt/ssd/sanity/sherman_100g.json'
PARAMS_JSON = 'examples/sanity/sherman_serdes_settings.json'
MODULE_TYPE = 'COPPER'
LOOP_MODE = 'none'
P2P_EXT = True
IPV4 = False


class counters_stress_test(traffic_gen_base):
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
                     IPV4)

    def tearDown(self):
        self.snake.device.flush()
        sdk.la_destroy_device(self.snake.device)

    def check_counters(self, iter, xena_info):
        self.assertEqual(xena_info['rx_packets'], xena_info['tx_packets'], 'iteration {}'.format(iter))

        xena_info['rx_bytes'] = xena_info['rx_bytes'] - 4 * xena_info['rx_packets']
        xena_info['tx_bytes'] = xena_info['tx_bytes'] - 4 * xena_info['tx_packets']
        for index in range(len(self.snake.ac_ports)):
            ac_info = self.snake.get_ac_port_stats(index)
            self.assertEqual(ac_info['in_packets'], xena_info['tx_packets'], 'iteration {}'.format(iter))
            self.assertEqual(ac_info['eg_packets'], xena_info['rx_packets'], 'iteration {}'.format(iter))
            self.assertEqual(ac_info['in_bytes'], xena_info['tx_bytes'], 'iteration {}'.format(iter))
            self.assertEqual(ac_info['eg_bytes'], xena_info['rx_bytes'], 'iteration {}'.format(iter))

    def test_counters_basic(self):
        for iter in range(RUN_ITERATIONS):
            self.snake.mph.clear_mac_stats()

            for index in range(len(self.snake.ac_ports)):  # Clear all ac port ingress/egress counters
                self.snake.get_ac_port_stats(index)

            xena_info = self.xena.run_and_get_rx_tx(TRAFFIC_DWELL_TIME)

            self.check_counters(iter, xena_info)

    def test_counters_no_wrap_around(self):
        for iter in range(RUN_ITERATIONS):
            self.snake.mph.clear_mac_stats()

            for index in range(len(self.snake.ac_ports)):  # Clear all ac port ingress/egress counters
                self.snake.get_ac_port_stats(index)

            msi_mask = self.snake.ll_device.read_register(self.snake.pacific_tree.sbif.msi_blocks_interrupt_summary_reg0_mask)
            self.xena.xena_port.ClearStatistic()
            self.xena.xena_port.StartTraffic()
            for interrupts_iter in range(INTERRUPT_ITERATIONS):
                time.sleep(INTERRUPTS_ENABLED_TIME)
                # Disable interrupts
                self.snake.ll_device.write_register(self.snake.pacific_tree.sbif.msi_blocks_interrupt_summary_reg0_mask, 0x0)
                self.snake.device.set_bool_property(sdk.la_device_property_e_PROCESS_INTERRUPTS, False)
                time.sleep(INTERRUPTS_DISABLED_TIME)
                # Enable interrupts
                self.snake.device.set_bool_property(sdk.la_device_property_e_PROCESS_INTERRUPTS, True)
                self.snake.ll_device.write_register(self.snake.pacific_tree.sbif.msi_blocks_interrupt_summary_reg0_mask, msi_mask)

            self.xena.xena_port.StopTraffic()
            time.sleep(1)
            xena_info = self.xena.xena_port.GetStatistic()
            self.check_counters(iter, xena_info)


if __name__ == '__main__':
    unittest.main()
