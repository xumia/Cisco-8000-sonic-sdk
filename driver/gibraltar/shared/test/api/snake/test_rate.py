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

from sanity_constants import *
from snake_test_base import *

TEST_PACKET_SIZE = 500

# Traffic dwell time in seconds
TRAFFIC_DWELL_TIME = 2

TEST_PACKET_NUM = 5600

BOARD_TYPE = 'examples/sanity/shermanP5_board_config.json'
APPLY_PACIFIC_B0_IFG = True
SHERMAN_MIX = 'test/api/snake/sherman_2x50g_mix.json'


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipUnless(is_hw_device, "Requires HW device")
@unittest.skipIf(decor.is_hw_gibraltar(), "SKIP-GB-HW")
class test_rate(snake_test_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_rate_serdes_max_tp(self):
        self.snake.args.pacific_b0_ifg = APPLY_PACIFIC_B0_IFG
        self.snake.args.loop_mode = 'serdes'
        self.snake.args.json_mix = SHERMAN_MIX

        self.base_loop_test(TEST_PACKET_SIZE, duration_seconds=TRAFFIC_DWELL_TIME,
                            inject_packets_count=TEST_PACKET_NUM, rate_check=True)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_rate_serdes_max_pps(self):
        self.snake.args.pacific_b0_ifg = APPLY_PACIFIC_B0_IFG
        self.snake.args.loop_mode = 'serdes'
        self.snake.args.json_mix = SHERMAN_MIX

        self.base_loop_test(178, duration_seconds=TRAFFIC_DWELL_TIME, inject_packets_count=20500, rate_check=True)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_rate_serdes_max_pps_shaped(self):
        self.snake.args.pacific_b0_ifg = APPLY_PACIFIC_B0_IFG
        self.snake.args.loop_mode = 'serdes'
        self.snake.args.json_mix = SHERMAN_MIX

        self.base_loop_test_setup()
        device_info = self.snake.device.get_device_information()
        if (device_info.revision < 2):
            self.skipTest("Limiting PPS not supported on this device")

        # Test set/get
        for i in range(6, 101):
            rate = i / 100.0
            self.snake.device.set_ifg_maximum_pps_utilization(rate)
            curr_max_pps_percent = self.snake.device.get_ifg_maximum_pps_utilization()
            self.assertAlmostEqual(curr_max_pps_percent, rate, delta=0.02)

        self.snake.device.set_ifg_maximum_pps_utilization(.9)
        self.base_loop_test_run(128, duration_seconds=TRAFFIC_DWELL_TIME, inject_packets_count=20500, rate_check=True)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_loop_pma(self):
        self.snake.args.pacific_b0_ifg = APPLY_PACIFIC_B0_IFG
        self.snake.args.board_cfg_path = BOARD_TYPE
        self.snake.args.loop_mode = 'pma'
        self.snake.args.json_mix = SHERMAN_MIX

        self.base_loop_test(TEST_PACKET_SIZE, duration_seconds=TRAFFIC_DWELL_TIME,
                            inject_packets_count=TEST_PACKET_NUM, rate_check=True)


if __name__ == '__main__':
    unittest.main()
