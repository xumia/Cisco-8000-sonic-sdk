#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import snake_standalone
from snake_test_base import *
import time

verbose = 0

HBM_RATE_LIMIT = 2000 * 1e9  # bps

RATE_DELTA_PCT = 0.01  # Tolerance

if decor.is_hw_kontron_compact_cpu():
    BOARD_TYPE = 'examples/sanity/blacktip_compact_cpu_board_config.json'
else:
    BOARD_TYPE = 'examples/sanity/blacktip_board_config.json'

BOARD_MIX = 'test/api/snake/blacktip_full_mix.json'
BOARD_CFG_PATH = 'examples/sanity/blacktip_serdes_settings.json'


@unittest.skipUnless(decor.is_hw_gibraltar(), "Requires GB HW Device")
@unittest.skipUnless(decor.is_run_slow(), "Slow test not part of sanity : Rate measturement tests may create time overhead")
class hbm_bw_shaper(snake_test_base):

    def setUp(self):
        super().setUp()

        self.snake.args.loop_mode = 'serdes'
        self.snake.args.board_cfg_path = BOARD_TYPE
        self.snake.args.json_mix = BOARD_MIX
        self.snake.args.params_json = BOARD_CFG_PATH
        self.snake.args.hbm = snake_standalone.HBM_MODE_FORCE
        self.snake.run_snake()

        self.dd = self.snake.debug_device
        self.tree = self.dd.device_tree
        self.device = self.snake.device

        device_caps = self.snake.device.get_device_bool_capabilities()
        self.has_hbm = device_caps[sdk.la_device.device_bool_capability_e_HAS_HBM]
        if verbose > 0:
            print("HAS_HBM = {}".format(self.has_hbm))

    def tearDown(self):
        super().tearDown()
        self.snake.teardown()

    def inject_traffic(self):
        INJECT_PACKETS_COUNT = 20500
        mp0 = self.snake.mph.mac_ports[0]
        self.snake.send_traffic_to_port(mp0.get_slice(),
                                        mp0.get_ifg(),
                                        mp0.get_first_serdes_id(),
                                        mp0.get_first_pif_id(),
                                        packet_count=INJECT_PACKETS_COUNT,
                                        packet_size=128)

    def test_setter_getter(self):
        if not self.has_hbm:
            self.skipTest("No HBM")

        hbm_h = self.device.get_hbm_handler()

        hbm_h.set_rate_limit(HBM_RATE_LIMIT)
        rate_limit = hbm_h.get_rate_limit()
        self.assertEqual(rate_limit, HBM_RATE_LIMIT)

    def test_hbm_rate_check(self):
        if not self.has_hbm:
            self.skipTest("No HBM")

        hbm_h = self.device.get_hbm_handler()

        self.inject_traffic()

        # Clear
        hbm_h.read_rate(True)
        is_done = hbm_h.is_rate_measurement_completed()
        self.assertFalse(is_done)

        try:
            hbm_h.start_rate_measurement(0)
        except BaseException:
            self.fail("Zero rate masurement failed")

        durations = [1, 3, 10]  # seconds

        tmp_rate = None
        for duration in durations:
            try:
                hbm_h.start_rate_measurement(duration)
            except sdk.NotImplementedException:
                print("{} seconds duration not supported yet".format(duration))
            except BaseException:
                self.fail()
            else:
                time.sleep(duration + 1)

                is_done = hbm_h.is_rate_measurement_completed()
                self.assertTrue(is_done)

                rate = hbm_h.read_rate(True)

                if tmp_rate is not None:
                    delta = int((tmp_rate + rate) / 2 * RATE_DELTA_PCT)
                    if verbose > 0:
                        print(
                            "Duration = {} : Measured rate = {:.2f} Gbps Delta = {:.2f} Gbps".format(
                                duration, rate / 10 ** 9, delta / 10 ** 9))
                    self.assertLessEqual(abs(tmp_rate - rate), delta)

                tmp_rate = rate


if __name__ == '__main__':
    unittest.main()
