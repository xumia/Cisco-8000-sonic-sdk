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
import decor
from leaba import sdk

from snake_test_base import *

BOARD_TYPE = 'examples/sanity/shermanP7_board_config.json'
PARAM_JSON = 'examples/sanity/sherman_serdes_settings.json'
APPLY_PACIFIC_B0_IFG = False
JSON_DEFAULT_DIR = 'test/board/mixes/'
TEST_PACKET_SIZE = 500
INJECT_SLICE = 2
INJECT_IFG = 0


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class hw_snake_test(snake_test_base):
    def fill_args_from_env_vars(self, is_an_enabled):
        self.snake.args.loop_mode = 'none'
        self.snake.args.p2p_ext = True

        board_type = os.getenv("board_type")
        if board_type is None:
            board_type = 'sherman'
        board_cfg_path = os.getenv("board_cfg_path")
        if board_cfg_path is None:
            board_cfg_path = BOARD_TYPE
        json_dir = os.getenv("connectivity_dir")
        if json_dir is None:
            json_dir = JSON_DEFAULT_DIR
        self.snake.args.json_mix = json_dir + '/' + board_type + '/'
        if is_an_enabled:
            self.snake.args.json_mix += 'anlt_mix.json'
        else:
            self.snake.args.json_mix += 'default_mix.json'

        self.snake.args.board_cfg_path = board_cfg_path if self.snake.args.loop_mode == 'none' else None

        self.snake.args.params_json = os.getenv("serdes_params_json")
        if self.snake.args.params_json is None:
            self.snake.args.params_json = PARAM_JSON

        self.snake.args.pacific_b0_ifg = APPLY_PACIFIC_B0_IFG

    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_loop_hw(self):
        self.fill_args_from_env_vars(False)

        self.base_loop_test(TEST_PACKET_SIZE, INJECT_SLICE, INJECT_IFG)

    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_loop_hw_w_anlt(self):
        self.fill_args_from_env_vars(True)

        self.base_loop_test(TEST_PACKET_SIZE, INJECT_SLICE, INJECT_IFG)

    @unittest.skip("Low power mode is instable")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_loop_hw_low_power(self):
        self.fill_args_from_env_vars(False)
        self.snake.args.serdes_low_power = True

        self.base_loop_test(TEST_PACKET_SIZE, INJECT_SLICE, INJECT_IFG)

    @unittest.skip("Low power mode is instable")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_loop_hw_low_power_w_anlt(self):
        self.fill_args_from_env_vars(True)
        self.snake.args.serdes_low_power = True

        self.base_loop_test(TEST_PACKET_SIZE, INJECT_SLICE, INJECT_IFG)


if __name__ == '__main__':
    unittest.main()

    # For interactive debug
    '''
    tc = hw_snake_test()
    tc.setUp()
    tc.snake.args.pacific_b0_ifg = APPLY_PACIFIC_B0_IFG
    tc.snake.args.board_cfg_path = BOARD_TYPE
    tc.snake.args.loop_mode = 'none'
    tc.snake.args.json_mix = SHERMAN_MIX
    tc.snake.args.p2p_ext = True

    tc.base_loop_test(TEST_PACKET_SIZE, INJECT_SLICE, INJECT_IFG)
    '''
