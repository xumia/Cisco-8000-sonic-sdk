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

SHERMAN_BOARD_TYPE = 'examples/sanity/shermanP5_board_config.json'
if decor.is_hw_kontron_compact_cpu():
    BLACKTIP_BOARD_TYPE = 'examples/sanity/blacktip_compact_cpu_board_config.json'
else:
    BLACKTIP_BOARD_TYPE = 'examples/sanity/blacktip_board_config.json'
APPLY_PACIFIC_B0_IFG = False
SHERMAN_MIX = 'test/api/snake/sherman_full_mix.json'
BLACKTIP_MIX = 'test/api/snake/blacktip_full_mix.json'
SHERMAN_LINE_CARD_MIX = 'test/api/snake/sherman_line_card_mix.json'


if decor.is_gibraltar():
    BOARD_TYPE = BLACKTIP_BOARD_TYPE
    if decor.is_matilda():
        BLACKTIP_MIX = 'test/api/snake/matilda_regular_mix.json'
    BOARD_MIX = BLACKTIP_MIX
else:
    BOARD_TYPE = SHERMAN_BOARD_TYPE
    BOARD_MIX = SHERMAN_MIX


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipUnless(is_hw_device, "Requires HW device")
@unittest.skipIf(decor.is_hw_gibraltar(), "SKIP-GB-HW")
class test_snake(snake_test_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_loop_serdes(self):
        self.snake.args.pacific_b0_ifg = APPLY_PACIFIC_B0_IFG
        self.snake.args.board_cfg_path = BOARD_TYPE
        self.snake.args.loop_mode = 'serdes'
        self.snake.args.json_mix = BOARD_MIX

        self.base_loop_test(TEST_PACKET_SIZE)

        save_state_fname = "dev_state.gz"
        # Clear all pending notifications
        crit, norm = self.snake.mph.read_notifications(1)
        # Read empty notifications to verify notifications are cleared
        crit, norm = self.snake.mph.read_notifications(1)

        # Check link notifications are empty
        self.assertEqual(len(crit), 0)
        self.assertEqual(len(norm), 0)

        options = sdk.save_state_options()
        options.include_mac_port_serdes = True
        self.snake.device.save_state(options, save_state_fname)

        # Check link notifications are still empty after save state
        self.assertEqual(len(crit), 0)
        self.assertEqual(len(norm), 0)
        os.remove(save_state_fname)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_loop_serdes_hbm(self):
        self.snake.args.pacific_b0_ifg = APPLY_PACIFIC_B0_IFG
        self.snake.args.board_cfg_path = BOARD_TYPE
        self.snake.args.loop_mode = 'serdes'
        self.snake.args.json_mix = BOARD_MIX
        self.snake.args.hbm = snake_standalone.HBM_MODE_ENABLE

        self.base_loop_test(TEST_PACKET_SIZE)

        self.check_dram_hbm(True)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_loop_pma(self):
        self.snake.args.pacific_b0_ifg = APPLY_PACIFIC_B0_IFG
        self.snake.args.board_cfg_path = BOARD_TYPE
        self.snake.args.loop_mode = 'pma'
        self.snake.args.json_mix = BOARD_MIX

        self.base_loop_test(TEST_PACKET_SIZE)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_loop_pma_hbm(self):
        self.snake.args.pacific_b0_ifg = APPLY_PACIFIC_B0_IFG
        self.snake.args.board_cfg_path = BOARD_TYPE
        self.snake.args.loop_mode = 'pma'
        self.snake.args.json_mix = BOARD_MIX
        self.snake.args.hbm = snake_standalone.HBM_MODE_ENABLE

        self.base_loop_test(TEST_PACKET_SIZE)

        self.check_dram_hbm(True)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_loop_pma_line_card(self):
        self.snake.args.pacific_b0_ifg = APPLY_PACIFIC_B0_IFG
        self.snake.args.board_cfg_path = BOARD_TYPE
        self.snake.args.loop_mode = 'pma'
        self.snake.args.json_mix = SHERMAN_LINE_CARD_MIX
        self.snake.args.line_card = True

        self.base_loop_test(TEST_PACKET_SIZE)


if __name__ == '__main__':
    unittest.main()

    # For interactive debug
    '''
    tc = test_snake()
    tc.setUp()
    tc.snake.args.pacific_b0_ifg = APPLY_PACIFIC_B0_IFG
    tc.snake.args.board_cfg_path = BOARD_TYPE
    tc.snake.args.loop_mode = 'serdes'
    tc.snake.args.json_mix = BOARD_MIX

    tc.base_loop_test(TEST_PACKET_SIZE, stop_after_dwell = False)
    '''
