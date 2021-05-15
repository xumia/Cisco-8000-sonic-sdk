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
import time

BOARD_TYPE = 'examples/sanity/churchillP0_board_config.json'
JSON_DEFAULT_DIR = 'test/board/mixes/'
DWELL_UP_TIME = 10  # Time in seconds
DWELL_SHUT_TIME = 10  # Time in seconds


class test_wb_sa_base(snake_base):
    def setUp(self):
        super().setUp()

    def tearDown(self):
        super().tearDown()

    def setup_ports(self):
        board_type = 'churchill'
        json_dir = os.getenv("connectivity_dir")
        if json_dir is None:
            json_dir = JSON_DEFAULT_DIR
        self.snake.args.json_mix = json_dir + '/' + board_type + '/'
        self.snake.args.json_mix += 'full-gb.json'
        board_cfg_path = os.getenv("board_cfg_path")
        if board_cfg_path is None:
            board_cfg_path = BOARD_TYPE
        self.snake.args.board_cfg_path = board_cfg_path

        self.snake.args.loop_mode = 'serdes'
        link_status = self.snake.run_snake()
        self.assertTrue(link_status, 'one or more port links are down')
