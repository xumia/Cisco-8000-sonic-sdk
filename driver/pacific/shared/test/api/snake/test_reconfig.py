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

SHERMAN_MIX = 'test/api/snake/reconfig.json'
BLACKTIP_MIX = 'test/api/snake/reconfig.json'


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
@unittest.skipIf(decor.is_matilda('3.2'), "Matilda 3.2 do not support port reconfig!")
class test_reconfig(snake_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Matilda Does not support serdes speed above 25 Gbit")
    def test_reconfig_2x50_to_8x50(self):
        self.snake.args.board_cfg_path = BOARD_TYPE
        self.snake.args.loop_mode = 'pma'
        self.snake.args.json_mix = BOARD_MIX
        self.snake.args.punt_traf = True

        self.snake.run_snake()

        self.send_and_check_traffic()

        self.snake.destroy_port(0, 0, 2)
        self.snake.destroy_port(0, 0, 4)
        self.snake.destroy_port(0, 0, 6)

        mp0 = self.snake.mph.mac_ports[0]
        mp0.stop()
        mp0.reconfigure(8, sdk.la_mac_port.port_speed_e_E_400G, sdk.la_mac_port.fc_mode_e_NONE,
                        sdk.la_mac_port.fc_mode_e_NONE, sdk.la_mac_port.fec_mode_e_RS_KP4)
        mp0.activate()
        for retry in range(10):
            if mp0.read_mac_status().link_state:
                break
            time.sleep(0.5)

        self.snake.ac_ports[0].set_destination(self.snake.ac_ports[1])
        self.snake.create_switch(self.snake.ac_ports[0], self.snake.ac_ports[1])

        self.send_and_check_traffic()

    def send_and_check_traffic(self):
        self.snake.send_traffic_to_port(0, 0, 0, 0)
        time.sleep(1)
        self.snake.get_traffic_from_port(0, 0, 0)

        stats = self.snake.mph.get_mac_fec_counters(False)
        self.snake.mph.print_mac_stats()

        self.assertGreater(stats[0]['tx_frames'], 0, 'no packets were sent')
        self.assertEqual(
            stats[0]['tx_frames'],
            stats[1]['rx_frames'],
            'number of packet received doesnt match number of packets sent. sent:{}, received: {}'.format(
                stats[0]['tx_frames'],
                stats[1]['rx_frames']))
        self.assertEqual(
            stats[1]['rx_frames'],
            stats[1]['tx_frames'],
            'number of packet received doesnt match number of packets sent. sent:{}, received: {}'.format(
                stats[1]['rx_frames'],
                stats[1]['tx_frames']))
        self.assertEqual(
            stats[1]['tx_frames'],
            stats[0]['rx_frames'],
            'number of packet received doesnt match number of packets sent. sent:{}, received: {}'.format(
                stats[0]['tx_frames'],
                stats[1]['rx_frames']))


if __name__ == '__main__':
    unittest.main()
    '''
    # For interactive debug
    tc = test_reconfig()
    tc.setUp()
    tc.test_reconfig_2x50_to_8x50()
    '''
