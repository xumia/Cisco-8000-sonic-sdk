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

import os
import socket
import unittest
from leaba import sdk

import decor
import snake_standalone
import mac_port_helper
import time

if decor.is_hw_kontron_compact_cpu():
    BLACKTIP_BOARD_TYPE = 'examples/sanity/blacktip_compact_cpu_board_config.json'
else:
    BLACKTIP_BOARD_TYPE = 'examples/sanity/blacktip_board_config.json'

BLACKTIP_MIX = 'test/api/snake/blacktip_full_mix.json'
if decor.is_matilda():
    BLACKTIP_MIX = 'test/api/snake/matilda_regular_mix.json'
PKT_SIZE = 500
PKT_COUNT = 10


@unittest.skipUnless(decor.is_hw_device(), "Requires HW device")
@unittest.skipUnless(decor.is_hw_gibraltar(), "Only-GB-HW")
class block_ingress_data_test(unittest.TestCase):
    def setUp(self):
        self.snake = snake_standalone.snake_base_topology()
        self.snake.set_default_args()
        self.traffic_enabled = False
        self.sockets = snake_standalone.NUM_SLICES_PER_DEVICE * [None]

    def tearDown(self):
        # Check for notifications
        n_lists = self.snake.mph.read_notifications(2)
        # Count non-link notifications, e.g. MEM_PROTECT, OTHER, ...
        non_link_notifications = 0
        for note_list in n_lists:
            for note_desc in note_list:
                print('Notification: {}'.format(self.snake.debug_device.notification_to_string(note_desc)))
                non_link_notifications += (note_desc.type != sdk.la_notification_type_e_LINK)

        self.snake.teardown()
        # TODO: cleanup and un-comment the following check
        # self.assertEqual(non_link_notifications, 0)

    def test_block_ingress_data(self):
        self.snake.args.board_cfg_path = BLACKTIP_BOARD_TYPE
        self.snake.args.loop_mode = 'serdes'
        self.snake.args.json_mix = BLACKTIP_MIX
        self.snake.args.punt_traf = True

        self.snake.run_snake()
        first_mp = self.snake.mph.mac_ports[0]

        mp_count = len(self.snake.mph.mac_ports)
        blocked_mp_i = int(mp_count / 2)
        blocked_mp = self.snake.mph.mac_ports[blocked_mp_i]
        blocked_mp.set_block_ingress_data(True)

        self.snake.send_traffic_to_port(
            first_mp.get_slice(),
            first_mp.get_ifg(),
            first_mp.get_first_serdes_id(),
            first_mp.get_first_pif_id(),
            packet_count=PKT_COUNT,
            packet_size=PKT_SIZE)
        time.sleep(0.1)
        first_mac_info = self.snake.mph.get_mac_stats(0, clear_on_read=False)
        blocked_mac_info = self.snake.mph.get_mac_stats(blocked_mp_i, clear_on_read=False)
        next_to_blocked_mac_info = self.snake.mph.get_mac_stats(blocked_mp_i + 1, clear_on_read=False)

        # Last Port to receive anything is the blocked port
        self.assertEqual(blocked_mac_info['rx_frames'], PKT_COUNT)
        self.assertEqual(blocked_mac_info['tx_frames'], PKT_COUNT)
        self.assertEqual(next_to_blocked_mac_info['rx_frames'], 0)
        self.assertEqual(next_to_blocked_mac_info['tx_frames'], 0)

        self.snake.mph.clear_mac_stats()

        blocked_mp.set_block_ingress_data(False)
        self.snake.send_traffic_to_port(
            first_mp.get_slice(),
            first_mp.get_ifg(),
            first_mp.get_first_serdes_id(),
            first_mp.get_first_pif_id(),
            packet_count=PKT_COUNT,
            packet_size=PKT_SIZE)
        time.sleep(0.1)
        self.snake.get_traffic_from_port(
            first_mp.get_slice(),
            first_mp.get_ifg(),
            first_mp.get_first_serdes_id(),
            packet_count=PKT_COUNT,
            packet_size=PKT_SIZE)
        self.check_mac_stats()

    def check_mac_stats(self):
        mac_info = self.snake.mph.get_mac_stats(0, clear_on_read=False)
        expected_packets = mac_info['rx_frames']
        expected_bytes = expected_packets * PKT_SIZE

        for index in range(len(self.snake.mph.network_mac_ports)):
            mac_info = self.snake.mph.get_mac_stats(index)
            print(
                'Link [{index}] name {name}, FC {fc_mode}, FEC {fec_mode}, (slice {slice}, IFG {ifg}, SerDes {serdes}), '
                'Rx {rx_frames} {rx_bytes}, Tx {tx_frames} {tx_bytes}, Tx CRC {tx_crc_err}, Tx Underrun {tx_underrun_err}, '
                'Uncorrectable {uncorrectable}, Correctable {correctable}'.format(
                    **mac_info))
            self.assertEqual(mac_info['rx_frames'], expected_packets)
            self.assertEqual(mac_info['rx_bytes'], expected_bytes)
            self.assertEqual(mac_info['tx_frames'], expected_packets)
            self.assertEqual(mac_info['tx_bytes'], expected_bytes)


if __name__ == '__main__':
    unittest.main()
