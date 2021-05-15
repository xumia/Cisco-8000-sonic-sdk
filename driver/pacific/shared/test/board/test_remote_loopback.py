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

from ports_base import *
from spirent_connector import *
import decor
import time

NUM_STREAMS = 1
GEN_TYPE = "FIXED"
RATE_PERCENTAGE = 2
TRAFFIC_DELAY = 1
DWELL_UP_TIME = 30
# Test topology:

#                            TG
#  / --- \       / --- \     |
# |      |      |      |     v
# mp4   mp3    mp2    mp1    mp0
#  U     |     |       |     |
#         \-X- /       \ - - /

# NPU connection between mp2 and mp3 is disconnected in traffic_gen_mix_remote_loopback.json
# packets are expected to return to TG only when mp2 is set to remote loopback mode.


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_remote_loopback(ports_base):
    loop_mode = 'none'
    p2p_ext = True

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_remote_loopback(self):
        if decor.is_pacific():
            loopback_modes = [sdk.la_mac_port.loopback_mode_e_REMOTE_PMA]
        else:
            # TO DO: REMOTE PMA lb mode is unstable in GB, add it once it is stabilized
            loopback_modes = [sdk.la_mac_port.loopback_mode_e_REMOTE_SERDES]

        self.fill_args_from_env_vars('traffic_gen_mix_remote_loopback.json')
        self.snake.run_snake()
        self.open_spirent()
        self.snake.mph.wait_mac_ports_up(timeout=DWELL_UP_TIME)
        link_status = self.snake.mph.print_mac_up()
        self.assertTrue(link_status, 'one or more port links are down')

        self.spirent.add_data_streams(num_streams=NUM_STREAMS)
        stats = self.spirent.run_and_get_rx_tx(TRAFFIC_DELAY)

        tx_spirent_pck = stats['tx_packets']
        rx_spirent_pck = stats['rx_packets']

        self.assertGreater(tx_spirent_pck, 0, 'no packets were sent')
        self.assertEqual(rx_spirent_pck, 0, 'reached end of snake with no loopback, not expected to receive packets')

        self.spirent.clear_stream()

        for remote_loopback_mode in loopback_modes:
            last_mp = self.snake.mph.mac_ports[2]
            last_mp.set_loopback_mode(remote_loopback_mode)
            self.snake.mph.wait_for_mac_port_up(2)
            link_status = self.snake.mph.print_mac_up()
            self.assertTrue(link_status, 'link doesnt go up in loopback mode: {}'.format(remote_loopback_mode))

            self.spirent.add_data_streams(num_streams=NUM_STREAMS)

            stats = self.spirent.run_and_get_rx_tx(TRAFFIC_DELAY)

            tx_spirent_pck = stats['tx_packets']
            rx_spirent_pck = stats['rx_packets']

            self.assertGreater(tx_spirent_pck, 0, 'no packets were sent')
            self.assertEqual(
                tx_spirent_pck,
                rx_spirent_pck,
                'number of packet received doesnt match number of packets sent. sent:{}, received: {}'.format(
                    tx_spirent_pck,
                    rx_spirent_pck))

            self.spirent.clear_stream()


if __name__ == '__main__':
    unittest.main()
