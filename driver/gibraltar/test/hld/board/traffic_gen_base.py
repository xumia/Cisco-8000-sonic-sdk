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

from snake_standalone import snake_base_topology
from xena_connector import *

NUM_OF_STREAMS = 1
MIN_PACKET_SIZE = 500  # in bytes
MAX_PACKET_SIZE = 500
RATE_PERCENTAGE = 99
GEN_TYPE = "RANDOM"
DMAC = "000000000000"
SMAC = "04F4BC57C880"
TYPE = "8100"
VLAN = "0100"
SIZE = "01F4"
DATA = "4500002A000000007FFF3AD60000000000000000"
PKT = "0x" + DMAC + SMAC + TYPE + VLAN + SIZE + DATA
PROGRESS_DELAY = 0.1


class traffic_gen_base(unittest.TestCase):
    class args_struct():
        pass

    def init(self,
             path,
             board,
             xena_ip,
             xena_port,
             json_mix,
             params_json,
             module_type,
             loop_mode,
             p2p_ext,
             protocol):
        self.snake = snake_base_topology()
        self.snake.args = self.args_struct()
        self.snake.args.loop_mode = loop_mode
        self.snake.args.p2p_ext = p2p_ext
        self.snake.args.protocol = protocol
        self.snake.args.json_mix = json_mix
        self.snake.args.params_json = params_json
        self.snake.args.module_type = module_type
        self.snake.args.fc = 'none'
        self.snake.args.loop_fec = 'rs-kr4'
        self.snake.args.device_frequency = None

        self.snake.init(path, 0, board)
        self.snake.run_snake()
        self.xena = xena_connector(xena_ip, xena_port)
        self.xena.add_data_streams(NUM_OF_STREAMS, GEN_TYPE, MIN_PACKET_SIZE, MAX_PACKET_SIZE, RATE_PERCENTAGE, PKT)

    def check_mac_fec(self, mac_ports):
        for index, mp in enumerate(mac_ports):
            codeword_uncorrectable = mp.read_counter(mp.counter_e_FEC_UNCORRECTABLE)
            self.assertEqual(codeword_uncorrectable, 0, 'mac port index {}'.format(index))

    def check_mac_stats(self, mac_ports, xena_tx_frames):
        for index in range(len(mac_ports)):
            mac_info = self.snake.mph.get_mac_stats(index, False)
            self.assertEqual(xena_tx_frames, mac_info['tx_frames'], 'mac port index {}'.format(index))
            self.assertEqual(mac_info['rx_frames'], mac_info['tx_frames'], 'mac port index {}'.format(index))
            self.assertEqual(mac_info['rx_bytes'], mac_info['tx_bytes'], 'mac port index {}'.format(index))

    # if progress is True: function check if there is packet progress
    # if progress is False: function check if traffic stopped
    def check_mac_progress(self, mac_ports, progress):
        mac_info1 = []
        for index in range(len(mac_ports)):
            mac_info1.append(self.snake.mph.get_mac_stats(index, False))

        time.sleep(PROGRESS_DELAY)
        mac_info2 = []
        for index in range(len(mac_ports)):
            mac_info2.append(self.snake.mph.get_mac_stats(index, False))
            self.assertEqual(mac_info1[index]['rx_frames'] != mac_info2[index]
                             ['rx_frames'], progress, 'mac port index {}'.format(index))
            self.assertEqual(mac_info1[index]['tx_frames'] != mac_info2[index]
                             ['tx_frames'], progress, 'mac port index {}'.format(index))
