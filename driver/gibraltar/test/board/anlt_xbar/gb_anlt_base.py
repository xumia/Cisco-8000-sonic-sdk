# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

from leaba import sdk
from leaba import debug
from snake_standalone import *
import argparse


LEABA_DEV_NAME = '/dev/uio'
BOARD = '../shared/examples/sanity/churchillP1_board_config.json'

NUM_SERDES_PER_QUAD = 4
ANLT_TEST_SLICE_START = 0
ANLT_TEST_SLICE_END = 6
ANLT_TEST_IFG_START = 0
ANLT_TEST_IFG_END = 2

WAIT_MAC_PORT_UP_DELAY = 10

SERDES_G8 = 8
SERDES_G4 = 4
SERDES_G2 = 2
SERDES_G1 = 1
DEBUG = False


class gb_anlt_base():

    def json_dir_set(self, serdes_group):
        return {
            8: "test/board/anlt_xbar/json/serdes_g8.json",
            4: "test/board/anlt_xbar/json/serdes_g4.json",
            2: "test/board/anlt_xbar/json/serdes_g2.json",
            1: "test/board/anlt_xbar/json/serdes_g1.json",
        }[serdes_group]

    def init_device(self, device_no=0, serdes_group=SERDES_G8):
        self.snake = snake_base_topology()
        self.snake.set_default_args()
        json_file = self.json_dir_set(serdes_group)
        self.snake.args.loop_mode = 'none'
        self.snake.args.json_mix = json_file
        self.snake.args.board_cfg_path = BOARD
        self.snake.args.debug_trace = DEBUG
        self.snake.run_snake()

        self.dev = self.snake.device
        self.dd = debug.debug_device(self.dev)
        self.mph = self.snake.mph
        self.lld = self.dev.get_ll_device()
        self.pt = self.lld.get_gibraltar_tree()

    def teardown_device(self):
        self.snake.teardown()

    def set_txrx_swap(self, cypher):
        key_1 = [0xe4, 0xb4, 0xd8, 0x78, 0x9c, 0x6c, 0xe1, 0xb1, 0xc9, 0x39, 0x8d, 0x2d,
                 0xd2, 0x72, 0xc6, 0x36, 0x4e, 0x1e, 0x93, 0x63, 0x87, 0x27, 0x4b, 0x1b]
        key_2 = [0xe4, 0xb4, 0xd8, 0x9c, 0x78, 0x6c, 0xe1, 0xb1, 0xd2, 0x93, 0x72, 0x63,
                 0xc9, 0x8d, 0xc6, 0x87, 0x4e, 0x4b, 0x39, 0x2d, 0x36, 0x27, 0x1e, 0x1b]
        pattern_1 = key_1[cypher]
        pattern_2 = key_2[cypher]
        for slice_id in range(ANLT_TEST_SLICE_START, ANLT_TEST_SLICE_END):
            for ifg_id in range(ANLT_TEST_IFG_START, ANLT_TEST_IFG_END):
                pool = self.pt.slice[slice_id].ifg[ifg_id]
                if (self.dev.get_num_of_serdes(slice_id, ifg_id) == 24):
                    cfg = (
                        pattern_1 << 40) | (
                        pattern_1 << 32) | (
                        pattern_1 << 24) | (
                        pattern_1 << 16) | (
                        pattern_1 << 8) | pattern_1
                    self.lld.write_register(pool.serdes_pool24.serdes_tx_lane_swap_config, cfg)
                    cfg = (
                        pattern_2 << 40) | (
                        pattern_2 << 32) | (
                        pattern_2 << 24) | (
                        pattern_2 << 16) | (
                        pattern_2 << 8) | pattern_2
                    self.lld.write_register(pool.serdes_pool24.serdes_rx_lane_swap_config, cfg)
                else:
                    cfg = (pattern_1 << 24) | (pattern_1 << 16) | (pattern_1 << 8) | pattern_1
                    self.lld.write_register(pool.serdes_pool16.serdes_tx_lane_swap_config, cfg)
                    cfg = (pattern_2 << 24) | (pattern_2 << 16) | (pattern_2 << 8) | pattern_2
                    self.lld.write_register(pool.serdes_pool16.serdes_rx_lane_swap_config, cfg)

    def get_serdes_tx_source(self, slice, ifg):
        serdes_num = self.dev.get_num_of_serdes(slice, ifg)
        tx_source = [0 for x in range(serdes_num)]
        rx_source = self.dev.get_serdes_source(slice, ifg)
        rx_serdes_index_ary = [0, 0, 0, 0]

        for serdes in range(serdes_num):
            start_serdes = int(serdes / NUM_SERDES_PER_QUAD) * NUM_SERDES_PER_QUAD
            for ii in range(NUM_SERDES_PER_QUAD):
                rx_serdes_index_ary[ii] = rx_source[start_serdes + ii] % NUM_SERDES_PER_QUAD
            for ii in range(NUM_SERDES_PER_QUAD):
                if (rx_serdes_index_ary[ii] == (serdes % NUM_SERDES_PER_QUAD)):
                    break
            tx_source[serdes] = ii
        return tx_source

    def set_txrx_swap_churchill(self):
        for slice_id in range(ANLT_TEST_SLICE_START, ANLT_TEST_SLICE_END):
            for ifg_id in range(ANLT_TEST_IFG_START, ANLT_TEST_IFG_END):
                pool = self.pt.slice[slice_id].ifg[ifg_id]
                rx_source = self.dev.get_serdes_source(slice_id, ifg_id)
                cfg = 0
                for serdes in range(self.dev.get_num_of_serdes(slice_id, ifg_id)):
                    cfg |= (rx_source[serdes] % NUM_SERDES_PER_QUAD) << (serdes << 1)
                if (self.dev.get_num_of_serdes(slice_id, ifg_id) == 24):
                    self.lld.write_register(pool.serdes_pool24.serdes_rx_lane_swap_config, cfg)
                else:
                    self.lld.write_register(pool.serdes_pool16.serdes_rx_lane_swap_config, cfg)

                tx_source = self.get_serdes_tx_source(slice_id, ifg_id)
                cfg = 0
                for serdes in range(self.dev.get_num_of_serdes(slice_id, ifg_id)):
                    cfg |= (tx_source[serdes] % NUM_SERDES_PER_QUAD) << (serdes << 1)
                if (self.dev.get_num_of_serdes(slice_id, ifg_id) == 24):
                    self.lld.write_register(pool.serdes_pool24.serdes_tx_lane_swap_config, cfg)
                else:
                    self.lld.write_register(pool.serdes_pool16.serdes_tx_lane_swap_config, cfg)

    def config_an_serdes(self, bundle_num):
        '''
        Configure master/bitmap into AN group of bundle_num SerDes
        '''
        for slice_id in range(6):
            for ifg_id in range(2):
                srd_num = self.dev.get_num_of_serdes(slice_id, ifg_id)
                master_cfg = 0
                bitmap_cfg = 0
                for ii in range(0, srd_num, bundle_num):
                    bitmap = 0
                    for jj in range(bundle_num):
                        serdes_idx = ii + jj
                        anlt_order = self.dev.get_serdes_anlt_order(slice_id, ifg_id)[serdes_idx]
                        srd = self.dev.get_serdes_source(slice_id, ifg_id)[anlt_order]
                        if (serdes_idx % bundle_num == 0):
                            mst = srd % SERDES_G8
                        bitmap |= 1 << (srd % 8)

                    for jj in range(bundle_num):
                        serdes_idx = ii + jj
                        anlt_order = self.dev.get_serdes_anlt_order(slice_id, ifg_id)[serdes_idx]
                        srd = self.dev.get_serdes_source(slice_id, ifg_id)[anlt_order]

                        master_cfg |= (mst << (3 * srd))
                        bitmap_cfg |= (bitmap << (8 * srd))

                if (srd_num == 24):
                    self.dd.write_register(self.pt.slice[slice_id].ifg[ifg_id].serdes_pool24.serdes_an_master_config, master_cfg)
                    self.dd.write_register(self.pt.slice[slice_id].ifg[ifg_id].serdes_pool24.serdes_an_bitmap_config, bitmap_cfg)
                else:
                    self.dd.write_register(self.pt.slice[slice_id].ifg[ifg_id].serdes_pool16.serdes_an_master_config, master_cfg)
                    self.dd.write_register(self.pt.slice[slice_id].ifg[ifg_id].serdes_pool16.serdes_an_bitmap_config, bitmap_cfg)


if __name__ == '__main__':
    tc = gb_anlt_base()
    parser = argparse.ArgumentParser(description='GB ANLT Xbar test configuration.')
    parser.add_argument('--mac_port', type=int, default=8, help='Serdes number in one Mac port.')
    args = parser.parse_args()
    mac_serdes_num = args.mac_port
    tc.init_device(0, mac_serdes_num)
    tc.config_an_serdes(mac_serdes_num)

    from gb_xbar_broadcast_msg_test import *
    tc.t1 = gb_xbar_broadcast_msg_test(tc.snake.device)
    # tc.t1.anlt_lt_broadcast_msg_test(mac_serdes_num)

    from gb_xbar_status_test import *
    tc.t2 = gb_xbar_status_test(tc.snake.device)
    # tc.t2.clear_before_test()
    # tc.t2.test_done_status(mac_serdes_num)
    # tc.t2.clear_before_test()
    # tc.t2.test_error_status(mac_serdes_num)

    from gb_xbar_txrx_msg_test import *
    tc.t3 = gb_xbar_txrx_msg_test(tc.snake.device)
    tc.set_txrx_swap_churchill()
    # tc.t3.txrx_anlt_lt_msg_test()
