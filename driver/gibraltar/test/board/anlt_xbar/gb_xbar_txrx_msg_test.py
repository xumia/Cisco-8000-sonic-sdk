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


import srmcli
from gb_anlt_base import *

TX_ANLT_MSG_RESET = 0x4a00
TX_ANLT_MSG_GEN_CFG = 0x4a01
TX_ANLT_MSG_TX_MSG_DATA0 = 0x4a02
TX_ANLT_MSG_TX_MSG_DATA1 = 0x4a03
TX_ANLT_MSG_TX_FIFO_STATUS = 0x4a04
TX_ANLT_MSG_RX_FIFO_STATUS = 0x4a05
TX_ANLT_MSG_RX_MSG_POP = 0x4a06
TX_ANLT_MSG_RX_MSG_STATUS = 0x4a07
TX_ANLT_MSG_RX_MSG_DATA0 = 0x4a08
TX_ANLT_MSG_RX_MSG_DATA1 = 0x4a09

RX_ANLT_MSG_RESET = 0x2b00
RX_ANLT_MSG_GEN_CFG = 0x2b01
RX_ANLT_MSG_TX_MSG_DATA0 = 0x2b02
RX_ANLT_MSG_TX_MSG_DATA1 = 0x2b03
RX_ANLT_MSG_TX_FIFO_STATUS = 0x2b04
RX_ANLT_MSG_RX_FIFO_STATUS = 0x2b05
RX_ANLT_MSG_RX_MSG_POP = 0x2b06
RX_ANLT_MSG_RX_MSG_STATUS = 0x2b07
RX_ANLT_MSG_RX_MSG_DATA0 = 0x2b08
RX_ANLT_MSG_RX_MSG_DATA1 = 0x2b09

ANLT_MSG_RESET = RX_ANLT_MSG_RESET
ANLT_MSG_GEN_CFG = RX_ANLT_MSG_GEN_CFG
ANLT_MSG_TX_MSG_DATA0 = RX_ANLT_MSG_TX_MSG_DATA0
ANLT_MSG_TX_MSG_DATA1 = RX_ANLT_MSG_TX_MSG_DATA1
ANLT_MSG_TX_FIFO_STATUS = RX_ANLT_MSG_TX_FIFO_STATUS
ANLT_MSG_RX_FIFO_STATUS = RX_ANLT_MSG_RX_FIFO_STATUS
ANLT_MSG_RX_MSG_POP = RX_ANLT_MSG_RX_MSG_POP
ANLT_MSG_RX_MSG_STATUS = RX_ANLT_MSG_RX_MSG_STATUS
ANLT_MSG_RX_MSG_DATA0 = RX_ANLT_MSG_RX_MSG_DATA0
ANLT_MSG_RX_MSG_DATA1 = RX_ANLT_MSG_RX_MSG_DATA1

TXRX_CHANNEL_OFFSET = 0x800
RX_TO_TX_OFFSET = 0x1f00
RX_DIR = 0
TX_DIR = 1

NUM_SERDES_PER_QUAD = 4
ANLT_TEST_SLICE_START = 0
ANLT_TEST_SLICE_END = 6
ANLT_TEST_IFG_START = 0
ANLT_TEST_IFG_END = 2
ANLT_TEST_SERDES_START = 0
ANLT_TEST_SERDES_END = 24


TX_TO_RX_PATTERN = 0x5A5A
RX_TO_TX_PATTERN = 0xA5A5

dir_msg = ['RX', 'TX']
DEBUG = 1


class gb_xbar_txrx_msg_test():
    def __init__(self, la_device):
        self.dev = la_device
        self.lld = self.dev.get_ll_device()
        self.pt = self.lld.get_gibraltar_tree()

    def txrx_enable_anlt_msg(self, die, channel, dir):
        srmcli.srm_reg_write(die, ANLT_MSG_GEN_CFG + dir * RX_TO_TX_OFFSET + channel * TXRX_CHANNEL_OFFSET, 0x3)
        srmcli.srm_reg_write(die, ANLT_MSG_RESET + dir * RX_TO_TX_OFFSET + channel * TXRX_CHANNEL_OFFSET, 0x303)
        srmcli.srm_reg_write(die, ANLT_MSG_RESET + dir * RX_TO_TX_OFFSET + channel * TXRX_CHANNEL_OFFSET, 0x0)

    def txrx_write_anlt_msg(self, die, channel, tx_msg_lsb, tx_msg_msb, dir):
        srmcli.srm_reg_write(die, ANLT_MSG_TX_MSG_DATA0 + dir * RX_TO_TX_OFFSET + channel * TXRX_CHANNEL_OFFSET, tx_msg_lsb)
        srmcli.srm_reg_write(die, ANLT_MSG_TX_MSG_DATA1 + dir * RX_TO_TX_OFFSET + channel * TXRX_CHANNEL_OFFSET, tx_msg_msb)
        if (DEBUG):
            print("Dir %s :Writing tx msg 0x%04x%04x" % (dir_msg[dir], tx_msg_msb, tx_msg_lsb))

    def txrx_read_rx_msg_status(self, die, channel, dir):
        data_r = srmcli.srm_reg_read(die, ANLT_MSG_RX_MSG_STATUS + dir * RX_TO_TX_OFFSET + channel * TXRX_CHANNEL_OFFSET)
        return data_r

    def txrx_read_rx_msg(self, die, channel, dir):
        status = self.txrx_read_rx_msg_status(die, channel, dir)
        if (status == 3):
            if (DEBUG):
                print("Got error while receiving valid msg. Clear it.")
            self.txrx_clear_rx_msg(die, channel, dir)
        elif (status == 1):
            depth = srmcli.srm_reg_read(die, ANLT_MSG_RX_FIFO_STATUS + dir * RX_TO_TX_OFFSET + channel * TXRX_CHANNEL_OFFSET)
            if (depth >> 2):
                rx_msg_lsb = srmcli.srm_reg_read(die, ANLT_MSG_RX_MSG_DATA0 + dir * RX_TO_TX_OFFSET + channel * TXRX_CHANNEL_OFFSET)
                rx_msg_msb = srmcli.srm_reg_read(die, ANLT_MSG_RX_MSG_DATA1 + dir * RX_TO_TX_OFFSET + channel * TXRX_CHANNEL_OFFSET)
                if (DEBUG):
                    print("Dir %s :Reading Rx msg 0x%04x%04x, FIFO Depth %d" % (dir_msg[dir], rx_msg_msb, rx_msg_lsb, depth >> 2))
                return 0, rx_msg_msb, rx_msg_lsb
            else:
                print("Valid status but No msg. Shouldn't be here")
        elif (status == 2):
            print('Got error, invalid status')
        else:
            print('No msg')
        return status, 0, 0

    def txrx_clear_rx_msg(self, die, channel, dir):
        srmcli.srm_reg_write(die, ANLT_MSG_RX_MSG_POP + dir * RX_TO_TX_OFFSET + channel * TXRX_CHANNEL_OFFSET, 0x1)

    def txrx_clear_rx_msg_in_fifo(self, die, channel, dir):
        while True:
            data = srmcli.srm_reg_read(die, ANLT_MSG_RX_FIFO_STATUS + dir * RX_TO_TX_OFFSET + channel * TXRX_CHANNEL_OFFSET)
            if (DEBUG):
                print("Dir %s :Read RX FIFO %d/%d status - 0x%x" % (dir_msg[dir], die, channel, data))
            if (data >> 2):
                self.txrx_clear_rx_msg(die, channel, dir)
            else:
                break

    def get_txrx_source_test_pattern(self, slice_id, ifg_id, serdes, source_dir):
        pool = self.pt.slice[slice_id].ifg[ifg_id]
        if (self.dev.get_num_of_serdes(slice_id, ifg_id) == 24):
            if (source_dir):
                reg = self.lld.read_register(pool.serdes_pool24.serdes_tx_lane_swap_config)
            else:
                reg = self.lld.read_register(pool.serdes_pool24.serdes_rx_lane_swap_config)
        else:
            if (source_dir):
                reg = self.lld.read_register(pool.serdes_pool16.serdes_tx_lane_swap_config)
            else:
                reg = self.lld.read_register(pool.serdes_pool16.serdes_rx_lane_swap_config)
        serdes_idx = (reg >> (serdes << 1)) & 0x3
        remote_serdes = int(serdes / 4) * 4 + serdes_idx
        exp_pattern = (slice_id << 12) | (ifg_id << 8) | remote_serdes
        return exp_pattern

    def txrx_anlt_lt_msg_test(self):
        '''
        ANLT LT Tx2Rx & Rx2Tx point to point Messaging.
        Message in pattern of :
        MSB: [15:12] - slice_id [11:8] - ifg_id [7:0]  - serdes
        LSB: Tx2Rx - 0x5a5a; Rx2Tx - 0xa5a5
        '''

        print("Testing txrx_anlt_lt_msg_test =============== ")
        for slice_id in range(6):
            for ifg_id in range(2):
                num_serdes = self.dev.get_num_of_serdes(slice_id, ifg_id)
                for serdes in range(ANLT_TEST_SERDES_START, ANLT_TEST_SERDES_END):
                    if (serdes >= num_serdes):
                        break
                    die = self.dev.get_serdes_addr(slice_id, ifg_id, serdes, sdk.la_serdes_direction_e_TX)
                    channel = serdes % 2
                    if (DEBUG):
                        print('Before ANLT enabled ::')
                    self.txrx_clear_rx_msg_in_fifo(die, channel, RX_DIR)
                    self.txrx_clear_rx_msg_in_fifo(die, channel, TX_DIR)

                    self.txrx_enable_anlt_msg(die, channel, RX_DIR)
                    self.txrx_enable_anlt_msg(die, channel, TX_DIR)

                    if (DEBUG):
                        print('After ANLT enabled ::')
                    self.txrx_clear_rx_msg_in_fifo(die, channel, RX_DIR)
                    self.txrx_clear_rx_msg_in_fifo(die, channel, TX_DIR)

        for slice_id in range(6):
            for ifg_id in range(2):
                if (DEBUG):
                    print("\nSlice %d IFG %d :" % (slice_id, ifg_id))
                num_serdes = self.dev.get_num_of_serdes(slice_id, ifg_id)
                for serdes in range(ANLT_TEST_SERDES_START, ANLT_TEST_SERDES_END):
                    if (serdes >= num_serdes):
                        break
                    die = self.dev.get_serdes_addr(slice_id, ifg_id, serdes, sdk.la_serdes_direction_e_TX)
                    channel = serdes % 2
                    test_pattern = (slice_id << 12) | (ifg_id << 8) | (serdes)
                    self.txrx_write_anlt_msg(die, channel, TX_TO_RX_PATTERN, test_pattern, TX_DIR)
                    self.txrx_write_anlt_msg(die, channel, RX_TO_TX_PATTERN, test_pattern, RX_DIR)

        for slice_id in range(6):
            for ifg_id in range(2):
                num_serdes = self.dev.get_num_of_serdes(slice_id, ifg_id)
                for serdes in range(ANLT_TEST_SERDES_START, ANLT_TEST_SERDES_END):
                    if (serdes >= num_serdes):
                        break
                    die = self.dev.get_serdes_addr(slice_id, ifg_id, serdes, sdk.la_serdes_direction_e_TX)
                    channel = serdes % 2
                    if (DEBUG):
                        print("\nTEST:: LT MSG - die 0x%x channel %d" % (die, channel))

                        print("From Rx -> Tx ------")
                    sts, rx_msb, rx_lsb = self.txrx_read_rx_msg(die, channel, TX_DIR)
                    if (sts == 3):
                        sts, rx_msb, rx_lsb = self.txrx_read_rx_msg(die, channel, TX_DIR)
                    exp = self.get_txrx_source_test_pattern(slice_id, ifg_id, serdes, RX_DIR)
                    assert rx_msb == exp
                    assert rx_lsb == RX_TO_TX_PATTERN

                    if (DEBUG):
                        print("From Tx -> Rx ------")
                    sts, rx_msb, rx_lsb = self.txrx_read_rx_msg(die, channel, RX_DIR)
                    if (sts == 3):
                        sts, rx_msb, rx_lsb = self.txrx_read_rx_msg(die, channel, RX_DIR)
                    exp = self.get_txrx_source_test_pattern(slice_id, ifg_id, serdes, TX_DIR)
                    assert rx_msb == exp
                    assert rx_lsb == TX_TO_RX_PATTERN
        print("End txrx_anlt_lt_msg_test testing : Pass =============== ")
