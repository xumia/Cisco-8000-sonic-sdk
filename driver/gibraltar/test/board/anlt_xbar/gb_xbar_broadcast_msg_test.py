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

LT_MSG_RESET = 0x300
LT_MSG_GEN_CFG = 0x301
LT_MSG_TX_MSG_DATA0 = 0x302
LT_MSG_TX_MSG_DATA1 = 0x303
LT_MSG_TX_FIFO_STATUS = 0x304
LT_MSG_RX_FIFO_STATUS = 0x305
LT_MSG_RX_MSG_POP = 0x306
LT_MSG_RX_MSG_STATUS = 0x307
LT_MSG_RX_MSG_DATA0 = 0x308
LT_MSG_RX_MSG_DATA1 = 0x309

LT_CHANNEL_OFFSET = 0X20
LT_PATTERN = 0xf0f0
ANLT_TEST_SLICE_START = 0
ANLT_TEST_SLICE_END = 6
ANLT_TEST_IFG_START = 0
ANLT_TEST_IFG_END = 2
ANLT_TEST_SERDES_START = 0
ANLT_TEST_SERDES_END = 24

DEBUG = 1


class gb_xbar_broadcast_msg_test():
    def __init__(self, la_device):
        self.dev = la_device

    def enable_anlt_msg(self, die, channel):
        srmcli.srm_reg_write(die, LT_MSG_GEN_CFG + channel * LT_CHANNEL_OFFSET, 0x3)
        srmcli.srm_reg_write(die, LT_MSG_RESET + channel * LT_CHANNEL_OFFSET, 0x303)
        srmcli.srm_reg_write(die, LT_MSG_RESET + channel * LT_CHANNEL_OFFSET, 0x0)

    def write_anlt_msg(self, die, channel, tx_msg_lsb, tx_msg_msb):
        srmcli.srm_reg_write(die, LT_MSG_TX_MSG_DATA0 + channel * LT_CHANNEL_OFFSET, tx_msg_lsb)
        srmcli.srm_reg_write(die, LT_MSG_TX_MSG_DATA1 + channel * LT_CHANNEL_OFFSET, tx_msg_msb)
        if (DEBUG):
            print("Writing 0x%04x/%d Tx -> Rx msg 0x%04x%04x" % (die, channel, tx_msg_msb, tx_msg_lsb))

    def read_rx_msg_status(self, die, channel):
        data_r = srmcli.srm_reg_read(die, LT_MSG_RX_MSG_STATUS + channel * LT_CHANNEL_OFFSET)
        return data_r

    def read_rx_msg(self, die, channel):
        status = self.read_rx_msg_status(die, channel)
        if (status == 3):
            if (DEBUG):
                print("Got error while receiving valid msg. Clear it.")
                rx_msg_lsb = srmcli.srm_reg_read(die, LT_MSG_RX_MSG_DATA0 + channel * LT_CHANNEL_OFFSET)
                rx_msg_msb = srmcli.srm_reg_read(die, LT_MSG_RX_MSG_DATA1 + channel * LT_CHANNEL_OFFSET)
                print('Reading Tx -> Rx msg 0x%04x%04x' % (rx_msg_msb, rx_msg_lsb))
            self.clear_rx_msg(die, channel)
        elif (status == 1):
            depth = srmcli.srm_reg_read(die, LT_MSG_RX_FIFO_STATUS + channel * LT_CHANNEL_OFFSET)
            if (depth >> 2):
                rx_msg_lsb = srmcli.srm_reg_read(die, LT_MSG_RX_MSG_DATA0 + channel * LT_CHANNEL_OFFSET)
                rx_msg_msb = srmcli.srm_reg_read(die, LT_MSG_RX_MSG_DATA1 + channel * LT_CHANNEL_OFFSET)
                if (DEBUG):
                    print('Reading Tx -> Rx msg 0x%04x%04x, FIFO Depth %d' % (rx_msg_msb, rx_msg_lsb, depth >> 2))
                return 0, rx_msg_msb, rx_msg_lsb
            else:
                print("Valid status but No msg. Shouldn't be here")
        elif (status == 2):
            print('Got error, invalid status')
        else:
            print('No msg')
        return status, 0, 0

    def clear_rx_msg(self, die, channel):
        srmcli.srm_reg_write(die, LT_MSG_RX_MSG_POP + channel * LT_CHANNEL_OFFSET, 0x1)

    def clear_rx_msg_in_fifo(self, die, channel):
        while True:
            data = srmcli.srm_reg_read(die, LT_MSG_RX_FIFO_STATUS + channel * LT_CHANNEL_OFFSET)
            if (DEBUG):
                print("Read RX FIFO 0x%x/%d status - 0x%x" % (die, channel, data))
            if (data >> 2):
                self.clear_rx_msg(die, channel)
            else:
                break

    def anlt_lt_broadcast_msg_test(self, srd_num):
        print("Testing anlt_lt_broadcast_msg =============== ")
        for slice_id in range(6):
            for ifg_id in range(2):
                num_serdes = self.dev.get_num_of_serdes(slice_id, ifg_id)
                for serdes in range(24):
                    if (serdes >= num_serdes):
                        break
                    die = self.dev.get_serdes_addr(slice_id, ifg_id, serdes, sdk.la_serdes_direction_e_TX)
                    channel = serdes % 2
                    if (DEBUG):
                        print('Before ANLT enabled ::')
                    self.clear_rx_msg_in_fifo(die, channel)

                    self.enable_anlt_msg(die, channel)
                    if (DEBUG):
                        print('After ANLT enabled ::')
                    self.clear_rx_msg_in_fifo(die, channel)

        for slice_id in range(6):
            for ifg_id in range(2):
                num_serdes = self.dev.get_num_of_serdes(slice_id, ifg_id)
                for serdes in range(24):
                    if (serdes >= num_serdes):
                        break
                    test_pattern = (slice_id << 12) | (ifg_id << 8) | (serdes)
                    if ((serdes % srd_num) == 0):
                        channel = self.dev.get_serdes_source(slice_id, ifg_id)[serdes] % 2
                        die = self.dev.get_serdes_addr(slice_id, ifg_id, serdes, sdk.la_serdes_direction_e_RX)
                        self.write_anlt_msg(die, channel, test_pattern, LT_PATTERN)

        for slice_id in range(6):
            for ifg_id in range(2):
                num_serdes = self.dev.get_num_of_serdes(slice_id, ifg_id)
                for serdes in range(24):
                    if (serdes >= num_serdes):
                        break
                    exp = (slice_id << 12) | (ifg_id << 8) | (int(serdes / srd_num) * srd_num)

                    die = self.dev.get_serdes_addr(slice_id, ifg_id, serdes, sdk.la_serdes_direction_e_RX)
                    channel = self.dev.get_serdes_source(slice_id, ifg_id)[serdes] % 2
                    if (DEBUG):
                        print("TEST:: LT MSG RX - die 0x%x channel %d" % (die, channel))
                    status, rx_msb, rx_lsb = self.read_rx_msg(die, channel)
                    if (status == 3):
                        if (DEBUG):
                            print('read again after clear error')
                        status, rx_msb, rx_lsb = self.read_rx_msg(die, channel)
                    if (DEBUG):
                        print("\n")
                    assert rx_msb == LT_PATTERN
                    assert rx_lsb == exp
        print("End anlt_lt_broadcast_msg testing : Pass =============== ")
