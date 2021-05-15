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
from leaba import debug
import itertools

SRM_LT_MSG_STATUS_TX_CHN0 = 0x312
SRM_LT_MSG_STATUS_TX_CHN1 = 0x332

SRM_LT_MSG_STATUS_RX_CHN0 = 0x313
SRM_LT_MSG_STATUS_RX_CHN1 = 0x333

BIT_CLR = 0
BIT_SET = 1
DEBUG = 1


class gb_xbar_status_test():
    def __init__(self, la_device):
        self.dev = la_device
        self.dd = debug.debug_device(self.dev)

    def config_an_clr(self):
        for slice_id in range(6):
            for ifg_id in range(2):
                if (self.dev.get_num_of_serdes(slice_id, ifg_id) == 24):
                    self.dd.write_register(
                        self.pt.slice[slice_id].ifg[ifg_id].serdes_pool24.serdes_an_master_config,
                        0xFAC688FAC688FAC688)
                    self.dd.write_register(self.pt.slice[slice_id].ifg[ifg_id].serdes_pool24.serdes_an_bitmap_config, 0x0)
                else:
                    self.dd.write_register(
                        self.pt.slice[slice_id].ifg[ifg_id].serdes_pool16.serdes_an_master_config,
                        0xFAC688FAC688)
                    self.dd.write_register(self.pt.slice[slice_id].ifg[ifg_id].serdes_pool16.serdes_an_bitmap_config, 0x0)

    def read_tx_sts(self, slice, ifg, start_serdes, serdes_num):
        for ii in range(start_serdes, start_serdes + serdes_num):
            die_id = self.dev.get_serdes_addr(slice, ifg, ii, sdk.la_serdes_direction_e_RX)
            channel = self.dev.get_serdes_source(slice, ifg)[ii]
            if (channel % 2):
                print(srmcli.srm_reg_read(die_id, SRM_LT_MSG_STATUS_TX_CHN1))
            else:
                print(srmcli.srm_reg_read(die_id, SRM_LT_MSG_STATUS_TX_CHN0))

    def read_rx_sts(self, slice, ifg, start_serdes, serdes_num):
        for ii in range(start_serdes, start_serdes + serdes_num):
            die_id = self.dev.get_serdes_addr(slice, ifg, ii, sdk.la_serdes_direction_e_RX)
            channel = self.dev.get_serdes_source(slice, ifg)[ii]
            if (channel % 2):
                print(srmcli.srm_reg_read(die_id, SRM_LT_MSG_STATUS_RX_CHN1))
            else:
                print(srmcli.srm_reg_read(die_id, SRM_LT_MSG_STATUS_RX_CHN0))

    def write_tx_sts(self, slice, ifg, start_serdes, serdes_num, data):
        for ii in range(start_serdes, start_serdes + serdes_num):
            die_id = self.dev.get_serdes_addr(slice, ifg, ii, sdk.la_serdes_direction_e_RX)
            channel = self.dev.get_serdes_source(slice, ifg)[ii]
            if (channel % 2):
                srmcli.srm_reg_write(die_id, SRM_LT_MSG_STATUS_TX_CHN1, data)
            else:
                srmcli.srm_reg_write(die_id, SRM_LT_MSG_STATUS_TX_CHN0, data)

    def check_rx_serdes_err(self, slice, ifg, srd):
        die_id = self.dev.get_serdes_addr(slice, ifg, srd, sdk.la_serdes_direction_e_RX)
        channel = self.dev.get_serdes_source(slice, ifg)[srd]
        if (channel % 2):
            data0 = srmcli.srm_reg_read(die_id, SRM_LT_MSG_STATUS_RX_CHN1)
        else:
            data0 = srmcli.srm_reg_read(die_id, SRM_LT_MSG_STATUS_RX_CHN0)
        err = data0 >> 1
        if (err):
            if (DEBUG):
                print("Got error - %1d/%1d/%1d" % (slice, ifg, srd))
            return 1
        else:
            if (DEBUG):
                print("No error - %1d/%1d/%1d" % (slice, ifg, srd))
            return 0

    def check_rx_serdes_done(self, slice, ifg, srd):
        die_id = self.dev.get_serdes_addr(slice, ifg, srd, sdk.la_serdes_direction_e_RX)
        channel = self.dev.get_serdes_source(slice, ifg)[srd]
        if (channel % 2):
            data0 = srmcli.srm_reg_read(die_id, SRM_LT_MSG_STATUS_RX_CHN1)
        else:
            data0 = srmcli.srm_reg_read(die_id, SRM_LT_MSG_STATUS_RX_CHN0)
        done = data0 & 1
        if (done):
            if (DEBUG):
                print("Done set - %1d/%1d/%1d" % (slice, ifg, srd))
            return 1
        else:
            if (DEBUG):
                print("Done not set - %1d/%1d/%1d" % (slice, ifg, srd))
            return 0

    def check_rx_bundle_err(self, slice, ifg, srd, srd_num, exp):
        err = 1
        for ii in range(srd, srd + srd_num):
            die_id = self.dev.get_serdes_addr(slice, ifg, ii, sdk.la_serdes_direction_e_RX)
            channel = self.dev.get_serdes_source(slice, ifg)[ii]
            if (channel % 2):
                data0 = srmcli.srm_reg_read(die_id, SRM_LT_MSG_STATUS_RX_CHN1)
            else:
                data0 = srmcli.srm_reg_read(die_id, SRM_LT_MSG_STATUS_RX_CHN0)
            err &= ((data0 >> 1) == exp)
        if (err):
            if (DEBUG):
                print("Error status: Expect %1d, all match - %1d/%1d/%1d" % (exp, slice, ifg, srd))
            return 1
        else:
            if (DEBUG):
                print("Error status: Expect %1d, not match - %1d/%1d/%1d" % (exp, slice, ifg, srd))
            return 0

    def check_rx_bundle_done(self, slice, ifg, srd, srd_num, exp):
        done = 1
        for ii in range(srd, srd + srd_num):
            die_id = self.dev.get_serdes_addr(slice, ifg, ii, sdk.la_serdes_direction_e_RX)
            channel = self.dev.get_serdes_source(slice, ifg)[ii]
            if (channel % 2):
                data0 = srmcli.srm_reg_read(die_id, SRM_LT_MSG_STATUS_RX_CHN1)
            else:
                data0 = srmcli.srm_reg_read(die_id, SRM_LT_MSG_STATUS_RX_CHN0)
            done &= ((data0 & 1) == exp)
        if (done):
            if (DEBUG):
                print("Done status: Expect %1d, all match - %1d/%1d/%1d" % (exp, slice, ifg, srd))
            return 1
        else:
            if (DEBUG):
                print("Done status: Expect %1d, not match - % 1d/% 1d/% 1d" % (exp, slice, ifg, srd))
            return 0

    def clear_before_test(self):
        for slice_id in range(6):
            for ifg_id in range(2):
                srd = self.dev.get_num_of_serdes(slice_id, ifg_id)
                self.write_tx_sts(slice_id, ifg_id, 0, srd, 0)

    def test_done_status(self, serdes_num):
        '''
        Done bit status testing.
        Set Done status on all SerDes in the ANLT group and check status change on the Rx master.
        Any one of the SerDes in the group clear Done, master clear Done.

        Example of test procedure:
        config_an_serdes8()
        clear_before_test()
        test_done_status(SERDES_G8)
        '''

        print("Testing done_status =============== ")
        for slice_id in range(6):
            for ifg_id in range(2):
                ifg_srd = self.dev.get_num_of_serdes(slice_id, ifg_id)
                for srd in range(ifg_srd):
                    if (srd % serdes_num == 0):
                        print("========== Serdes % d ============" % (srd))
                        self.write_tx_sts(slice_id, ifg_id, srd, serdes_num, 1)

                        sts = self.check_rx_bundle_done(slice_id, ifg_id, srd, serdes_num, BIT_SET)
                        assert sts == 1
                        for ii in itertools.chain(range(srd), range(srd + serdes_num, ifg_srd)):
                            sts = self.check_rx_serdes_done(slice_id, ifg_id, ii)
                            assert sts == 0

                        for ii in range(srd, srd + serdes_num):
                            self.write_tx_sts(slice_id, ifg_id, ii, 1, 0)
                            sts = self.check_rx_bundle_done(slice_id, ifg_id, srd, serdes_num, BIT_CLR)
                            assert sts == 1

                        self.write_tx_sts(slice_id, ifg_id, 0, ifg_srd, 0)
        print("End done_status testing : Pass =============== ")

    def test_error_status(self, serdes_num):
        '''
        Error bit status testing.
        Set Error status on any SerDes in the ANLT group and check status change on the Rx master.
        Any one of the SerDes in the group set Error, master set Error.

        Example of test procedure:
        config_an_serdes8()
        clear_before_test()
        test_error_status(SERDES_G8)
        '''

        print("Testing error_status =============== ")
        for slice_id in range(6):
            for ifg_id in range(2):
                ifg_srd = self.dev.get_num_of_serdes(slice_id, ifg_id)
                for srd in range(ifg_srd):
                    if (srd % serdes_num == 0):
                        print("========== Serdes % d ============" % (srd))
                        sts = self.check_rx_bundle_err(slice_id, ifg_id, srd, serdes_num, BIT_CLR)
                        assert sts == 1
                        for ii in range(serdes_num):
                            self.write_tx_sts(slice_id, ifg_id, srd + ii, 1, 2)
                            sts = self.check_rx_bundle_err(slice_id, ifg_id, srd, serdes_num, BIT_SET)
                            assert sts == 1

                            for jj in itertools.chain(range(srd), range(srd + serdes_num, ifg_srd)):
                                sts = self.check_rx_serdes_err(slice_id, ifg_id, jj)
                                assert sts == 0

                            self.write_tx_sts(slice_id, ifg_id, srd + ii, 1, 0)
                            sts = self.check_rx_bundle_err(slice_id, ifg_id, srd, serdes_num, BIT_CLR)
                            assert sts == 1

                            for jj in itertools.chain(range(srd), range(srd + serdes_num, ifg_srd)):
                                sts = self.check_rx_serdes_err(slice_id, ifg_id, jj)
                                assert sts == 0

        print("End error_status testing : Pass =============== ")
