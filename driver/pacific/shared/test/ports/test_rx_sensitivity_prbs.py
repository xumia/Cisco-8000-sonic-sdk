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

from leaba import sdk
import unittest
import time
import copy
from ports_test_base import *
import srmcli
import decor

RX_SENSITIVITY_RUN_TIME = 0.5
CLEANUP = 2
COUNT0  = 0
COUNT1  = 1
NA      = 3
TEST_STEP = 4


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class rx_sensitivity_prbs(ports_test_base):
    modes = ["1x50G_KP4"]

    def enable_rx_core_prbs_chk(self, mp):
        slice = mp.get_slice()
        ifg = mp.get_ifg()
        first_serdes = mp.get_first_serdes_id()
        num_serdes = mp.get_num_of_serdes()
        dev = mp.get_device()
        chk_rules = srmcli.srm_prbs_chk_rules_t()
        chk_rules.core.auto_polarity_en = True
        chk_status = srmcli.srm_prbs_chk_status_t()
        die_list = []
        for i in range(0, num_serdes):
            serdes = first_serdes + i
            rx_die = dev.get_serdes_addr(slice, ifg, serdes, sdk.la_serdes_direction_e_RX)
            if rx_die not in die_list:
                die_list.append(rx_die)
                for rx_chan in range(2):
                    srmcli.srm_prbs_chk_rules_set_default(chk_rules)
                    chk_rules.core.auto_polarity_en = True
                    srmcli.srm_prbs_chk_config(rx_die, rx_chan, srmcli.SRM_INTF_CORE_RX, chk_rules)
                    time.sleep(0.1)
                    srmcli.srm_prbs_chk_status(rx_die, rx_chan, srmcli.SRM_INTF_CORE_RX, chk_status)
                    time.sleep(0.1)
                    srmcli.srm_prbs_chk_status(rx_die, rx_chan, srmcli.SRM_INTF_CORE_RX, chk_status)

    def enable_rx_ser_prbs_chk(self, mp):
        slice = mp.get_slice()
        ifg = mp.get_ifg()
        first_serdes = mp.get_first_serdes_id()
        num_serdes = mp.get_num_of_serdes()
        dev = mp.get_device()
        chk_rules = srmcli.srm_prbs_chk_rules_t()
        chk_status = srmcli.srm_prbs_chk_status_t()
        srmcli.srm_prbs_chk_rules_set_default(chk_rules)
        chk_rules.serial.prbs_auto_lock = True
        die_list = []
        for i in range(0, num_serdes):
            serdes = first_serdes + i
            rx_die = dev.get_serdes_addr(slice, ifg, serdes, sdk.la_serdes_direction_e_RX)
            if rx_die not in die_list:
                die_list.append(rx_die)
                for rx_chan in range(2):
                    srmcli.srm_prbs_chk_config(rx_die, rx_chan, srmcli.SRM_INTF_SERIAL_RX, chk_rules)
                    time.sleep(0.1)
                    srmcli.srm_prbs_chk_status(rx_die, rx_chan, srmcli.SRM_INTF_SERIAL_RX, chk_status)
                    time.sleep(0.1)
                    srmcli.srm_prbs_chk_status(rx_die, rx_chan, srmcli.SRM_INTF_SERIAL_RX, chk_status)

    def enable_srm_prbs_check(self, mp):
        self.enable_rx_core_prbs_chk(mp)
        self.enable_rx_ser_prbs_chk(mp)

    def srm_rx_chk_test(self, rx_die, rx_chan, cnt_sel):
        chk_status_seri = srmcli.srm_prbs_chk_status_t()
        chk_status_core = srmcli.srm_prbs_chk_status_t()
        srmcli.srm_prbs_chk_status(rx_die, rx_chan, srmcli.SRM_INTF_SERIAL_RX, chk_status_seri)
        srmcli.srm_prbs_chk_status(rx_die, rx_chan, srmcli.SRM_INTF_CORE_RX, chk_status_core)
        if (chk_status_seri.prbs_lock):
            err_cnt = chk_status_seri.prbs_error_bit_count
            ber = err_cnt / chk_status_seri.prbs_total_bit_count
            if (cnt_sel < NA):
                self.err[cnt_sel]['serial_max'] = max(self.err[cnt_sel]['serial_max'], err_cnt)
                self.err[cnt_sel]['serial_sum'] += err_cnt
            print(f"SERIAL_RX: [{chk_status_seri.prbs_total_bit_count} / {err_cnt}, BER {ber:e}]   ", end='')
        else:
            print("SERIAL_RX: N/A   ", end='')
        if (chk_status_core.prbs_lock):
            err_cnt = chk_status_core.prbs_error_bit_count
            ber = err_cnt / chk_status_core.prbs_total_bit_count
            if (cnt_sel < NA):
                self.err[cnt_sel]['core_max'] = max(self.err[cnt_sel]['core_max'], err_cnt)
                self.err[cnt_sel]['core_sum'] += err_cnt
            print(f"CORE_RX: [{chk_status_core.prbs_total_bit_count} / {err_cnt}, BER {ber:e}]")
        else:
            print("CORE_RX: N/A")

    def srm_rx_init_test(self, mp, lane, lane_n):
        dev = mp.get_device()
        lld = dev.get_ll_device()
        slice_id = mp.get_slice()
        ifg = mp.get_ifg()
        first_serdes = int(mp.get_first_serdes_id() / TEST_STEP) * TEST_STEP
        num_serdes = 1

        rx_rules = srmcli.srm_rx_rules_t()
        first_serdes_n = first_serdes + lane_n
        die_rx_n = dev.get_serdes_addr(slice_id, ifg, first_serdes_n, sdk.la_serdes_direction_e_RX)
        chn_n = (dev.get_serdes_source(slice_id, ifg)[first_serdes_n]) % 2

        for i in range(num_serdes):
            serdes = first_serdes + lane + i
            die_rx = dev.get_serdes_addr(slice_id, ifg, serdes, sdk.la_serdes_direction_e_RX)
            chn = (dev.get_serdes_source(slice_id, ifg)[serdes]) % 2
            my_pool = int(serdes / 8)
            my_serdes = serdes % 8
            my_ls_serdes = (dev.get_serdes_source(slice_id, ifg)[serdes]) % 8
            pool = lld.get_gibraltar_tree().slice[slice_id].ifg[ifg]
            r = lld.read_register(pool.mac_pool8[my_pool].rx_pma_rd_cnt_reg[my_ls_serdes])
            r = lld.read_register(pool.mac_pool8[my_pool].rx_pma_test_counter[my_serdes])

            print("\nStart init ===================== ")
            self.srm_rx_chk_test(die_rx, chn, NA)

            print("Clean up..")
            time.sleep(self.prbs_run_time)
            rc = lld.read_register(pool.mac_pool8[my_pool].rx_pma_rd_cnt_reg[my_ls_serdes])
            rt = lld.read_register(pool.mac_pool8[my_pool].rx_pma_test_counter[my_serdes])
            print("Check %d/%d/%d - Die 0x%x/%d " % (slice_id, ifg, serdes, die_rx, chn))
            print(f" rx_pma: [{rc} / {rt}, BER {rt/rc:e}]   ", end='')
            self.err[CLEANUP]['pma_max'] = max(self.err[CLEANUP]['pma_max'], rt)
            self.err[CLEANUP]['pma_sum'] += rt
            self.srm_rx_chk_test(die_rx, chn, CLEANUP)

            print("\nTo run srm_init_rx on %d/%d/%d - Die 0x%x/%d" % (slice_id, ifg, first_serdes_n, die_rx_n, chn_n))
            srmcli.srm_rx_rules_query(die_rx_n, chn_n, rx_rules)
            srmcli.srm_init_rx(die_rx_n, chn_n, rx_rules)

            print("                Check %d/%d/%d - Die 0x%x/%d " % (slice_id, ifg, serdes, die_rx, chn))
            for ii in range(2):
                print(f"\n{ii}", end='')
                time.sleep(self.prbs_run_time)
                rc = lld.read_register(pool.mac_pool8[my_pool].rx_pma_rd_cnt_reg[my_ls_serdes])
                rt = lld.read_register(pool.mac_pool8[my_pool].rx_pma_test_counter[my_serdes])
                print(f" rx_pma: [{rc} / {rt} , BER {rt/rc:e}]   ", end='')

                if (ii == 0):
                    self.err[COUNT0]['pma_max'] = max(self.err[COUNT0]['pma_max'], rt)
                    self.err[COUNT0]['pma_sum'] += rt
                else:
                    self.err[COUNT1]['pma_max'] = max(self.err[COUNT1]['pma_max'], rt)
                    self.err[COUNT1]['pma_sum'] += rt

                self.srm_rx_chk_test(die_rx, chn, ii)

    def find_chn_in_same_die(self, mp):
        rx_ser_list = []
        dev = self.snake.device
        start_serdes = int(mp.get_first_serdes_id() / TEST_STEP) * TEST_STEP
        for ii in range(TEST_STEP):
            rx = dev.get_serdes_source(mp.get_slice(), mp.get_ifg(), start_serdes + ii)
            rx_ser_list.append(rx % 4)
        index0 = rx_ser_list.index(0)
        index1 = rx_ser_list.index(1)
        index2 = rx_ser_list.index(2)
        index3 = rx_ser_list.index(3)
        if (abs(index0 - index1) == abs(index2 - index3)):
            return (abs(index0 - index1))
        else:
            return 3

    def init_prbs_all(self, a, port_num):
        mp1_list = []
        print(f"init_prbs_all {a} --> Set up PRBS")
        for ii in range(port_num):
            mp = self.mph.mac_ports[a + ii]
            mp1_list.append(mp)
        for mpa in mp1_list:
            mpa.set_link_management_enabled(False)
            mpa.set_pma_test_mode(mpa.pma_test_mode_e_PRBS31)
        for mpa in mp1_list:
            self.enable_srm_prbs_check(mpa)

    def clean_prbs_all(self, a, port_num):
        mp1_list = []
        for ii in range(port_num):
            mp = self.mph.mac_ports[a + ii]
            mp1_list.append(mp)

        for mpa in mp1_list:
            mpa.set_pma_test_mode(mpa.pma_test_mode_e_NONE)
        for mpa in mp1_list:
            mpa.stop()
        for mpa in mp1_list:
            mpa.activate()

    def run_prbs_all(self, a):
        print(f"run_prbs_all  mac_port - {a}")
        mp = self.mph.mac_ports[a]
        ser_type = self.find_chn_in_same_die(mp)
        if (ser_type == 1):
            self.srm_rx_init_test(mp, 0, 1)
            self.srm_rx_init_test(mp, 2, 3)
        if (ser_type == 2):
            self.srm_rx_init_test(mp, 0, 2)
            self.srm_rx_init_test(mp, 1, 3)
        if (ser_type == 3):
            self.srm_rx_init_test(mp, 0, 3)
            self.srm_rx_init_test(mp, 1, 2)

    @unittest.skipIf(decor.is_pacific(), "Test is not supported on Pacific")
    def test_rx_sensitivity(self):
        self.fill_args_from_env_vars()
        self.link_down_timeout = self.DWELL_UP_TIME
        self.snake_args = self.snake.args
        loopback_mode = sdk.la_mac_port.loopback_mode_e_NONE
        is_an_enabled = False
        print(self.snake_args.board_cfg_path)
        self.prbs_run_time = RX_SENSITIVITY_RUN_TIME
        self.snake_init()
        self.create_port_connectivity_config()

        #self.device.set_bool_property(sdk.la_device_property_e_ENABLE_SERDES_LDO_VOLTAGE_REGULATOR, True)
        sdk.la_set_logging_level(self.snake_args.id, sdk.la_logger_component_e_MAC_PORT, sdk.la_logger_level_e_ERROR)

        self.load_connectivity_config_from_json(self.connect_mix, self.board_select)
        self.load_front_port_from_json(self.snake.args.board_cfg_path)
        self.load_valid_modes_from_json(self.ports_modes, self.device_rev)

        for current_test_iteration in range(self.test_iterations):
            c = {'pma_max': 0,
                 'pma_sum': 0,
                 'serial_max': 0,
                 'serial_sum': 0,
                 'core_max': 0,
                 'core_sum': 0
                 }
            self.err = [0] * 3
            self.err[COUNT0] = copy.deepcopy(c)
            self.err[COUNT1] = copy.deepcopy(c)
            self.err[CLEANUP] = copy.deepcopy(c)
            cnt = 0

            for test_pair in self.port_pairs:
                self.create_paired_ports("1x50G_KP4", test_pair, loopback_mode, is_an_enabled)
                self.snake_activate_ports()

                index_gap = self.ports[test_pair[0]][self.SER_IN_USE_IDX]
                for idx in range(0, index_gap, TEST_STEP):
                    cnt += 1
                    self.init_prbs_all(idx << 1, TEST_STEP << 1)
                    time.sleep(1)
                    self.run_prbs_all(idx << 1)
                    time.sleep(1)
                    self.run_prbs_all((idx << 1) + 1)
                    time.sleep(1)
                    self.clean_prbs_all(idx << 1, TEST_STEP << 1)
                    time.sleep(3)
                self.destroy_paired_ports()

            total_num = cnt * TEST_STEP
            print(f"total_num {total_num}")
            cleanup_pma_avg = self.err[CLEANUP]['pma_sum'] / total_num
            cleanup_ser_avg = self.err[CLEANUP]['serial_sum'] / total_num
            burst_pma_avg = self.err[COUNT0]['pma_sum'] / total_num
            burst_ser_avg = self.err[COUNT0]['serial_sum'] / total_num
            count1_pma_avg = self.err[COUNT1]['pma_sum'] / total_num
            count1_ser_avg = self.err[COUNT1]['serial_sum'] / total_num
            print(f"\tPMA Max \tPMA Average\t\tSERIAL Max \tSERIAL Average")
            print(
                f"Cleanup: %d \t%6.3f \t\t%d \t%6.3f" %
                (self.err[CLEANUP]['pma_max'], cleanup_pma_avg,
                 self.err[CLEANUP]['serial_max'], cleanup_ser_avg))
            print(
                f"Count0: %d \t%6.3f \t\t%d \t%6.3f" %
                (self.err[COUNT0]['pma_max'],
                 burst_pma_avg,
                 self.err[COUNT0]['serial_max'],
                 burst_ser_avg))
            print(
                f"Count1: %d \t%6.3f \t\t%d \t%6.3f" %
                (self.err[COUNT1]['pma_max'],
                 count1_pma_avg,
                 self.err[COUNT1]['serial_max'],
                 count1_ser_avg))
            ratio = 0
            if (cleanup_pma_avg != 0):
                ratio = burst_pma_avg / cleanup_pma_avg
                print(f"PMA error ratio (Count0 /Cleanup) : %6.3f" % (ratio))
                if (burst_pma_avg > self.BER_AVERAGE_THRESHOLD):
                    self.assertLess(ratio, 3.0)
            else:
                print(f"PMA error ratio (Count0 /Cleanup) : Not Available due to low Average BER threshold.")

            if (cleanup_ser_avg != 0):
                ratio = burst_ser_avg / cleanup_ser_avg
                print(f"SER error ratio (Count0 /Cleanup) : %6.3f" % (ratio))
                if (burst_ser_avg > self.BER_AVERAGE_THRESHOLD):
                    self.assertLess(ratio, 3.0)
            else:
                print(f"SER error ratio (Count0 /Cleanup) : Not Available due to low Average BER threshold.")

            if (cleanup_pma_avg != 0):
                ratio = count1_pma_avg / cleanup_pma_avg
                print(f"PMA error ratio (Count1 /Cleanup) : %6.3f" % (ratio))
                if (count1_pma_avg > self.BER_AVERAGE_THRESHOLD):
                    self.assertLess(ratio, 3.0)
            else:
                print(f"PMA error ratio (Count1 /Cleanup) : Not Available due to low Average BER threshold.")

            if (cleanup_ser_avg != 0):
                ratio = count1_ser_avg / cleanup_ser_avg
                print(f"SER error ratio (Count1 /Cleanup) : %6.3f" % (ratio))
                if (count1_ser_avg > self.BER_AVERAGE_THRESHOLD):
                    self.assertLess(ratio, 3.0)
            else:
                print(f"SER error ratio (Count1 /Cleanup) : Not Available due to low Average BER threshold.")


if __name__ == '__main__':
    unittest.main()
