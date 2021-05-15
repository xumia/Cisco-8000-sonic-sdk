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
import os
import warnings
from ports_test_base import *
import srmcli
import decor

TX_SENSITIVITY_RUN_TIME = 0.5
CLEANUP = 2
COUNT0  = 0
COUNT1  = 1
NA      = 3
HUGE_PRBS_BER_THRS = 100000


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class tx_sensitivity_prbs(ports_test_base):

    def prepare_rules(self, port):
        p_slice = self.ports[port][self.SLICE_ID_IDX]
        p_ifg = self.ports[port][self.IFG_IDX]
        p_first_ser = self.ports[port][self.FIRST_SERDES_IDX]
        die0 = self.device.get_serdes_addr(p_slice, p_ifg, p_first_ser, sdk.la_serdes_direction_e_TX)

        pll_rules = srmcli.srm_pll_rules_t()
        srmcli.srm_pll_rules_query(die0, pll_rules)

        tx_rules = srmcli.srm_tx_rules_t()
        srmcli.srm_tx_rules_query(die0, 0, tx_rules)

        rx_rules = srmcli.srm_rx_rules_t()
        srmcli.srm_rx_rules_query(die0, 0, rx_rules)
        return pll_rules, tx_rules, rx_rules

    def init_ports_srm_pll(self, port, pll_rules):
        num_serdes = self.ports[port][self.SER_IN_USE_IDX]
        gen_slice = self.ports[port][self.SLICE_ID_IDX]
        gen_ifg = self.ports[port][self.IFG_IDX]
        gen_first_ser = self.ports[port][self.FIRST_SERDES_IDX]

        for serdes in range(0, num_serdes, 2):
            die = self.device.get_serdes_addr(gen_slice, gen_ifg, gen_first_ser + serdes, sdk.la_serdes_direction_e_TX)
            self.dbg_print(f"SRM init on {gen_slice}/{gen_ifg}/{gen_first_ser+serdes} - Die 0x{die:x}")
            srmcli.srm_init(die)
            srmcli.srm_init_pll(die, pll_rules)
            time.sleep(0.5)
            is_lock = srmcli.srm_is_pll_locked(die)
            self.dbg_print(f"pll_locked : {is_lock}")

    def init_gen_port_srm_tx(self, port, tx_rules):
        num_serdes = self.ports[port][self.SER_IN_USE_IDX]
        gen_slice = self.ports[port][self.SLICE_ID_IDX]
        gen_ifg = self.ports[port][self.IFG_IDX]
        gen_first_ser = self.ports[port][self.FIRST_SERDES_IDX]

        for serdes in range(num_serdes):
            die = self.device.get_serdes_addr(gen_slice, gen_ifg, gen_first_ser + serdes, sdk.la_serdes_direction_e_TX)
            tx_rules.invert_chan = self.device.get_serdes_polarity_inversion(gen_slice, gen_ifg, gen_first_ser + serdes,
                                                                             sdk.la_serdes_direction_e_TX)
            self.dbg_print(f"SRM init Tx on {gen_slice}/{gen_ifg}/{gen_first_ser+serdes} - Die 0x{die:x}")
            srmcli.srm_init_tx(die, serdes % 2, tx_rules)
            time.sleep(0.5)

    def init_chk_port_srm_rx(self, port, rx_rules):
        print(f"\nInit srm Rx on {port}")
        num_serdes = self.ports[port][self.SER_IN_USE_IDX]
        chk_slice = self.ports[port][self.SLICE_ID_IDX]
        chk_ifg = self.ports[port][self.IFG_IDX]
        chk_first_ser = self.ports[port][self.FIRST_SERDES_IDX]

        for serdes in range(num_serdes):
            die = self.device.get_serdes_addr(chk_slice, chk_ifg, chk_first_ser + serdes, sdk.la_serdes_direction_e_RX)
            chn = self.device.get_serdes_source(chk_slice, chk_ifg)[chk_first_ser + serdes] % 2
            rx_rules.invert_chan = self.device.get_serdes_polarity_inversion(
                chk_slice, chk_ifg, chk_first_ser + serdes, sdk.la_serdes_direction_e_RX)
            self.dbg_print(f"SRM init Rx on {chk_slice}/{chk_ifg}/{chk_first_ser+serdes} - Die 0x{die:x}")
            srmcli.srm_init_rx(die, chn, rx_rules)

    def enable_prbs(self, testing_pair, enable):
        port = testing_pair[1]
        num_serdes = self.ports[port][self.SER_IN_USE_IDX]
        chk_slice = self.ports[port][self.SLICE_ID_IDX]
        chk_ifg = self.ports[port][self.IFG_IDX]
        chk_first_ser = self.ports[port][self.FIRST_SERDES_IDX]

        print(f"Check PRBS on {port}")
        for serdes in range(num_serdes):
            mp = self.device.get_mac_port(chk_slice, chk_ifg, chk_first_ser + serdes)
            self.dbg_print(f"Enable PRBS Check on {chk_slice}/{chk_ifg}/{chk_first_ser + serdes}")
            mp.set_link_management_enabled(False)
            if (enable):
                mp.set_serdes_test_mode(sdk.la_serdes_direction_e_RX, mp.serdes_test_mode_e_PRBS31)
            else:
                mp.set_serdes_test_mode(sdk.la_serdes_direction_e_RX, mp.serdes_test_mode_e_NONE)

        port = testing_pair[0]
        print(f"Generate PRBS on {port}")
        num_serdes = self.ports[port][self.SER_IN_USE_IDX]
        self.cnt += num_serdes
        gen_slice = self.ports[port][self.SLICE_ID_IDX]
        gen_ifg = self.ports[port][self.IFG_IDX]
        gen_first_ser = self.ports[port][self.FIRST_SERDES_IDX]

        gen_rules = srmcli.srm_prbs_gen_rules_t()
        srmcli.srm_prbs_gen_rules_set_default(gen_rules)
        gen_rules.gen_en_lsb = False
        gen_rules.prbs_mode = srmcli.SRM_PRBS_MODE_COMBINED
        if (enable == False):
            gen_rules.en = False

        for serdes in range(num_serdes):
            die = self.device.get_serdes_addr(gen_slice, gen_ifg, gen_first_ser + serdes, sdk.la_serdes_direction_e_TX)
            self.dbg_print(f"Enable PRBS Gen on {gen_slice}/{gen_ifg}/{gen_first_ser+serdes} - Die 0x{die:x}")
            srmcli.srm_prbs_gen_config(die, serdes % 2, srmcli.SRM_INTF_SERIAL_TX, gen_rules)

    def srm_rx_chk_prbs(self, port, cnt_sel):
        chk_num_serdes = self.ports[port][self.SER_IN_USE_IDX]
        chk_slice = self.ports[port][self.SLICE_ID_IDX]
        chk_ifg = self.ports[port][self.IFG_IDX]
        chk_first_ser = self.ports[port][self.FIRST_SERDES_IDX]

        chk_status_seri = srmcli.srm_prbs_chk_status_t()
        for serdes in range(chk_num_serdes):
            rx_die = self.device.get_serdes_addr(chk_slice, chk_ifg, chk_first_ser + serdes, sdk.la_serdes_direction_e_RX)
            rx_chn = (self.device.get_serdes_source(chk_slice, chk_ifg)[chk_first_ser + serdes] % 2)

            srmcli.srm_prbs_chk_status(rx_die, rx_chn, srmcli.SRM_INTF_SERIAL_RX, chk_status_seri)
            if (chk_status_seri.prbs_lock):
                err_cnt = chk_status_seri.prbs_error_bit_count
                ber = err_cnt / chk_status_seri.prbs_total_bit_count
                if (cnt_sel < NA):
                    self.err[cnt_sel]['serial_max'] = max(self.err[cnt_sel]['serial_max'], err_cnt)
                    self.err[cnt_sel]['serial_sum'] += err_cnt
                    if (err_cnt > HUGE_PRBS_BER_THRS and cnt_sel == CLEANUP):
                        self.high_ber_ports.append(port)

                print(f"SERIAL_RX: [{chk_status_seri.prbs_total_bit_count} / {err_cnt}, BER {ber:e}]   ", end='')
            else:
                print("SERIAL_RX: N/A   ", end='')
            print("\n")

    def dump_chk_port_savestate(self):
        print(f"Run save_state on {self.high_ber_ports}")
        for port in self.high_ber_ports:
            chk_num_serdes = self.ports[port][self.SER_IN_USE_IDX]
            chk_slice = self.ports[port][self.SLICE_ID_IDX]
            chk_ifg = self.ports[port][self.IFG_IDX]
            chk_first_ser = self.ports[port][self.FIRST_SERDES_IDX]

            filename = "tx_sensitivity_prbs" + f"-{chk_slice}_{chk_ifg}_{chk_first_ser}" + ".json"
            savefile = "{}/{}".format(self.log_directory, filename)
            mp = self.device.get_mac_port(chk_slice, chk_ifg, chk_first_ser)
            mp.save_state(mp.port_debug_info_e_SERDES_EXTENDED_DEBUG, savefile)

    def wait_chk_port_rx_ready(self):
        for test_pair in self.port_pairs:
            port = test_pair[1]
            chk_num_serdes = self.ports[port][self.SER_IN_USE_IDX]
            chk_slice = self.ports[port][self.SLICE_ID_IDX]
            chk_ifg = self.ports[port][self.IFG_IDX]
            chk_first_ser = self.ports[port][self.FIRST_SERDES_IDX]

            for serdes in range(chk_num_serdes):
                rx_die = self.device.get_serdes_addr(chk_slice, chk_ifg, chk_first_ser + serdes, sdk.la_serdes_direction_e_RX)
                rx_chn = (self.device.get_serdes_source(chk_slice, chk_ifg)[chk_first_ser + serdes] % 2)
                retry = 50
                for ii in range(retry):
                    is_ready = srmcli.srm_is_rx_ready(rx_die, rx_chn)
                    time.sleep(0.1)
                    if (is_ready is True):
                        break
                if (is_ready == False):
                    print("%d/%d/%d Rx not ready !" % (chk_slice, chk_ifg, chk_first_ser + serdes))
                    warnings.warn(UserWarning("{}/{}/{} Rx not ready !".format(chk_slice, chk_ifg, chk_first_ser + serdes)))

    @unittest.skipIf(decor.is_pacific(), "Test is not supported on Pacific")
    def test_tx_sensitivity(self):
        self.fill_args_from_env_vars()
        self.link_down_timeout = 10
        self.log_directory = "/tmp/extended_ports_sanity_logs"
        if not os.path.isdir(self.log_directory):
            os.makedirs(self.log_directory)
        self.snake_args = self.snake.args
        loopback_mode = sdk.la_mac_port.loopback_mode_e_NONE
        is_an_enabled = False
        self.prbs_run_time = TX_SENSITIVITY_RUN_TIME
        self.snake_init()
        self.create_port_connectivity_config()

        sdk.la_set_logging_level(self.snake_args.id, sdk.la_logger_component_e_MAC_PORT, sdk.la_logger_level_e_ERROR)

        self.load_connectivity_config_from_json(self.connect_mix, self.board_select)
        self.load_front_port_from_json(self.snake.args.board_cfg_path)
        self.load_valid_modes_from_json(self.ports_modes, self.device_rev)

        c = {'serial_max': 0,
             'serial_sum': 0
             }
        self.err = [0] * 3
        self.err[COUNT0] = copy.deepcopy(c)
        self.err[COUNT1] = copy.deepcopy(c)
        self.err[CLEANUP] = copy.deepcopy(c)
        self.cnt = 0

        # Create right ports in port_pair as the PRBS receive side.
        for test_pair in self.port_pairs:
            self.create_paired_ports("1x50G_KP4", test_pair, sdk.la_mac_port.loopback_mode_e_NONE, False, self.CREATE_RIGHT_PORTS)
        self.snake_activate_ports()
        pll_rules, tx_rules, rx_rules = self.prepare_rules(self.port_pairs[0][1])

        for test_pair in self.port_pairs:
            self.init_ports_srm_pll(test_pair[0], pll_rules)
            self.init_gen_port_srm_tx(test_pair[0], tx_rules)

        self.wait_chk_port_rx_ready()
        for test_pair in self.port_pairs:
            print("\nStart PRBS ===================== ")
            self.enable_prbs(test_pair, True)
        time.sleep(3)

        self.high_ber_ports = []
        for test_pair in self.port_pairs:
            chk_port = test_pair[1]
            self.srm_rx_chk_prbs(chk_port, NA)

            print("\nClean up..")
            time.sleep(self.prbs_run_time)
            self.srm_rx_chk_prbs(chk_port, CLEANUP)

            self.init_chk_port_srm_rx(test_pair[0], rx_rules)

            for ii in range(2):
                print(f"\nCount {ii}")
                time.sleep(self.prbs_run_time)
                self.srm_rx_chk_prbs(chk_port, ii)

        self.dump_chk_port_savestate()

        self.destroy_paired_ports()
        total_num = self.cnt
        print(f"total_num {total_num}")
        print(f"\tSERIAL Max \tSERIAL Average")
        print(
            f"Cleanup: \t%d \t%6.3f" %
            (self.err[CLEANUP]['serial_max'],
             self.err[CLEANUP]['serial_sum'] /
             total_num))
        print(
            f"Count0: \t%d \t%6.3f" %
            (self.err[COUNT0]['serial_max'],
             self.err[COUNT0]['serial_sum'] /
             total_num))
        print(
            f"Count1: \t%d \t%6.3f" %
            (self.err[COUNT1]['serial_max'],
             self.err[COUNT1]['serial_sum'] /
             total_num))
        cleanup_avg = self.err[CLEANUP]['serial_sum'] / total_num
        ber_burst = self.err[COUNT0]['serial_sum'] / total_num
        ber_burst1 = self.err[COUNT1]['serial_sum'] / total_num
        ratio = 0
        if (cleanup_avg != 0):
            ratio = ber_burst / cleanup_avg
            print(f"error ratio (Count0 /Cleanup) : %6.3f" % (ratio))
            if (ber_burst > self.BER_AVERAGE_THRESHOLD):
                self.assertLess(ratio, 3.0)
            if (ratio >= 2.0):
                warnings.warn(UserWarning("BER Burst 1 vs Clean BER ratio is greater than 2"))

            ratio = ber_burst1 / cleanup_avg
            print(f"error ratio (Count1 /Cleanup) : %6.3f" % (ratio))
            if (ratio >= 2.0):
                warnings.warn(UserWarning("BER After Burst vs Clean BER ratio is greater than 2"))
        else:
            print(f"SER error ratio (Count0 /Cleanup) : Not Available due to low Average BER threshold.")


if __name__ == '__main__':
    unittest.main()
