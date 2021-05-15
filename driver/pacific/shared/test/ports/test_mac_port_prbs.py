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
import datetime
import copy
import os
import warnings
from ports_test_base import *
import srmcli
import decor

GENERAL_PRBS_RUN_TIME = 10
PRBS_SETUP_DELAY = 10
PRBS_MAC_PORT_DELAY = 1
DIFF_PRBS_BER = 1.0e-5
WARN_PRBS_BER = 1.0e-6


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class mac_port_prbs(ports_test_base):
    mac_modes = ["8x50G_KP4", "1x50G_KP4"]
    prbs_modes = ["PMA", "SERDES"]

    def set_default_testing_param(self):
        self.link_down_timeout = self.DWELL_UP_TIME
        self.loopback_mode = sdk.la_mac_port.loopback_mode_e_NONE
        self.is_an_enabled = False
        self.prbs_run_time = GENERAL_PRBS_RUN_TIME
        self.log_directory = "/tmp/extended_ports_sanity_logs"
        if not os.path.isdir(self.log_directory):
            os.makedirs(self.log_directory)

    def test_mac_port_pma_prbs(self):
        self.fill_args_from_env_vars()
        self.set_default_testing_param()
        self.snake_args = self.snake.args
        self.snake_init()
        self.create_port_connectivity_config()

        self.load_connectivity_config_from_json(self.connect_mix, self.board_select)
        self.load_front_port_from_json(self.snake.args.board_cfg_path)
        self.load_valid_modes_from_json(self.ports_modes, self.device_rev)

        for mode in (self.mac_modes):
            print("Testing {} mode".format(mode))
            self.destroy_paired_ports()

            for test_pair in self.port_pairs:
                self.create_paired_ports(mode, test_pair, self.loopback_mode, self.is_an_enabled)
            self.snake_activate_ports()

            prbs_mode = "PMA"
            self.init_port_prbs(prbs_mode)
            self.check_port_prbs(prbs_mode)
            self.clear_port_prbs(prbs_mode)

    def test_mac_port_serdes_prbs(self):
        self.fill_args_from_env_vars()
        self.set_default_testing_param()
        self.snake_args = self.snake.args
        self.snake_init()
        self.create_port_connectivity_config()

        self.load_connectivity_config_from_json(self.connect_mix, self.board_select)
        self.load_front_port_from_json(self.snake.args.board_cfg_path)
        self.load_valid_modes_from_json(self.ports_modes, self.device_rev)

        for mode in (self.mac_modes):
            print("Testing {} mode".format(mode))
            self.destroy_paired_ports()

            for test_pair in self.port_pairs:
                self.create_paired_ports(mode, test_pair, self.loopback_mode, self.is_an_enabled)
            self.snake_activate_ports()

            prbs_mode = "SERDES"
            self.init_port_prbs(prbs_mode)
            self.check_port_prbs(prbs_mode)
            self.clear_port_prbs(prbs_mode)

    def init_port_prbs(self, prbs_mode):
        for mac_port in self.mph.mac_ports:
            mac_port.set_link_management_enabled(False)

        if (prbs_mode is "PMA"):
            print("Test PRBS in PMA mode")
            for mac_port in self.mph.mac_ports:
                mac_port.set_pma_test_mode(mac_port.pma_test_mode_e_PRBS31)
        else:
            print("Test PRBS in SERDES mode")
            for mac_port in self.mph.mac_ports:
                mac_port.set_serdes_test_mode(sdk.la_serdes_direction_e_TX, mac_port.serdes_test_mode_e_PRBS31)
                mac_port.set_serdes_test_mode(sdk.la_serdes_direction_e_RX, mac_port.serdes_test_mode_e_PRBS31)

    def check_port_prbs(self, prbs_mode):
        day = datetime.datetime.now()
        filename = "mac_port_prbs" + f"{day.year:04d}_{day.month:02d}-{day.day:02d}" + ".log"
        logfile = "{}/{}".format(self.log_directory, filename)
        log_fp = open(logfile, 'a+')
        if (prbs_mode is "PMA"):
            log_fp.write("PMA PRBS ***\n")
            # PMA PRBS
            # Clean up
            for mac_port in self.mph.mac_ports:
                mac_port.read_pma_test_ber()
            time.sleep(self.prbs_run_time)
            # Check error
            for mac_port in self.mph.mac_ports:
                num_serdes = mac_port.get_num_of_serdes()
                prbs_ber = mac_port.read_pma_test_ber()
                print(f'{mac_port.to_string()}')
                log_fp.write(f'{mac_port.to_string()}')
                print(f'prbs_ber {prbs_ber.lane_ber}')
                log_fp.write(f'prbs_ber {prbs_ber.lane_ber}\n\n')

                for srd in range(num_serdes):
                    self.assertLess(
                        prbs_ber.lane_ber[srd],
                        float(DIFF_PRBS_BER),
                        '%s BER rate higher than 1e-5' %
                        (mac_port.to_string()))
                    if (prbs_ber.lane_ber[srd] > float(WARN_PRBS_BER)):
                        warnings.warn(UserWarning(f"*** {mac_port.to_string()} BER rate higher than 1e-6"))

        else:
            log_fp.write("Serdes PRBS ***\n")
            # Serdes PRBS
            # Clean up
            for mac_port in self.mph.mac_ports:
                prbs_ber = mac_port.read_serdes_test_ber()

            time.sleep(self.prbs_run_time)
            # Check error
            for mac_port in self.mph.mac_ports:
                num_serdes = mac_port.get_num_of_serdes()
                prbs_ber = mac_port.read_serdes_test_ber()
                print(f'{mac_port.to_string()}')
                log_fp.write(f'{mac_port.to_string()}\n')
                print('prbs_ber.prbs_lock ', prbs_ber.prbs_lock)
                log_fp.write(f'prbs_ber.prbs_lock {prbs_ber.prbs_lock}\n')
                print('prbs_ber.errors ', prbs_ber.errors)
                log_fp.write(f'prbs_ber.errors {prbs_ber.errors} \n')
                print('prbs_ber.lane_ber ', prbs_ber.lane_ber)
                log_fp.write(f'prbs_ber.lane_ber {prbs_ber.lane_ber}\n')
                for srd in range(num_serdes):
                    self.assertTrue(prbs_ber.prbs_lock[srd], '%s PRBS not locked' %
                                    (mac_port.to_string()))
                    self.assertLess(
                        prbs_ber.lane_ber[srd],
                        float(DIFF_PRBS_BER),
                        '%s BER rate higher than 1e-5' %
                        (mac_port.to_string()))
                    if (prbs_ber.lane_ber[srd] > float(WARN_PRBS_BER)):
                        warnings.warn(UserWarning(f"*** {mac_port.to_string()} BER rate higher than 1e-6"))
        log_fp.close()

    def clear_port_prbs(self, prbs_mode):
        if (prbs_mode is "PMA"):
            for mac_port in self.mph.mac_ports:
                mac_port.set_pma_test_mode(mac_port.pma_test_mode_e_NONE)
        else:
            for mac_port in self.mph.mac_ports:
                mac_port.set_serdes_test_mode(sdk.la_serdes_direction_e_TX, mac_port.serdes_test_mode_e_NONE)
                mac_port.set_serdes_test_mode(sdk.la_serdes_direction_e_RX, mac_port.serdes_test_mode_e_NONE)


if __name__ == '__main__':
    unittest.main()
