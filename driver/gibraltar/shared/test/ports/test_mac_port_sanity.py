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
import datetime
import time
import copy
import csv
import os
import warnings
from ports_test_base import *
import lldcli
import srmcli
import decor
from save_state_parse import *

ANLT_MAC_PORT_LINKUP_TIME = 60


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class mac_port_sanity(ports_test_base):
    modes_default = ["4x10G_NONE", "4x25G_KR4", "8x50G_KP4"]
    modes_extend = ["4x10G_NONE", "4x25G_KR4", "1x10G_NONE", "1x25G_KR4", "2x25G_KR4", "1x50G_KP4", "2x50G_KP4", "8x50G_KP4"]

    # Enable SDK Logging
    def enable_sdk_logging(self, enable):
        if (enable):
            print("ENABLE_SDK_LOGGING")
            sdk.la_set_logging_level(0, sdk.la_logger_component_e_MAC_PORT, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(0, sdk.la_logger_component_e_API, sdk.la_logger_level_e_DEBUG)
            if (self.en_sdk_timestamp):
                lldcli.logger_instance().set_timestamps_enabled(True)
        else:
            sdk.la_set_logging_level(0, sdk.la_logger_component_e_MAC_PORT, sdk.la_logger_level_e_ERROR)
            sdk.la_set_logging_level(0, sdk.la_logger_component_e_SERDES, sdk.la_logger_level_e_ERROR)
            sdk.la_set_logging_level(0, sdk.la_logger_component_e_API, sdk.la_logger_level_e_ERROR)

    # Edit device properties
    def edit_device_properties(self):
        print("Editing Device Properties")
        self.device.set_int_property(sdk.la_device_property_e_MAC_PORT_TUNE_TIMEOUT, self.mac_port_tune_timeout)
        if (self.rxa_power_sequence != -1):
            self.device.set_int_property(sdk.la_device_property_e_SERDES_RXA_POWER_SEQUENCE_MODE, self.rxa_power_sequence)
        self.device.set_int_property(
            sdk.la_device_property_e_MAC_PORT_PAM4_LINK_TRAINING_TIMEOUT,
            self.mac_port_pam4_link_training_timeout)
        self.device.set_int_property(
            sdk.la_device_property_e_MAC_PORT_NRZ_LINK_TRAINING_TIMEOUT,
            self.mac_port_nrz_link_training_timeout)
        self.device.set_int_property(
            sdk.la_device_property_e_MAC_PORT_SAVE_STATE_SM_STATE_TRANSITION_CAPTURES,
            self.mac_port_save_state_sm_state_transition_captures)

    def set_default_testing_param(self):
        self.link_down_timeout = ANLT_MAC_PORT_LINKUP_TIME
        self.log_directory = "/tmp/extended_ports_sanity_logs"
        self.mac_port_tune_timeout = 30
        self.rxa_power_sequence = 1
        self.mac_port_pam4_link_training_timeout = 3000
        self.mac_port_nrz_link_training_timeout = 1000
        self.mac_port_save_state_sm_state_transition_captures = 30
        self.en_sdk_timestamp = False
        self.anlt_only = False
        if (self.port_sanity_mode == self.PORT_SANITY_DEFAULT_MODES):
            self.test_modes = self.modes_default
        elif (self.port_sanity_mode == self.PORT_SANITY_EXTEND_MODES):
            self.test_modes = self.modes_extend
        else:
            # For EXTEND_MODES_ANLT_ONLY
            self.test_modes = self.modes_extend
            self.anlt_only = True

    # Perform Dump and with 5s Dwell
    def port_dump(self, mode, an_mode, current_test_iteration, dwell=5):
        # Clear all counters in one place instead of per mac_ports to save time.
        for mp in self.mph.mac_ports:
            self.clear_all_counters(mp)
        time.sleep(dwell)

        for mp in self.mph.mac_ports:
            self.savestate_port_dump(mp, mode, an_mode, current_test_iteration)

        mp_idx = 0
        for mp in self.mph.mac_ports:
            peer_mp = self.mph.mac_ports[mp_idx + 1] if (mp_idx % 2) == 0 else self.mph.mac_ports[mp_idx - 1]
            peer_mp_l = [peer_mp.get_slice(), peer_mp.get_ifg(), peer_mp.get_first_serdes_id()]
            self.savestate_peer_list.append(peer_mp_l)
            mp_idx += 1

    def disable_anlt(self):
        for mp in self.mph.mac_ports:
            mp.stop()
            mp.set_an_enabled(False)

    def clear_all_counters(self, mp):
        # FEC Mode None can't clear counters
        if mp.get_fec_mode() != 0:
            mp.clear_counters()

    # Need to have path created before running
    def savestate_port_dump(self, mp, mode, an_mode, iteration):
        # Create dir if it does not exist
        file_path = self.log_directory
        if not os.path.isdir(file_path):
            os.makedirs(file_path)

        an_str = self.get_anlt_str(an_mode).strip()
        port_string = "{}_{}_{}_{}".format(an_str, mp.get_slice(), mp.get_ifg(), mp.get_first_serdes_id())
        iter_string = "{:03}".format(iteration)
        filename = self.ss.make_filename(iter_string, mode, port_string)

        mp.save_state(mp.port_debug_info_e_ALL, filename)

        print("Save State file {} created.".format(filename))
        self.savestate_file.append(filename)

    def get_anlt_str(self, an_mode):
        return {
            True: "  ANLT  ",
            False: "NON_ANLT",
        }[an_mode]

    @unittest.skipIf(decor.is_pacific(), "Test is not supported on Pacific")
    def test_mac_port_sanity_anlt(self):
        self.mac_port_sanity_test(True)
        self.assertTrue(self.test_pass, 'Mac port Sanity check Failed')

    @unittest.skipIf(decor.is_pacific(), "Test is not supported on Pacific")
    def test_mac_port_sanity_non_anlt(self):
        self.mac_port_sanity_test(False)
        if self.test_pass is False:
            warnings.warn(UserWarning('Mac port Sanity check Failed !!!'))

    def mac_port_sanity_test(self, is_an_enabled):
        self.fill_args_from_env_vars()
        self.snake_args = self.snake.args
        self.set_default_testing_param()
        loopback_mode = sdk.la_mac_port.loopback_mode_e_NONE

        if self.anlt_only:
            print("test_mac_port_sanity_non_anlt - Test Skipped due to test_mode setting")
            return

        self.snake_init()
        self.enable_sdk_logging(False)
        self.edit_device_properties()
        self.create_port_connectivity_config()
        self.load_connectivity_config_from_json(self.connect_mix, self.board_select)
        self.load_front_port_from_json(self.snake.args.board_cfg_path)
        self.load_valid_modes_from_json(self.ports_modes, self.device_rev)
        self.ss = save_state_parse(self.port_sanity_dump_pair, self.link_down_timeout, self.log_directory)
        self.test_pass = True
        self.test_warn = False
        self.ss_summary = []
        self.savestate_file = []
        self.savestate_peer_list = []

        total_run_time_start = time.time()
        for current_test_iteration in range(1, self.test_iterations + 1):
            print("**********************************     ********")
            print(
                f"**   Iteration #: {current_test_iteration:3} of {self.test_iterations:3}    **     {self.get_anlt_str(is_an_enabled)}")
            print("**********************************     ********")
            for mode in list(self.test_modes):
                print("Testing {} mode".format(mode))
                self.destroy_paired_ports()

                for test_pair in self.port_pairs:
                    self.create_paired_ports(mode, test_pair, loopback_mode, is_an_enabled)
                self.snake_activate_ports()

                print("port_dump()")
                self.port_dump(mode, is_an_enabled, current_test_iteration)
                print("")

                if (is_an_enabled is True):
                    self.disable_anlt()

        file_num = len(self.savestate_file)
        for mp_idx in range(file_num):
            if (self.mp_db_loss):
                self.ss.savestate_port_test(
                    self.savestate_file[mp_idx],
                    self.ss_summary,
                    self.savestate_peer_list[mp_idx],
                    self.mp_db_loss[mp_idx])
            else:
                self.ss.savestate_port_test(self.savestate_file[mp_idx], self.ss_summary, self.savestate_peer_list[mp_idx])
        self.ss.savestate_create_report(self.ss_summary)
        self.test_pass &= self.ss.mp_parse_result
        self.test_warn |= self.ss.mp_parse_warning

        # Test Finished. Teardown remaining ports.
        self.destroy_paired_ports()
        # Print total run time.
        total_run_time = time.time() - total_run_time_start
        str_time = str(datetime.timedelta(seconds=total_run_time))
        print(f"Total iterations: {self.test_iterations} Total time: {total_run_time} seconds (H:M:S):{str_time}")
        if (self.test_warn):
            print("*** ******* ***")
            print("*** WARNING *** Test finished with link up but quality analysis warnings.")
            print("*** ******* ***")
            warnings.warn(UserWarning("*** Test finished with link up but quality analysis warnings."))


if __name__ == '__main__':
    unittest.main()
