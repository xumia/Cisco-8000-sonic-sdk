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

import os
import unittest
from leaba import sdk
from mac_port_helper import *
import time
import sys
from snake_standalone import snake_base_topology
from ports_base import *
import decor

PRBS_TESTING_TIME = 10
PRBS_SETUP_DELAY = 10
PRBS_MAC_PORT_DELAY = 1
WAIT_MAC_PORT_UP_DELAY = 60
DIFF_BER_PCAL_ICAL = 1.0e-5
DIFF_PRBS_BER = 1.0e-3
DEBUG_MODE = 0


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class mac_port_prbs(ports_base):
    loop_mode = 'none'
    p2p_ext = True

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mac_port_prbs(self, test_mode=sdk.la_mac_port.serdes_test_mode_e_PRBS31, is_pcal=1, test_time=10):
        self.fill_args_from_env_vars('default_mix.json')
        self.snake.run_snake()

        self.device = self.snake.device
        self.mph = self.snake.mph
        self.pcal_ber = [0] * 20
        self.ical_ber = [0] * 20

        self.mac_ports = self.mph.mac_ports

        if self.device.get_ll_device().is_gibraltar():
            self.run_gb_prbs(test_mode, PRBS_TESTING_TIME)
            return

        is_pcal = True
        self.run_pac_prbs(test_mode, is_pcal, PRBS_TESTING_TIME)
        time.sleep(PRBS_SETUP_DELAY)
        is_pcal = False
        self.run_pac_prbs(test_mode, is_pcal, PRBS_TESTING_TIME)

        for mac_port in self.mac_ports:
            srd = mac_port.get_num_of_serdes()
            for num_serdes in range(srd):
                diffs = self.pcal_ber[self.mac_ports.index(mac_port)][num_serdes] - \
                    self.ical_ber[self.mac_ports.index(mac_port)][num_serdes]
                self.assertLess(
                    abs(diffs),
                    float(DIFF_BER_PCAL_ICAL),
                    '%s BER rate in Pcal and Ical differs too much' %
                    (mac_port.to_string()))

    def run_pac_prbs(self, test_mode, is_pcal, test_time):
        for mac_port in self.mac_ports:
            mac_port.set_serdes_continuous_tuning_enabled(False)

        time.sleep(PRBS_SETUP_DELAY)
        for mac_port in self.mac_ports:
            mac_port.set_serdes_test_mode(sdk.la_serdes_direction_e_TX, test_mode)
            mac_port.set_serdes_test_mode(sdk.la_serdes_direction_e_RX, test_mode)
            if is_pcal:
                if DEBUG_MODE:
                    print('Turn on continuous tuning')
                mac_port.set_serdes_continuous_tuning_enabled(True)
            else:
                if DEBUG_MODE:
                    print('Turn on iCal')
                mac_port.set_serdes_tuning_mode(sdk.la_mac_port.serdes_tuning_mode_e_ICAL)

        for mac_port in self.mac_ports:
            mac_port.tune(block=False)

        time.sleep(3 * PRBS_SETUP_DELAY)

        if DEBUG_MODE:
            print('Run PRBS for ', test_time, 's')
        time.sleep(test_time)

        for mac_port in self.mac_ports:
            srd = mac_port.get_num_of_serdes()
            prbs_ber = mac_port.read_serdes_test_ber()
            if DEBUG_MODE:
                print('prbs_ber.errors ', prbs_ber.errors)
                print('prbs_ber.lane_ber ', prbs_ber.lane_ber)

            if is_pcal:
                self.pcal_ber[self.mac_ports.index(mac_port)] = prbs_ber.lane_ber
            else:
                self.ical_ber[self.mac_ports.index(mac_port)] = prbs_ber.lane_ber

            for num_serdes in range(srd):
                self.assertLess(
                    prbs_ber.lane_ber[num_serdes],
                    float(DIFF_PRBS_BER),
                    '%s BER rate higher than 1e-3' %
                    (mac_port.to_string()))

        for mac_port in self.mac_ports:
            mac_port.set_serdes_test_mode(sdk.la_serdes_direction_e_TX, sdk.la_mac_port.serdes_test_mode_e_NONE)
            mac_port.set_serdes_test_mode(sdk.la_serdes_direction_e_RX, sdk.la_mac_port.serdes_test_mode_e_NONE)

    def run_gb_prbs(self, test_mode, test_time):
        for mac_port in self.mac_ports:
            mac_port.set_serdes_test_mode(sdk.la_serdes_direction_e_TX, test_mode)
            mac_port.set_serdes_test_mode(sdk.la_serdes_direction_e_RX, test_mode)

        time.sleep(PRBS_SETUP_DELAY)

        for mac_port in self.mac_ports:
            mac_port.read_serdes_test_ber()

        if DEBUG_MODE:
            print('Run PRBS for ', test_time, 's')
        time.sleep(test_time)

        for mac_port in self.mac_ports:
            srd = mac_port.get_num_of_serdes()
            prbs_ber = mac_port.read_serdes_test_ber()
            if DEBUG_MODE:
                print('prbs_ber.prbs_lock ', prbs_ber.prbs_lock)
                print('prbs_ber.errors ', prbs_ber.errors)
                print('prbs_ber.lane_ber ', prbs_ber.lane_ber)

            for num_serdes in range(srd):
                self.assertTrue(prbs_ber.prbs_lock[num_serdes], '%s PRBS not locked' %
                                (mac_port.to_string()))
                self.assertLess(
                    prbs_ber.lane_ber[num_serdes],
                    float(DIFF_PRBS_BER),
                    '%s BER rate higher than 1e-3' %
                    (mac_port.to_string()))

        for mac_port in self.mac_ports:
            mac_port.set_serdes_test_mode(sdk.la_serdes_direction_e_TX, sdk.la_mac_port.serdes_test_mode_e_NONE)
            mac_port.set_serdes_test_mode(sdk.la_serdes_direction_e_RX, sdk.la_mac_port.serdes_test_mode_e_NONE)


if __name__ == '__main__':
    unittest.main()
