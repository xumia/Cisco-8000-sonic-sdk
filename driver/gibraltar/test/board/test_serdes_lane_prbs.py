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
import argparse
import sys
from snake_standalone import snake_base_topology

BOARD = 'examples/sanity/churchillP0_board_config.json'
PARAMS_JSON = 'examples/sanity/serdes_settings.json'
PACIFIC_DEV_NAME = '/dev/uio0'
PRBS_TESTING_TIME = 10
PRBS_SETUP_DELAY = 10
PRBS_MAC_PORT_DELAY = 1
TEST_SERDES_NUM = 8
WAIT_MAC_PORT_UP_DELAY = 60
TEST_SLICE_ID = 3
TEST_IFG_ID = 0
SOURCE_FIRST_SERDES_ID = 0
DEST_FIRST_SERDES_ID = 8
DIFF_PRBS_BER = 1.0e-3
DEBUG_MODE = 0


class mac_port_prbs(unittest.TestCase):

    def setUp(self):
        ssd = snake_base_topology()

        snake_base_topology.set_default_args(ssd)
        #ssd.args.params_json = PARAMS_JSON
        snake_base_topology.init(ssd, PACIFIC_DEV_NAME, 0, BOARD, 0, False)

        self.ssd = ssd
        self.device = ssd.device
        self.mph = ssd.mph
        self.ll_device = ssd.device.get_ll_device()

    def tearDown(self):
        sdk.la_destroy_device(self.device)

    def test_serdes_prbs(self, test_mode=sdk.la_mac_port.serdes_test_mode_e_PRBS31, test_time=10):
        if self.ll_device.is_pacific():
            return
        else:
            #sdk.la_set_logging_level(0, sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)
            #sdk.la_set_logging_level(0, sdk.la_logger_component_e_MAC_PORT, sdk.la_logger_level_e_DEBUG)

            slice_id = TEST_SLICE_ID
            ifg_id = TEST_IFG_ID
            first_serdes_id = SOURCE_FIRST_SERDES_ID
            self.prbs_mac_port_create(slice_id, ifg_id, first_serdes_id)
            self.src_mac_port = self.device.get_mac_port(slice_id, ifg_id, first_serdes_id)
            self.mac_ports = [self.src_mac_port]

            if (args.p2p):
                first_serdes_id = DEST_FIRST_SERDES_ID
                self.prbs_mac_port_create(slice_id, ifg_id, first_serdes_id)
                self.dst_mac_port = self.device.get_mac_port(slice_id, ifg_id, first_serdes_id)
                self.mac_ports.append(self.dst_mac_port)

            self.run_prbs(test_mode, PRBS_TESTING_TIME)

    def run_prbs(self, test_mode, test_time):
        for serdes_idx in range(TEST_SERDES_NUM):
            for mac_port in self.mac_ports:
                mac_port.set_serdes_test_mode(serdes_idx, test_mode)

            time.sleep(PRBS_SETUP_DELAY)

            # clear PRBS counter
            for mac_port in self.mac_ports:
                mac_port.read_serdes_test_ber(serdes_idx)

            if DEBUG_MODE:
                print('Run PRBS for ', test_time, 's')
            time.sleep(test_time)

            for mac_port in self.mac_ports:
                prbs_ber = mac_port.read_serdes_test_ber(serdes_idx)
            if DEBUG_MODE:
                print('prbs_ber.prbs_lock ', prbs_ber.prbs_lock[serdes_idx])
                print('prbs_ber.errors ', prbs_ber.errors[serdes_idx])
                print('prbs_ber.lane_ber ', prbs_ber.lane_ber[serdes_idx])

            self.assertTrue(prbs_ber.prbs_lock[serdes_idx])
            self.assertLess(prbs_ber.lane_ber[serdes_idx], float(DIFF_PRBS_BER))

            for mac_port in self.mac_ports:
                mac_port.set_serdes_test_mode(serdes_idx, sdk.la_mac_port.serdes_test_mode_e_NONE)

    def prbs_mac_port_create(self, slice_id, ifg_id, first_serdes):
        num_serdes = TEST_SERDES_NUM
        speed = sdk.la_mac_port.port_speed_e_E_400G
        fc_mode = sdk.la_mac_port.fc_mode_e_NONE
        fec_mode = sdk.la_mac_port.fec_mode_e_RS_KP4

        # for first_serdes_id in range(first_serdes, first_serdes + 4, num_serdes):
        loopback_mode = sdk.la_mac_port.loopback_mode_e_NONE
        self.mph.create_mac_port(slice_id, ifg_id, first_serdes, num_serdes, speed, fec_mode, fc_mode, loopback_mode, False)
        self.device.flush()
        time.sleep(PRBS_MAC_PORT_DELAY)
        self.mph.mac_ports_activate('LOOPBACK', None)
        self.mph.wait_mac_ports_up(WAIT_MAC_PORT_UP_DELAY)
        self.mph.print_mac_up()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Avago Serdes PRBS test')
    parser.add_argument('--p2p', default=1, help='Avago Serdes PRBS port configuration')
    parser.add_argument('unittest_args', nargs='*')
    args = parser.parse_args()

    # Now set the sys.argv to the unittest_args (leaving sys.argv[0] alone)
    sys.argv[1:] = args.unittest_args
    unittest.main()
