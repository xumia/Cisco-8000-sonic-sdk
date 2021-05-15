#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import unittest
import argparse
from leaba import sdk
import decor
from mac_port_base import *
import time

verbose = 0


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
@unittest.skipUnless(decor.is_hw_device(), "Requires HW device")
class mac_port_counters(mac_port_base):

    def is_test_port_rs_fec_debug(self, mac_port):
        # For pacific only test first serdes in mac pool
        if self.device.get_ll_device().is_pacific():
            if mac_port.get_first_serdes_id() % 8 == 0:
                return True
            else:
                return False
        else:
            return True

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mac_port_counters(self):

        slice_id = 0
        ifg_id = 0
        first_serdes_id = 0
        serdes_count = 2
        ports_per_ifg = 9
        speed = sdk.la_mac_port.port_speed_e_E_50G

        port_counters = [
            sdk.la_mac_port.counter_e_PCS_BLOCK_ERROR,
            sdk.la_mac_port.counter_e_PCS_BER,
            sdk.la_mac_port.counter_e_FEC_CORRECTABLE,
            sdk.la_mac_port.counter_e_FEC_UNCORRECTABLE,
        ]

        serdes_counters = [
            sdk.la_mac_port.serdes_counter_e_PMA_TEST_ERROR,
        ]

        fc_modes = [
            sdk.la_mac_port.fc_mode_e_NONE,
        ]

        fec_modes = [
            sdk.la_mac_port.fec_mode_e_RS_KR4,
        ]

        self.mac_port_setup(slice_id, ifg_id, first_serdes_id, serdes_count, ports_per_ifg, speed,
                            fc_modes, fec_modes)

        for mac_port in self.mac_ports:
            # Put ports in serdes loopback and activate
            mac_port.set_loopback_mode(sdk.la_mac_port.loopback_mode_e_SERDES)
            mac_port.activate()

        # Wait for link up
        timeout = 5
        for elapsed in range(timeout):
            link_up = True
            for port_num, mac_port in enumerate(self.mac_ports):
                if not mac_port.read_mac_status().link_state:
                    link_up = False
            if link_up:
                break
            time.sleep(1)

        self.assertTrue(link_up, 'Links not up in {}s'.format(timeout))

        # Expect clear results after first clear
        for mac_port in self.mac_ports:
            for counter in port_counters:
                # read the counter twice to ensure that the counter is not clear
                mac_port.read_counter(counter)
                val = mac_port.read_counter(counter)
                self.assertEqual(
                    val,
                    0,
                    'Counter {} expected to be zero is {} after clearing at start of test'.format(
                        counter,
                        val))

        # Enable RS FEC debug for ports that are to be tested
        for mac_port in self.mac_ports:
            if self.is_test_port_rs_fec_debug(mac_port):
                mac_port.set_rs_fec_debug_enabled()

        # Read symbol error RS FEC codeword count, non-zero error counts should be 0
        for mac_port in self.mac_ports:
            if self.is_test_port_rs_fec_debug(mac_port):
                codewords = mac_port.read_rs_fec_debug_counters().codeword
                for index, codeword in enumerate(codewords):
                    # Only compare codewords with more than 0 symbol errors, i.e. index 1 and onwards
                    if index > 0:
                        self.assertEqual(
                            codeword,
                            0,
                            'rs fec codewords {} symbol errors expected to be zero is {} after clearing at start of test for Serdes {}/{}/{}'.format(
                                index,
                                codeword,
                                mac_port.get_slice(),
                                mac_port.get_ifg(),
                                mac_port.get_first_serdes_id()))

        # Read RS FEC lane errors should be 0
        for mac_port in self.mac_ports:
            if self.is_test_port_rs_fec_debug(mac_port):
                lane_errors = mac_port.read_rs_fec_symbol_errors_counters().lane_errors
                for index in range(2):
                    self.assertEqual(
                        lane_errors[index],
                        0,
                        'rs fec lane {} errors expected to be zero is {} after clearing at start of test for Serdes {}/{}/{}'.format(
                            index,
                            lane_errors[index],
                            mac_port.get_slice(),
                            mac_port.get_ifg(),
                            mac_port.get_first_serdes_id()))

        # Start injecting 5 symbol errors on both fec lanes
        enable = 1
        for mac_port in self.mac_ports:
            self.pma_tx_err_helper.pma_tx_err_inject(
                mac_port.get_slice(),
                mac_port.get_ifg(),
                mac_port.get_first_serdes_id(),
                enable,
                0xfffffffffffffff,
                5,
                100000000)
            self.pma_tx_err_helper.pma_tx_err_inject(
                mac_port.get_slice(),
                mac_port.get_ifg(),
                mac_port.get_first_serdes_id() + 1,
                enable,
                0xfffffffffffffff,
                5,
                100000000)

        # sleep 2 seconds
        time.sleep(2)

        # Stop fault injection on both fec lanes
        enable = 0
        for mac_port in self.mac_ports:
            self.pma_tx_err_helper.pma_tx_err_inject(
                mac_port.get_slice(),
                mac_port.get_ifg(),
                mac_port.get_first_serdes_id(),
                enable,
                0xfffffffffffffff,
                0,
                1)
            self.pma_tx_err_helper.pma_tx_err_inject(
                mac_port.get_slice(),
                mac_port.get_ifg(),
                mac_port.get_first_serdes_id() + 1,
                enable,
                0xfffffffffffffff,
                0,
                1)

        # sleep a second to settle down
        time.sleep(1)

        # read values twice and expect to be same
        for mac_port in self.mac_ports:
            for counter in port_counters:
                val1 = mac_port.read_counter(False, counter)
                val = mac_port.read_counter(True, counter)
                if verbose == 1:
                    print("Serdes {}/{}/{} counter {} read first {} second {}".format(mac_port.get_slice(),
                                                                                      mac_port.get_ifg(), mac_port.get_first_serdes_id(), counter, val1, val))
                self.assertEqual(
                    val1,
                    val,
                    'Counter {} expected to be same. first read={}, second read={}'.format(
                        counter,
                        val1,
                        val))

                if counter == sdk.la_mac_port.counter_e_PCS_BER:
                    self.assertNotEqual(val1, 0, 'PCS_BER counter expected to be non-zero after error injection')

        # expect cleared results
        for mac_port in self.mac_ports:
            for counter in port_counters:
                val = mac_port.read_counter(counter)
                self.assertEqual(val, 0, 'Counter {} expected to be zero is {} after clearing'.format(counter, val))

        # Read twice the symbol error RS FEC codeword count, non-zero error counts should be same
        for mac_port in self.mac_ports:
            symbol_errors = 0
            if self.is_test_port_rs_fec_debug(mac_port):
                codewords = mac_port.read_rs_fec_debug_counters(False).codeword
                codewords1 = mac_port.read_rs_fec_debug_counters(True).codeword
                for index in range(len(codewords)):
                    # Only compare codewords with more than 0 symbol errors, i.e. index 1 and onwards
                    if index > 0:
                        self.assertEqual(
                            codewords[index],
                            codewords1[index],
                            'rs fec codewords {} symbol errors expected to be same. first read={}, second read={} for Serdes {}/{}/{}'.format(
                                index,
                                codewords[index],
                                codewords1[index],
                                mac_port.get_slice(),
                                mac_port.get_ifg(),
                                mac_port.get_first_serdes_id()))
                        symbol_errors = symbol_errors + index * codewords[index]

                if verbose == 1:
                    print("Serdes {}/{}/{} symbol_errors {}".format(mac_port.get_slice(),
                                                                    mac_port.get_ifg(),
                                                                    mac_port.get_first_serdes_id(),
                                                                    symbol_errors))

                self.assertNotEqual(
                    symbol_errors,
                    0,
                    'rs fec codewords total symbol errors expected to be non-zero. read={} for Serdes {}/{}/{}'.format(
                        symbol_errors,
                        mac_port.get_slice(),
                        mac_port.get_ifg(),
                        mac_port.get_first_serdes_id()))

        # Expect symbol error RS FEC codeword count, non-zero error counts should be 0
        for mac_port in self.mac_ports:
            if self.is_test_port_rs_fec_debug(mac_port):
                codewords = mac_port.read_rs_fec_debug_counters().codeword
                for index in range(len(codewords)):
                    # Only compare codewords with more than 0 symbol errors, i.e. index 1 and onwards
                    if index > 0:
                        self.assertEqual(
                            codewords[index],
                            0,
                            'rs fec codewords {} symbol errors expected to be 0. read={} for Serdes {}/{}/{} after clearing'.format(
                                index,
                                codewords[index],
                                mac_port.get_slice(),
                                mac_port.get_ifg(),
                                mac_port.get_first_serdes_id()))

        # Read twice RS FEC lane errors should be same
        for mac_port in self.mac_ports:
            if self.is_test_port_rs_fec_debug(mac_port):
                lane_errors = mac_port.read_rs_fec_symbol_errors_counters(False).lane_errors
                lane_errors1 = mac_port.read_rs_fec_symbol_errors_counters(True).lane_errors
                for index in range(2):
                    self.assertEqual(
                        lane_errors[index],
                        lane_errors1[index],
                        'rs fec lane {} errors expected to be same. first read={}, second read={} for Serdes {}/{}/{}'.format(
                            index,
                            lane_errors[index],
                            lane_errors1[index],
                            mac_port.get_slice(),
                            mac_port.get_ifg(),
                            mac_port.get_first_serdes_id()))

                    if verbose == 1:
                        print("Serdes {}/{}/{} rs fec lane {} error {}".format(mac_port.get_slice(),
                                                                               mac_port.get_ifg(),
                                                                               mac_port.get_first_serdes_id(),
                                                                               index,
                                                                               lane_errors[index]))

                    self.assertNotEqual(
                        lane_errors[index],
                        0,
                        'rs fec lane {} errors expected to be non-zero. read={} for Serdes {}/{}/{}'.format(
                            index,
                            codewords[index],
                            mac_port.get_slice(),
                            mac_port.get_ifg(),
                            mac_port.get_first_serdes_id()))

        # Read RS FEC lane errors should be 0 after clearing
        for mac_port in self.mac_ports:
            if self.is_test_port_rs_fec_debug(mac_port):
                lane_errors = mac_port.read_rs_fec_symbol_errors_counters().lane_errors
                for index in range(2):
                    self.assertEqual(
                        lane_errors[index],
                        0,
                        'rs fec lane {} errors expected to be 0. read={} for Serdes {}/{}/{} after clearing'.format(
                            index,
                            lane_errors[index],
                            mac_port.get_slice(),
                            mac_port.get_ifg(),
                            mac_port.get_first_serdes_id()))


if __name__ == '__main__':
    unittest.main()
