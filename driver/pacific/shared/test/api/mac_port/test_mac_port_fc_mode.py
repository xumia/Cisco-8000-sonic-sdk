#!/usr/bin/env python3
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

import unittest
from leaba import sdk
import decor
from sdk_test_case_base import *


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class mac_port_fc_mode(sdk_test_case_base):

    mac_port = None

    def setUp(self):
        super().setUp()

        self.mac_port = self.device.get_mac_port(T.RX_SLICE,
                                                 T.RX_IFG,
                                                 T.FIRST_SERDES)

        # reset the fc_mode for each test
        self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR,
                                  sdk.la_mac_port.fc_mode_e_NONE)

    def test_fc_mode_rx_pause(self):
        """ Set RX mode, check RX is set and TX is not set """
        self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_RX,
                                  sdk.la_mac_port.fc_mode_e_PAUSE)

        with self.assertRaises(sdk.InvalException):
            fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR)
        rx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_RX)
        tx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_TX)

        self.assertEqual(rx_fc_mode, sdk.la_mac_port.fc_mode_e_PAUSE)
        self.assertEqual(tx_fc_mode, sdk.la_mac_port.fc_mode_e_NONE)

    def test_fc_mode_tx_pause(self):
        """ Set TX mode, check TX is set and RX is not set """
        self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_TX,
                                  sdk.la_mac_port.fc_mode_e_PAUSE)

        with self.assertRaises(sdk.InvalException):
            fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR)
        rx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_RX)
        tx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_TX)

        self.assertEqual(rx_fc_mode, sdk.la_mac_port.fc_mode_e_NONE)
        self.assertEqual(tx_fc_mode, sdk.la_mac_port.fc_mode_e_PAUSE)

    def test_fc_mode_bidir_pause(self):
        """ Set both RX and TX mode, check both are set """
        self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR,
                                  sdk.la_mac_port.fc_mode_e_PAUSE)

        fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR)
        rx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_RX)
        tx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_TX)

        self.assertEqual(fc_mode, sdk.la_mac_port.fc_mode_e_PAUSE)
        self.assertEqual(rx_fc_mode, sdk.la_mac_port.fc_mode_e_PAUSE)
        self.assertEqual(tx_fc_mode, sdk.la_mac_port.fc_mode_e_PAUSE)

    def test_fc_mode_rx_pfc(self):
        """ Set RX mode, check RX is set and TX is not set """
        self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_RX,
                                  sdk.la_mac_port.fc_mode_e_PFC)

        with self.assertRaises(sdk.InvalException):
            fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR)
        rx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_RX)
        tx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_TX)

        self.assertEqual(rx_fc_mode, sdk.la_mac_port.fc_mode_e_PFC)
        self.assertEqual(tx_fc_mode, sdk.la_mac_port.fc_mode_e_NONE)

    def test_fc_mode_tx_pfc(self):
        """ Set TX mode, check TX is set and RX is not set """
        self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_TX,
                                  sdk.la_mac_port.fc_mode_e_PFC)

        with self.assertRaises(sdk.InvalException):
            fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR)
        rx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_RX)
        tx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_TX)

        self.assertEqual(rx_fc_mode, sdk.la_mac_port.fc_mode_e_NONE)
        self.assertEqual(tx_fc_mode, sdk.la_mac_port.fc_mode_e_PFC)

    def test_fc_mode_bidir_pfc(self):
        """ Set both RX and TX mode, check both are set """
        self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR,
                                  sdk.la_mac_port.fc_mode_e_PFC)

        fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR)
        rx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_RX)
        tx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_TX)

        self.assertEqual(fc_mode, sdk.la_mac_port.fc_mode_e_PFC)
        self.assertEqual(rx_fc_mode, sdk.la_mac_port.fc_mode_e_PFC)
        self.assertEqual(tx_fc_mode, sdk.la_mac_port.fc_mode_e_PFC)

    def test_fc_mode_rx_pfc_invalid_tx(self):
        """ Set RX PFC and invalid TX mode """
        self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_RX,
                                  sdk.la_mac_port.fc_mode_e_PFC)

        with self.assertRaises(sdk.InvalException):
            self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_TX,
                                      sdk.la_mac_port.fc_mode_e_PAUSE)

        with self.assertRaises(sdk.InvalException):
            fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR)
        rx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_RX)
        tx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_TX)

        self.assertEqual(rx_fc_mode, sdk.la_mac_port.fc_mode_e_PFC)
        self.assertEqual(tx_fc_mode, sdk.la_mac_port.fc_mode_e_NONE)

    def test_fc_mode_tx_pfc_invalid_rx(self):
        """ Set TX PFC and invalid RX mode """
        self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_TX,
                                  sdk.la_mac_port.fc_mode_e_PFC)

        with self.assertRaises(sdk.InvalException):
            self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_RX,
                                      sdk.la_mac_port.fc_mode_e_PAUSE)

        with self.assertRaises(sdk.InvalException):
            fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR)
        rx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_RX)
        tx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_TX)

        self.assertEqual(rx_fc_mode, sdk.la_mac_port.fc_mode_e_NONE)
        self.assertEqual(tx_fc_mode, sdk.la_mac_port.fc_mode_e_PFC)

    def test_fc_mode_bidir_pfc_invalid_rx(self):
        """ Set BIDIR PFC and invalid RX mode """
        self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR,
                                  sdk.la_mac_port.fc_mode_e_PFC)

        with self.assertRaises(sdk.InvalException):
            self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_RX,
                                      sdk.la_mac_port.fc_mode_e_PAUSE)

        fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR)
        rx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_RX)
        tx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_TX)

        self.assertEqual(fc_mode, sdk.la_mac_port.fc_mode_e_PFC)
        self.assertEqual(rx_fc_mode, sdk.la_mac_port.fc_mode_e_PFC)
        self.assertEqual(tx_fc_mode, sdk.la_mac_port.fc_mode_e_PFC)

    def test_fc_mode_bidir_pfc_invalid_tx(self):
        """ Set BIDIR PFC and invalid TX mode """
        self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR,
                                  sdk.la_mac_port.fc_mode_e_PFC)

        with self.assertRaises(sdk.InvalException):
            self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_TX,
                                      sdk.la_mac_port.fc_mode_e_PAUSE)

        fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR)
        rx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_RX)
        tx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_TX)

        self.assertEqual(fc_mode, sdk.la_mac_port.fc_mode_e_PFC)
        self.assertEqual(rx_fc_mode, sdk.la_mac_port.fc_mode_e_PFC)
        self.assertEqual(tx_fc_mode, sdk.la_mac_port.fc_mode_e_PFC)

    def test_fc_mode_bidir_pfc_disable_rx(self):
        """ Set BIDIR PFC and disable RX mode """
        self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR,
                                  sdk.la_mac_port.fc_mode_e_PFC)

        self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_RX,
                                  sdk.la_mac_port.fc_mode_e_NONE)

        with self.assertRaises(sdk.InvalException):
            fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR)
        rx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_RX)
        tx_fc_mode = self.mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_TX)

        self.assertEqual(rx_fc_mode, sdk.la_mac_port.fc_mode_e_NONE)
        self.assertEqual(tx_fc_mode, sdk.la_mac_port.fc_mode_e_PFC)


if __name__ == '__main__':
    unittest.main()
