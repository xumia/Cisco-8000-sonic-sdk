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

import os
import unittest
from leaba import sdk
import decor
import packet_test_utils
import re
from mac_port_base import *


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class mac_pool_2x25_counters(mac_port_base):

    @unittest.skipIf(not decor.is_pacific_A0(), "Test is enabled only on Pacific A0")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mac_pool_2x25_counters(self):
        slice_id = 0
        ifg_id = 0
        first_serdes_id = 0
        serdes_count = 2
        if decor.is_asic4():
            ports_per_ifg = 8
        else:
            ports_per_ifg = 9
        speed = sdk.la_mac_port.port_speed_e_E_50G
        fec_modes = [
            sdk.la_mac_port.fec_mode_e_NONE]
        fc_modes = [
            sdk.la_mac_port.fc_mode_e_NONE]

        pcs_test_modes = [
            sdk.la_mac_port.pcs_test_mode_e_SCRAMBLED,
            sdk.la_mac_port.pcs_test_mode_e_RANDOM,
            sdk.la_mac_port.pcs_test_mode_e_RANDOM_ZEROS,
            sdk.la_mac_port.pcs_test_mode_e_PRBS31,
            sdk.la_mac_port.pcs_test_mode_e_PRBS9,
            sdk.la_mac_port.pcs_test_mode_e_NONE
        ]

        pma_test_modes = [
            sdk.la_mac_port.pma_test_mode_e_RANDOM,
            sdk.la_mac_port.pma_test_mode_e_PRBS31,
            sdk.la_mac_port.pma_test_mode_e_PRBS9,
            sdk.la_mac_port.pma_test_mode_e_PRBS15,
            sdk.la_mac_port.pma_test_mode_e_PRBS13,
            sdk.la_mac_port.pma_test_mode_e_JP03B,
            sdk.la_mac_port.pma_test_mode_e_RANDOM,
            sdk.la_mac_port.pma_test_mode_e_SSPRQ,
            sdk.la_mac_port.pma_test_mode_e_SQUARE_WAVE,
            sdk.la_mac_port.pma_test_mode_e_NONE,
        ]

        port_counters = [
            sdk.la_mac_port.counter_e_PCS_TEST_ERROR,
            sdk.la_mac_port.counter_e_PCS_BLOCK_ERROR,
            sdk.la_mac_port.counter_e_PCS_BER,
        ]

        serdes_counters = [
            sdk.la_mac_port.serdes_counter_e_PMA_TEST_ERROR,
        ]

        self.mac_port_setup(slice_id, ifg_id, first_serdes_id, serdes_count, ports_per_ifg, speed, fc_modes, fec_modes)

        for mac_port in self.mac_ports:
            for pcs_test_mode in pcs_test_modes:
                mac_port.set_pcs_test_mode(pcs_test_mode)

            for pma_test_mode in pma_test_modes:
                mac_port.set_pma_test_mode(pma_test_mode)

            for counter in port_counters:
                val = mac_port.read_counter(counter)
                self.assertEqual(val, 0)

            for counter in serdes_counters:
                for serdes_id in range(serdes_count):
                    val = mac_port.read_counter(counter, serdes_id)
                    self.assertEqual(val, 0)


if __name__ == '__main__':
    unittest.main()
