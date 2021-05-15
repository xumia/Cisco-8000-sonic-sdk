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

import unittest
from leaba import sdk
import decor
import sim_utils


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class mac_port_serdes_params(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(0)

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
    @unittest.skipUnless(decor.is_pacific(), "Test supported only for Pacific")
    def test_mac_port_serdes_params(self):
        slice_id = 2
        ifg_id = 0
        num_serdes = 2
        speed = sdk.la_mac_port.port_speed_e_E_100G
        fc_mode = sdk.la_mac_port.fc_mode_e_NONE
        fec_mode = sdk.la_mac_port.fec_mode_e_RS_KR4
        first_serdes_id = 8
        last_serdes_id = 11
        port = self.device.create_mac_port(slice_id, ifg_id, first_serdes_id, last_serdes_id, speed, fc_mode, fec_mode)

        # Getters that are expected to return status other than LA_STATUS_SUCCESS
        with self.assertRaises(sdk.NotFoundException):
            port.get_serdes_parameter(first_serdes_id - 8, sdk.la_mac_port.serdes_param_stage_e_ACTIVATE,
                                      sdk.la_mac_port.serdes_param_e_ELECTRICAL_IDLE_THRESHOLD)

        rx_pll_bb_val = 1
        rx_pll_bb_mode = sdk.la_mac_port.serdes_param_mode_e_FIXED
        port.set_serdes_parameter(
            0,
            sdk.la_mac_port.serdes_param_stage_e_ACTIVATE,
            sdk.la_mac_port.serdes_param_e_RX_PLL_BB,
            rx_pll_bb_mode,
            rx_pll_bb_val)
        out_rx_pll_bb_mode, out_rx_pll_bb_val = port.get_serdes_parameter(
            0, sdk.la_mac_port.serdes_param_stage_e_ACTIVATE, sdk.la_mac_port.serdes_param_e_RX_PLL_BB)
        self.assertEqual(rx_pll_bb_val, out_rx_pll_bb_val)
        self.assertEqual(rx_pll_bb_mode, out_rx_pll_bb_mode)

        param_dump = port.get_serdes_parameters(0)
        found = False
        for param_ent in param_dump:
            if (param_ent.stage == sdk.la_mac_port.serdes_param_stage_e_ACTIVATE) and (
                    param_ent.parameter == sdk.la_mac_port.serdes_param_e_RX_PLL_BB):
                found = True
                self.assertEqual(rx_pll_bb_val, param_ent.value)
                self.assertEqual(rx_pll_bb_mode, param_ent.mode)

        self.assertTrue(found)

    @unittest.skipUnless(decor.is_gibraltar(), "Test supported only for Gibraltar")
    def test_mac_port_serdes_param_hardware_value_gibraltar(self):
        supported_device_properties = [
            sdk.la_mac_port.serdes_param_e_DATAPATH_RX_PRECODE,
            sdk.la_mac_port.serdes_param_e_DATAPATH_TX_PRECODE,
            sdk.la_mac_port.serdes_param_e_TX_MAIN,
            sdk.la_mac_port.serdes_param_e_TX_POST,
            sdk.la_mac_port.serdes_param_e_TX_PRE1,
            sdk.la_mac_port.serdes_param_e_RX_AC_COUPLING_BYPASS,
            sdk.la_mac_port.serdes_param_e_RX_AFE_TRIM,
            sdk.la_mac_port.serdes_param_e_RX_CTLE_CODE,
            sdk.la_mac_port.serdes_param_e_RX_DSP_MODE,
            sdk.la_mac_port.serdes_param_e_RX_VGA_TRACKING,
            sdk.la_mac_port.serdes_param_e_TX_INNER_EYE1,
            sdk.la_mac_port.serdes_param_e_TX_INNER_EYE2,
            sdk.la_mac_port.serdes_param_e_TX_LUT_MODE,
            sdk.la_mac_port.serdes_param_e_RX_SDT_CODE_FALL,
            sdk.la_mac_port.serdes_param_e_RX_SDT_CODE_RISE,
            sdk.la_mac_port.serdes_param_e_RX_SDT_CODE_TH,
            sdk.la_mac_port.serdes_param_e_RX_SDT_BLOCK_CNT,
        ]

        slice_id = 2
        ifg_id = 0
        num_serdes = 2
        speed = sdk.la_mac_port.port_speed_e_E_100G
        fc_mode = sdk.la_mac_port.fc_mode_e_NONE
        fec_mode = sdk.la_mac_port.fec_mode_e_RS_KR4
        first_serdes_id = 8
        last_serdes_id = 11
        port = self.device.create_mac_port(slice_id, ifg_id, first_serdes_id, last_serdes_id, speed, fc_mode, fec_mode)

        num_of_serdes = port.get_num_of_serdes()

        # verify that serdes parameters are implemented
        for device_prop in supported_device_properties:
            for serdes_idx in range(0, num_of_serdes):
                val = port.get_serdes_parameter_hardware_value(0, device_prop)


if __name__ == '__main__':
    unittest.main()
