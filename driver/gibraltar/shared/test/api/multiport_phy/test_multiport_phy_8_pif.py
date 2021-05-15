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

FIRST_SERDES_ID = 8
LAST_SERDES_ID = 11
NUM_MULTIPORT_PHY = 8
# Each multiport PHY reserves 8 PIF values
EXPECTED_FIRST_MAC_PORT_PIF = NUM_MULTIPORT_PHY * 8


class multiport_phy_8_pif(unittest.TestCase):

    def device_config_func(device, state):
        if (state == sdk.la_device.init_phase_e_DEVICE):
            device.set_int_property(sdk.la_device_property_e_NUM_MULTIPORT_PHY, 8)

    def setUp(self):
        self.device = sim_utils.create_device(0, device_config_func = multiport_phy_8_pif.device_config_func)

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
    @unittest.skipUnless(decor.is_asic5(), "Test supported only for Asic5")
    def test_mac_port_serdes_params(self):
        slice_id = 0
        ifg_id = 0
        speed = sdk.la_mac_port.port_speed_e_E_100G
        fc_mode = sdk.la_mac_port.fc_mode_e_NONE
        fec_mode = sdk.la_mac_port.fec_mode_e_RS_KR4
        first_serdes_id = FIRST_SERDES_ID
        last_serdes_id = LAST_SERDES_ID
        port = self.device.create_mac_port(slice_id, ifg_id, first_serdes_id, last_serdes_id, speed, fc_mode, fec_mode)

        pif_id = port.get_first_pif_id()

        self.assertEqual(pif_id, EXPECTED_FIRST_MAC_PORT_PIF)


if __name__ == '__main__':
    unittest.main()
