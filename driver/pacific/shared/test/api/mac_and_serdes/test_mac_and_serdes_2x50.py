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
import decor
import unittest
from leaba import sdk
import packet_test_utils
import re
from mac_and_serdes_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_hw_gibraltar(), "SKIP-GB-HW")
class mac_and_serdes_2x50(mac_and_serdes_base):

    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mac_and_serdes_2x50(self):
        slice_id = 0
        ifg_id = 0
        first_serdes_id = 0
        serdes_count = 2
        ports_per_ifg = 9
        speed = sdk.la_mac_port.port_speed_e_E_100G
        fec_modes = [
            sdk.la_mac_port.fec_mode_e_RS_KR4,
            sdk.la_mac_port.fec_mode_e_RS_KP4]
        fc_modes = [
            sdk.la_mac_port.fc_mode_e_NONE,
            sdk.la_mac_port.fc_mode_e_PAUSE,
            sdk.la_mac_port.fc_mode_e_PFC]

        swap_all_list = [3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 17, 16]

        # Complete initialization
        self.device.initialize(sdk.la_device.init_phase_e_DEVICE)

        for sid in self.device.get_used_slices():
            self.device.set_slice_mode(sid, sdk.la_slice_mode_e_NETWORK)

        # Swap SerDes source
        self.device.set_serdes_source(slice_id, ifg_id + 1, swap_all_list)

        # Invert polarity
        for serdes_id in range(SERDES_COUNT):
            self.device.set_serdes_polarity_inversion(
                slice_id, ifg_id + 1, serdes_id, sdk.la_serdes_direction_e_RX, True)
            self.device.set_serdes_polarity_inversion(
                slice_id, ifg_id + 1, serdes_id, sdk.la_serdes_direction_e_TX, True)

        self.device.initialize(sdk.la_device.init_phase_e_TOPOLOGY)

        # Create MAC port
        self.mac_port_setup(slice_id, ifg_id, first_serdes_id, serdes_count, ports_per_ifg, speed, fc_modes, fec_modes)

        # Check


if __name__ == '__main__':
    unittest.main()
