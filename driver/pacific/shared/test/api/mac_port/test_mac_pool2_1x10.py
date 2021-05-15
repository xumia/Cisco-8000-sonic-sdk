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
class mac_pool2_1x10(mac_port_base):

    @unittest.skipIf(not decor.is_pacific_A0(), "Test is enabled only on Pacific A0")
    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mac_pool2_1x10(self):
        slice_id = 0
        ifg_id = 0
        first_serdes_id = 0
        serdes_count = 1
        ports_per_ifg = 18
        speed = sdk.la_mac_port.port_speed_e_E_10G
        fec_modes = [
            sdk.la_mac_port.fec_mode_e_NONE,
            sdk.la_mac_port.fec_mode_e_KR]
        fc_modes = [
            sdk.la_mac_port.fc_mode_e_NONE,
            sdk.la_mac_port.fc_mode_e_PAUSE,
            sdk.la_mac_port.fc_mode_e_PFC]

        self.mac_port_setup(slice_id, ifg_id, first_serdes_id, serdes_count, ports_per_ifg, speed, fc_modes, fec_modes)

        if not self.slices_changed_from_default:
            packet_test_utils.compare_regs_mems(self, self.device, os.path.join(
                self.expected_dir, EXPECTED_JSON_FILENAME), 'mac_pool2_1x10')


if __name__ == '__main__':
    unittest.main()
