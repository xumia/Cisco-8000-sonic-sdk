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
import decor
import re
from mac_port_base import *


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class mac_port_serdes_enum(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def getEnumLength(self, enum) -> int:
        dirlist = dir(sdk.la_mac_port)
        count = 0
        for string in dirlist:
            if string.find(enum) != -1:
                count += 1
        return count

    def test_mac_port_serdes_enum(self):
        enum_map = {
            'loopback_mode_e_': sdk.la_mac_port.loopback_mode_e_LAST,
            'pcs_test_mode_e_': sdk.la_mac_port.pcs_test_mode_e_LAST,
            'port_speed_e_': sdk.la_mac_port.port_speed_e_LAST,
            'fec_mode_e_': sdk.la_mac_port.fec_mode_e_LAST,
            'fc_mode_e_': sdk.la_mac_port.fc_mode_e_LAST,
            'tc_protocol_e_': sdk.la_mac_port.tc_protocol_e_LAST,
            'mlp_mode_e_': sdk.la_mac_port.mlp_mode_e_LAST,
            'fault_state_e_': sdk.la_mac_port.fault_state_e_LAST,
            'pma_test_mode_e_': sdk.la_mac_port.pma_test_mode_e_LAST,
            'serdes_tuning_mode_e_': sdk.la_mac_port.serdes_tuning_mode_e_LAST,
        }
        for enum, last in enum_map.items():
            enum_len = self.getEnumLength(enum) - 2
            print(f'{enum}_LAST : {enum_len}')
            self.assertEqual(enum_len, last)


if __name__ == '__main__':
    unittest.main()
