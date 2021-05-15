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
class invalid(mac_port_base):

    def test_invalid(self):
        invalid_configs = [
            {'slice': 0, 'ifg': 0, 'serdes_start': 16, 'serdes_count': 1, 'speed': sdk.la_mac_port.port_speed_e_E_10G,
             'fec': sdk.la_mac_port.fec_mode_e_RS_KR4, 'fc': sdk.la_mac_port.fc_mode_e_NONE},
            {'slice': 0, 'ifg': 0, 'serdes_start': 16, 'serdes_count': 1, 'speed': sdk.la_mac_port.port_speed_e_E_10G,
             'fec': sdk.la_mac_port.fec_mode_e_RS_KP4, 'fc': sdk.la_mac_port.fc_mode_e_NONE},
            {'slice': 0, 'ifg': 0, 'serdes_start': 16, 'serdes_count': 1, 'speed': sdk.la_mac_port.port_speed_e_E_50G,
             'fec': sdk.la_mac_port.fec_mode_e_NONE, 'fc': sdk.la_mac_port.fc_mode_e_NONE},
            {'slice': 0, 'ifg': 0, 'serdes_start': 16, 'serdes_count': 1, 'speed': sdk.la_mac_port.port_speed_e_E_50G,
             'fec': sdk.la_mac_port.fec_mode_e_KR, 'fc': sdk.la_mac_port.fc_mode_e_NONE},
            {'slice': 0, 'ifg': 0, 'serdes_start': 16, 'serdes_count': 2, 'speed': sdk.la_mac_port.port_speed_e_E_50G,
             'fec': sdk.la_mac_port.fec_mode_e_KR, 'fc': sdk.la_mac_port.fc_mode_e_NONE},
            {'slice': 0, 'ifg': 0, 'serdes_start': 16, 'serdes_count': 2, 'speed': sdk.la_mac_port.port_speed_e_E_100G,
             'fec': sdk.la_mac_port.fec_mode_e_KR, 'fc': sdk.la_mac_port.fc_mode_e_NONE}
        ]

        for invalid_cfg in invalid_configs:
            try:
                mac_port = self.device.create_mac_port(invalid_cfg['slice'], invalid_cfg['ifg'],
                                                       invalid_cfg['serdes_start'],
                                                       invalid_cfg['serdes_start'] + invalid_cfg['serdes_count'] - 1,
                                                       invalid_cfg['speed'],
                                                       invalid_cfg['fc'],
                                                       invalid_cfg['fec'])
                self.assertFail()
            except sdk.BaseException as STATUS:
                self.assertEqual(
                    STATUS.args[0],
                    sdk.la_status_e_E_INVAL,
                    'Failed invalid create_mac_port: slice {0}, ifg {1}, SerDes {2}-{3}, speed {4}, FC_MODE {5}, FEC_MODE {6} '.format(
                        invalid_cfg['slice'],
                        invalid_cfg['ifg'],
                        invalid_cfg['serdes_start'],
                        invalid_cfg['serdes_start'] +
                        invalid_cfg['serdes_count'] -
                        1,
                        invalid_cfg['speed'],
                        invalid_cfg['fc'],
                        invalid_cfg['fec']))


if __name__ == '__main__':
    unittest.main()
