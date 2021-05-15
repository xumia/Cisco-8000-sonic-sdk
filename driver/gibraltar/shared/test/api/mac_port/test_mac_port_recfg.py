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
import topology as T
from mac_port_base import *


# test "la_mac_port::reconfigure" API with all possible reconfiguration settings.
# Check serdes count, port speed, fec mode, fc mode after each API call.


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
@unittest.skipIf(decor.is_matilda("3.2"), "GB 3.2 Does not support mac_port->reconfigure() functionality")
class test_mac_port_recfg(mac_port_base):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_mac_port_recfg(self):
        slice_id = 0
        ifg_id = 0
        first_serdes_id = 0
        serdes_count = 8
        speed = sdk.la_mac_port.port_speed_e_E_400G
        fc_mode = sdk.la_mac_port.fc_mode_e_NONE
        fec_mode = sdk.la_mac_port.fec_mode_e_RS_KP4

        RECFG_LINK = 0

        port_cfg = [
            [4, sdk.la_mac_port.port_speed_e_E_100G, fc_mode, sdk.la_mac_port.fec_mode_e_RS_KP4],
            [8, sdk.la_mac_port.port_speed_e_E_200G, fc_mode, sdk.la_mac_port.fec_mode_e_RS_KP4],
            [1, sdk.la_mac_port.port_speed_e_E_25G, fc_mode, sdk.la_mac_port.fec_mode_e_RS_KP4],
            [4, sdk.la_mac_port.port_speed_e_E_100G, fc_mode, sdk.la_mac_port.fec_mode_e_NONE],
            [2, sdk.la_mac_port.port_speed_e_E_50G, fc_mode, sdk.la_mac_port.fec_mode_e_RS_KP4],
            [4, sdk.la_mac_port.port_speed_e_E_40G, fc_mode, sdk.la_mac_port.fec_mode_e_KR],
            [2, sdk.la_mac_port.port_speed_e_E_50G, fc_mode, sdk.la_mac_port.fec_mode_e_NONE],
            [1, sdk.la_mac_port.port_speed_e_E_10G, fc_mode, sdk.la_mac_port.fec_mode_e_KR],
            [4, sdk.la_mac_port.port_speed_e_E_40G, fc_mode, sdk.la_mac_port.fec_mode_e_NONE],
            [2, sdk.la_mac_port.port_speed_e_E_40G, fc_mode, sdk.la_mac_port.fec_mode_e_NONE],
            [1, sdk.la_mac_port.port_speed_e_E_25G, fc_mode, sdk.la_mac_port.fec_mode_e_NONE],
            [1, sdk.la_mac_port.port_speed_e_E_25G, fc_mode, sdk.la_mac_port.fec_mode_e_KR],
            [1, sdk.la_mac_port.port_speed_e_E_10G, fc_mode, sdk.la_mac_port.fec_mode_e_NONE],
        ]
        if not T.is_matilda_model(self.device):
            port_cfg = port_cfg + [
                [2, sdk.la_mac_port.port_speed_e_E_100G, fc_mode, sdk.la_mac_port.fec_mode_e_RS_KP4],
                [1, sdk.la_mac_port.port_speed_e_E_50G, fc_mode, sdk.la_mac_port.fec_mode_e_RS_KP4],
                [serdes_count, speed, fc_mode, fec_mode]
            ]

        # create two 400G ports
        serdes_count, speed, fc_mode, fec_mode = port_cfg[1]
        self.mac_port_setup(slice_id, ifg_id, first_serdes_id, serdes_count, 2, speed, [fc_mode], [fec_mode])

        for index in range(len(port_cfg)):
            self.mac_ports[RECFG_LINK].stop()

            self.mac_ports[RECFG_LINK].reconfigure(
                port_cfg[index][0],
                port_cfg[index][1],
                port_cfg[index][2],
                port_cfg[index][2],
                port_cfg[index][3])
            self.mac_ports[RECFG_LINK].set_loopback_mode(sdk.la_mac_port.loopback_mode_e_SERDES)

            self.mac_ports[RECFG_LINK].activate()

            configured = [
                self.mac_ports[RECFG_LINK].get_num_of_serdes(),
                self.mac_ports[RECFG_LINK].get_speed(),
                self.mac_ports[RECFG_LINK].get_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR),
                self.mac_ports[RECFG_LINK].get_fec_mode()]
            expected = [port_cfg[index][0], port_cfg[index][1], port_cfg[index][2], port_cfg[index][3]]

            self.assertEqual(configured, expected)


if __name__ == '__main__':
    unittest.main()
