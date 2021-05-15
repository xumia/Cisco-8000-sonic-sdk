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
import test_lldcli
import sim_utils
import packet_test_utils
import re

SERDES_COUNT = 18


class mac_and_serdes_base(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(1, False)

        self.expected_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'expected', 'test_mac_port')
        self.mac_ports = []
        self.activate_ports = False  # Should be enabled only on real device

    def tearDown(self):
        self.device.tearDown()

    def mac_port_setup(self, base_slice, base_ifg, base_serdes, serdes_count, ports_per_ifg, speed, fc_modes, fec_modes):
        slice_id = base_slice
        ifg_id = base_ifg
        for fec_mode in fec_modes:
            for fc_mode in fc_modes:
                for port_idx in range(ports_per_ifg):
                    serdes_start = base_serdes + port_idx * serdes_count
                    serdes_last = serdes_start + serdes_count - 1
                    try:
                        mac_port = self.device.create_mac_port(slice_id, ifg_id, serdes_start, serdes_last,
                                                               speed, fc_mode, fec_mode)
                    except sdk.BaseException:
                        raise exceptions.AssertionError(
                            'Failed create_mac_port {0} with FC_MODE {1}, FEC_MODE {2} '.format(
                                port_idx, fc_mode, fec_mode))

                    self.assertIsNotNone(mac_port)
                    self.mac_ports.append(mac_port)

                    if (self.activate_ports):
                        try:
                            mac_port.activate()
                        except sdk.BaseException:
                            raise exceptions.AssertionError('Failed mac_port.activate {0} '.format(port_idx))

                    out_speed = mac_port.get_speed()
                    self.assertEqual(out_speed, speed)

                ifg_id += 1
                if ifg_id > 1:
                    ifg_id = 0
                    slice_id += 1
